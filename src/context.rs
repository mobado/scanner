//! Context for the findings, added after the modules ran: ordinary desktop activity becomes
//! Info, findings about a user's own files are marked as user level, and every finding that
//! names a process or a file says who started it, which package it comes from and when.

use crate::finding::{Finding, Severity};
use crate::modules::Collector;
use crate::pkgverify::packages_of;
use crate::procinfo::ProcInfo;
use crate::sys::SysRoot;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Rules whose Low findings are everyday life on a desktop: listed, but out of the way.
const ORDINARY: [&str; 17] = [
    "AUTH-ADMIN-ACTIONS", "FS-DOWNLOAD-PROGRAM", "DESK-APPIMAGE", "DESK-FLATPAK-ACCESS", "DESK-SNAP", "PERS-AUTOSTART",
    "PERS-SESSION-SCRIPT-OWN", "PROC-APPIMAGE", "PROC-ENV-SECRETS", "KERN-THUNDERBOLT", "NET-LOCAL-SERVER",
    "NET-BLUETOOTH", "EXT-LYNIS-SUGGEST", "PERS-GNOME-EXTENSION", "PERS-SYSTEMD-USER", "EXT-RKHUNTER-UPDATED",
    "PROC-HIGH-CPU",
];

/// Rules whose Low findings are ordinary when the program comes from a package.
const ORDINARY_WHEN_PACKAGED: [&str; 5] = ["NET-OUTBOUND-UNUSUAL", "NET-LISTEN-UNKNOWN", "PROC-DELETED", "PROC-ROOT-ODD-PATH", "PROC-IO-URING"];

/// Modules whose findings about files under /home are the user's own to review.
const USER_MODULES: [&str; 4] = ["persistence", "desktop_session", "fs_perms", "proc_audit"];

/// "PID 123 …" in a line of evidence.
fn pid_in(evidence: &str) -> Option<u32> {
    evidence.split("PID ").nth(1)?.split(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
}

/// The file a finding is about: its evidence starts with the path.
fn file_in(evidence: &str) -> Option<String> {
    let first = evidence.lines().next()?;
    if !first.starts_with('/') {
        return None;
    }
    let end = [" mode ", " sha256 ", " (", ": "].iter().filter_map(|s| first.find(s)).min().unwrap_or(first.len());
    let path = first[..end].trim();
    // "path:12" points at a line of the file
    Some(path.rsplit_once(':').filter(|(_, n)| n.chars().all(|c| c.is_ascii_digit())).map(|(p, _)| p).unwrap_or(path).to_string())
}

fn local_time(t: SystemTime) -> String {
    chrono::DateTime::<chrono::Local>::from(t).format("%Y-%m-%d %H:%M:%S %z").to_string()
}

/// When a process started: the kernel's boot time plus the ticks in /proc/<pid>/stat.
fn started(sys: &SysRoot, pid: u32) -> Option<String> {
    let stat = sys.read_string(format!("/proc/{pid}/stat")).ok()?;
    // field 22; the name in parentheses may contain spaces
    let ticks: u64 = stat.rsplit_once(')')?.1.split_whitespace().nth(19)?.parse().ok()?;
    let boot: u64 = sys.read_string("/proc/stat").ok()?.lines().find_map(|l| l.strip_prefix("btime "))?.trim().parse().ok()?;
    // Linux reports these ticks at 100 per second
    Some(local_time(UNIX_EPOCH + Duration::from_secs(boot + ticks / 100)))
}

/// The program file of a process, without the "(deleted)" mark.
fn program(p: &ProcInfo) -> Option<String> {
    p.exe_path().filter(|e| e.starts_with('/')).map(str::to_string)
}

/// Mark levels and add the context lines. `processes` is the snapshot the modules used.
pub fn add(sys: &SysRoot, processes: &[ProcInfo], col: &mut Collector) {
    let by_pid: HashMap<u32, &ProcInfo> = processes.iter().map(|p| (p.pid, p)).collect();
    let mut paths: Vec<String> = Vec::new();
    for f in &col.findings {
        if let Some(p) = pid_in(&f.evidence).and_then(|pid| by_pid.get(&pid)) {
            paths.extend(program(p));
        }
        paths.extend(file_in(&f.evidence));
    }
    paths.sort();
    paths.dedup();
    let has_dpkg = !sys.dir_names("/var/lib/dpkg/info").is_empty();
    let packages = if has_dpkg { packages_of(sys, &paths) } else { HashMap::new() };
    let package = |path: &str| packages.get(path).map(|p| p.split(':').next().unwrap_or(p).to_string());

    for f in col.findings.iter_mut() {
        let mut lines = Vec::new();
        let mut packaged = false;
        if let Some(p) = pid_in(&f.evidence).and_then(|pid| by_pid.get(&pid)) {
            let parent = by_pid.get(&p.ppid).map(|q| format!(" ({})", q.display_name())).unwrap_or_default();
            let mut line = format!("context: PID {} PPID {}{parent} UID {}", p.pid, p.ppid, p.uid);
            if let Some(exe) = program(p) {
                packaged = package(&exe).is_some();
                if has_dpkg {
                    line.push_str(&format!(", package: {}", package(&exe).unwrap_or_else(|| "none".into())));
                }
            }
            if let Some(time) = started(sys, p.pid) {
                line.push_str(&format!(", started {time}"));
            }
            lines.push(line);
        } else if let Some(path) = file_in(&f.evidence) {
            if let Ok(meta) = std::fs::symlink_metadata(sys.path(&path)) {
                // only where packages put files: "package: none" says nothing about a log or
                // a file in a home folder
                let packaged_place = ["/usr/", "/etc/", "/bin/", "/sbin/", "/lib/", "/boot/", "/opt/"].iter().any(|d| path.starts_with(d));
                let owner = match package(&path) {
                    Some(p) => format!("package: {p}, "),
                    None if has_dpkg && meta.is_file() && packaged_place => "package: none, ".to_string(),
                    None => String::new(),
                };
                if let Ok(modified) = meta.modified() {
                    lines.push(format!("context: {owner}modified {}", local_time(modified)));
                }
            }
        }
        let ordinary = ORDINARY.contains(&rule_key(f).as_str()) || (packaged && ORDINARY_WHEN_PACKAGED.contains(&f.rule.as_str()));
        if f.severity == Severity::Low && ordinary {
            f.severity = Severity::Info;
        }
        let own_file = file_in(&f.evidence).map(|p| p.starts_with("/home/")).unwrap_or(false);
        f.user_level = own_file && f.severity <= Severity::Medium && USER_MODULES.contains(&f.module.as_str());
        for line in lines {
            f.evidence.push('\n');
            f.evidence.push_str(&line);
        }
    }
}

/// A session script of the user's own is ordinary; one in a system folder is not.
fn rule_key(f: &Finding) -> String {
    if f.rule == "PERS-SESSION-SCRIPT" && f.evidence.starts_with("/home/") {
        return "PERS-SESSION-SCRIPT-OWN".to_string();
    }
    f.rule.clone()
}
