//! External Debian tools: debsums, chkrootkit, rkhunter and lynis.
//!
//! Each tool is first looked up in PATH and in /usr/sbin, /sbin etc. If it is missing
//! a note is logged and the scan continues. The tools run with a timeout
//! and their output is turned into [`Finding`] entries.

use crate::config::Config;
use crate::error::ScanError;
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, shq};
use crate::modules::Collector;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Tool {
    Debsums,
    Chkrootkit,
    Rkhunter,
    Lynis,
}

impl Tool {
    pub const ALL: [Tool; 4] = [Tool::Debsums, Tool::Chkrootkit, Tool::Rkhunter, Tool::Lynis];

    pub fn binary(&self) -> &'static str {
        match self {
            Tool::Debsums => "debsums",
            Tool::Chkrootkit => "chkrootkit",
            Tool::Rkhunter => "rkhunter",
            Tool::Lynis => "lynis",
        }
    }

    pub fn args(&self) -> &'static [&'static str] {
        match self {
            Tool::Debsums => &["-c"],
            Tool::Chkrootkit => &["-q"],
            Tool::Rkhunter => &["--check", "--sk", "--nocolors", "--rwo"],
            Tool::Lynis => &["audit", "system", "--quick", "--no-colors"],
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Tool::Debsums => "Compares installed files with the package checksums",
            Tool::Chkrootkit => "Looks for known rootkits",
            Tool::Rkhunter => "Rootkit and backdoor hunting (writes a log in /var/log)",
            Tool::Lynis => "Security audit of the system (writes a report in /var/log)",
        }
    }

    pub fn module(&self) -> String {
        format!("external:{}", self.binary())
    }
}

impl std::str::FromStr for Tool {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Tool::ALL
            .iter()
            .find(|t| t.binary().eq_ignore_ascii_case(s.trim()))
            .copied()
            .ok_or_else(|| format!("unknown tool '{s}' (debsums, chkrootkit, rkhunter, lynis)"))
    }
}

const EXTRA_DIRS: [&str; 6] = ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin", "/usr/bin", "/bin"];

/// Look up a program in PATH and in the usual sbin directories.
pub fn find_binary(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    dirs.extend(EXTRA_DIRS.iter().map(PathBuf::from));
    dirs.into_iter().map(|d| d.join(name)).find(|p| {
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

pub fn availability() -> Vec<(Tool, Option<PathBuf>)> {
    Tool::ALL.iter().map(|t| (*t, find_binary(t.binary()))).collect()
}

#[derive(Debug, Clone, Default)]
pub struct CmdOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// Run a program, read stdout/stderr and stop after `timeout_secs`.
pub fn run_capture(program: &Path, args: &[&str], timeout_secs: u64) -> Result<CmdOutput, ScanError> {
    let tool = program.display().to_string();
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ScanError::Tool { tool: tool.clone(), msg: e.to_string() })?;

    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_t = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(p) = out_pipe.as_mut() {
            let _ = p.read_to_end(&mut s);
        }
        String::from_utf8_lossy(&s).into_owned()
    });
    let err_t = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(p) = err_pipe.as_mut() {
            let _ = p.read_to_end(&mut s);
        }
        String::from_utf8_lossy(&s).into_owned()
    });

    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.code(),
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(timeout_secs) {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(ScanError::Tool { tool, msg: e.to_string() }),
        }
    };
    Ok(CmdOutput {
        status,
        stdout: out_t.join().unwrap_or_default(),
        stderr: err_t.join().unwrap_or_default(),
        timed_out,
    })
}

/// Run a tool if it exists and put the findings in `col`.
pub fn run_tool(tool: Tool, cfg: &Config, col: &mut Collector) {
    let Some(bin) = find_binary(tool.binary()) else {
        col.note(format!(
            "{} is missing – skipped (install with: apt install {})",
            tool.binary(),
            tool.binary()
        ));
        return;
    };
    let out = match run_capture(&bin, tool.args(), cfg.external_tool_timeout_secs) {
        Ok(o) => o,
        Err(e) => {
            col.note(e.to_string());
            return;
        }
    };
    if out.timed_out {
        col.note(format!("{} was stopped after {} s", tool.binary(), cfg.external_tool_timeout_secs));
    }
    let findings = match tool {
        Tool::Debsums => parse_debsums(&out.stdout, &out.stderr),
        Tool::Chkrootkit => parse_chkrootkit(&out.stdout),
        Tool::Rkhunter => parse_rkhunter(&out.stdout),
        Tool::Lynis => {
            let report = std::fs::read_to_string("/var/log/lynis-report.dat").unwrap_or_default();
            parse_lynis(&out.stdout, &report)
        }
    };
    col.note(format!(
        "{} ran ({}) and gave {} finding(s)",
        tool.binary(),
        bin.display(),
        findings.len()
    ));
    col.findings.extend(findings);
}

fn debsums_severity(path: &str) -> Severity {
    let bin_dirs = ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/", "/lib/modules/", "/usr/lib/modules/", "/boot/"];
    if bin_dirs.iter().any(|d| path.starts_with(d)) || path.ends_with(".so") || path.contains(".so.") || path.contains("/security/") {
        Severity::Critical
    } else if path.starts_with("/usr/share/") {
        Severity::Low
    } else if path.starts_with("/etc/") {
        Severity::Medium
    } else {
        Severity::High
    }
}

/// `debsums -c` prints changed files on stdout (one per line) and
/// "debsums: missing file X (from Y package)" / "changed file" on stderr.
pub fn parse_debsums(stdout: &str, stderr: &str) -> Vec<Finding> {
    let module = Tool::Debsums.module();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut changed = |path: &str, pkg: Option<&str>, out: &mut Vec<Finding>| {
        if !seen.insert(path.to_string()) {
            return;
        }
        let sev = debsums_severity(path);
        out.push(
            Finding::new(sev, &module, "EXT-DEBSUMS-CHANGED", format!("Changed package file: {path}"))
                .evidence(format!("debsums -c: {path}{}", pkg.map(|p| format!(" (package {p})")).unwrap_or_default()))
                .description("The file's checksum does not match the installed .deb package. System binaries and libraries changed outside apt are a strong sign of intrusion (or a local change that should be documented).")
                .verify(format!("dpkg -S {}", shq(path)))
                .verify(format!("debsums -s \"$(dpkg -S {} | cut -d: -f1)\"", shq(path)))
                .verify(format!("ls -l --time-style=full-iso {}", shq(path)))
                .verify(format!("apt-get download \"$(dpkg -S {} | cut -d: -f1)\"   # compare with the original", shq(path))),
        );
    };
    for line in stdout.lines().map(|l| l.trim()) {
        if line.starts_with('/') {
            changed(line, None, &mut out);
        }
    }
    for line in stderr.lines().map(|l| l.trim()) {
        let rest = line.strip_prefix("debsums: ").unwrap_or(line);
        let pkg = rest
            .split("(from ")
            .nth(1)
            .and_then(|r| r.split_whitespace().next());
        if let Some(r) = rest.strip_prefix("changed file ") {
            let path = r.split(" (from").next().unwrap_or(r).trim();
            changed(path, pkg, &mut out);
        } else if let Some(r) = rest.strip_prefix("missing file ") {
            let path = r.split(" (from").next().unwrap_or(r).trim();
            out.push(
                Finding::new(Severity::Low, &module, "EXT-DEBSUMS-MISSING", format!("Missing package file: {path}"))
                    .evidence(line.to_string())
                    .description("A file the package installed no longer exists. Usually removed documentation (dpkg path-exclude), but a removed system file can also be a trace of an intrusion.")
                    .verify(format!("dpkg -S {}", shq(path))),
            );
        }
    }
    // Several changed documentation/theme files (Low, under /usr/share) become one finding.
    let (low, mut rest): (Vec<Finding>, Vec<Finding>) = out.into_iter().partition(|f| f.rule == "EXT-DEBSUMS-CHANGED" && f.severity == Severity::Low);
    if low.len() >= 3 {
        let files: Vec<String> = low.iter().map(|f| f.title.trim_start_matches("Changed package file: ").to_string()).collect();
        rest.push(
            Finding::new(Severity::Low, &module, "EXT-DEBSUMS-CHANGED", format!("{} documentation/data files differ from their packages", files.len()))
                .evidence(files.join("\n"))
                .description("These files under /usr/share do not match their .deb packages. They are not programs, so this is usually a local edit or a package script that rewrote them. Programs and libraries that differ are reported separately and are far more serious.")
                .verify("debsums -c")
                .verify("dpkg -S <file>"),
        );
    } else {
        rest.extend(low);
    }
    rest
}

/// chkrootkit -q only prints deviations.
pub fn parse_chkrootkit(stdout: &str) -> Vec<Finding> {
    let module = Tool::Chkrootkit.module();
    let mut out = Vec::new();
    let mut other = Vec::new();
    let mut ignored = 0usize;
    for line in stdout.lines().map(|l| l.trim_end()).filter(|l| !l.trim().is_empty()) {
        let lower = line.to_lowercase();
        // chkrootkit marks files that belong to Debian packages itself; permission errors mean we are not root
        // ifpromisc: a network card in "sniffer" mode from NetworkManager/wpa_supplicant/dhcp is normal
        let owners: Vec<&str> = line.split(['(', ',', ')']).filter(|p| p.contains('[')).collect();
        let benign_sniffer = lower.contains("packet sniffer")
            && !owners.is_empty()
            && owners.iter().all(|p| {
                ["networkmanager", "wpa_supplicant", "dhclient", "dhcpcd", "systemd-networkd", "iwd"]
                    .iter()
                    .any(|ok| p.to_lowercase().contains(ok))
            });
        if benign_sniffer || line.contains("[From Debian package:") || lower.contains("permission denied") || lower.contains("needs root privileges") {
            ignored += 1;
            continue;
        }
        if lower.contains("infected") && !lower.contains("not infected") {
            out.push(
                Finding::new(Severity::Critical, &module, "EXT-CHKROOTKIT-INFECTED", format!("chkrootkit: {}", clip(line.trim(), 120)))
                    .evidence(line.trim().to_string())
                    .description("chkrootkit reports an infected file or a known rootkit. Check manually – some tests give known false alarms.")
                    .verify("chkrootkit -x | less")
                    .verify("debsums -c"),
            );
        } else {
            other.push(line.trim().to_string());
        }
    }
    // Headings without lines of their own ("... were found:") mean nothing once the lines below are filtered out
    let mut kept: Vec<String> = Vec::new();
    for (i, l) in other.iter().enumerate() {
        let is_header = l.ends_with(':') || l.ends_with("failed):");
        let next_is_content = other.get(i + 1).map(|n| !(n.ends_with(':'))).unwrap_or(false);
        if !is_header || next_is_content {
            kept.push(l.clone());
        }
    }
    // chkwtmp: a gap in the login records is common (crashes, power cuts, the move to wtmpdb) – keep it apart and Low
    let mut wtmp: Vec<String> = Vec::new();
    let mut other: Vec<String> = Vec::new();
    let mut i = 0;
    while i < kept.len() {
        if kept[i].to_lowercase().contains("chkwtmp") {
            wtmp.push(kept[i].clone());
            while i + 1 < kept.len() && kept[i + 1].contains("deletion") {
                wtmp.push(kept[i + 1].clone());
                i += 1;
            }
        } else {
            other.push(kept[i].clone());
        }
        i += 1;
    }
    if wtmp.iter().any(|l| l.contains("deletion")) {
        out.push(
            Finding::new(Severity::Low, &module, "EXT-CHKROOTKIT-WTMP", "chkrootkit: a gap in the login records (wtmp)")
                .evidence(wtmp.join("\n"))
                .description("chkwtmp found zeroed entries in the login history. That usually comes from a crash, a power cut or a reboot while the file was written (Debian 13 is also moving from wtmp to wtmpdb). It is only worth a closer look if the time matches a moment you were logged in and did not crash anything.")
                .verify("last -x | head -40")
                .verify("chkrootkit chkwtmp"),
        );
    }
    if ignored > 0 && other.is_empty() && out.is_empty() {
        return out;
    }
    if !other.is_empty() {
        let sev = if other.iter().any(|l| l.to_lowercase().contains("suspicious") || l.to_lowercase().contains("possible")) {
            Severity::High
        } else {
            Severity::Medium
        };
        out.push(
            Finding::new(sev, &module, "EXT-CHKROOTKIT-WARN", format!("chkrootkit reported {} deviation(s)", other.len()))
                .evidence(clip(&other.join("\n"), 1500))
                .description("The lines below are chkrootkit's warnings (suspicious files, hidden directories, promiscuous network card …). Review every line.")
                .verify("chkrootkit"),
        );
    }
    out
}

/// rkhunter warnings that are known and harmless on Debian 13.
const RKHUNTER_KNOWN_DEBIAN: [(&str, &str); 4] = [
    ("/etc/.updated", "/etc/.updated is created by systemd-update-done and only holds a timestamp."),
    ("/usr/bin/lwp-request", "lwp-request is a Perl script from the Debian package libwww-perl; rkhunter thinks it replaced a program."),
    ("/etc/.resolv.conf.systemd-resolved.bak", "Backup copy that systemd-resolved creates at installation."),
    ("/dev/shm/PostgreSQL", "Shared memory used by PostgreSQL."),
];

/// A known false alarm: (why it is harmless, command that silences it).
fn rkhunter_known(g: &[String], text: &str) -> Option<(String, String)> {
    if g.first().map(|l| l.starts_with("Suspicious file types found in /dev")).unwrap_or(false) {
        let paths: Vec<String> = g[1..].iter().map(|l| l.split(": ").next().unwrap_or(l).trim().to_string()).collect();
        if !paths.is_empty() && paths.iter().all(|p| p.starts_with("/dev/shm/")) {
            let args: Vec<String> = paths.iter().map(|p| format!("'ALLOWDEVFILE={p}'")).collect();
            return Some((
                "These are shared-memory files that desktop programs (audio plug-ins, browsers, Wine …) create in /dev/shm.".into(),
                format!("printf '%s\\n' {} | sudo tee -a /etc/rkhunter.conf.local", args.join(" ")),
            ));
        }
    }
    if text.contains("'PermitRootLogin' has not been set") {
        return Some((
            "Debian 13's sshd defaults to PermitRootLogin prohibit-password, so root cannot log in with a password; rkhunter only wants the setting written down explicitly.".into(),
            "echo 'PermitRootLogin prohibit-password' | sudo tee /etc/ssh/sshd_config.d/10-permit-root-login.conf".into(),
        ));
    }
    RKHUNTER_KNOWN_DEBIAN
        .iter()
        .find(|(needle, _)| text.contains(needle))
        .map(|(n, why)| (why.to_string(), rkhunter_silence(n)))
}

fn rkhunter_silence(needle: &str) -> String {
    if needle.contains("lwp-request") {
        format!("echo 'SCRIPTWHITELIST={needle}' | sudo tee -a /etc/rkhunter.conf.local")
    } else {
        format!("echo 'ALLOWHIDDENFILE={needle}' | sudo tee -a /etc/rkhunter.conf.local")
    }
}

/// rkhunter --rwo prints "Warning: ..." followed by indented continuation lines.
pub fn parse_rkhunter(stdout: &str) -> Vec<Finding> {
    let module = Tool::Rkhunter.module();
    let mut groups: Vec<Vec<String>> = Vec::new();
    for line in stdout.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Some(rest) = t.strip_prefix("Warning:") {
            groups.push(vec![rest.trim().to_string()]);
        } else if let Some(g) = groups.last_mut() {
            g.push(t.to_string());
        }
    }
    groups
        .into_iter()
        .map(|g| {
            let text = g.join("\n");
            let lower = text.to_lowercase();
            if let Some((why, fix)) = rkhunter_known(&g, &text) {
                return Finding::new(Severity::Low, &module, "EXT-RKHUNTER-KNOWN", format!("rkhunter (known Debian false alarm): {}", clip(g.first().map(|s| s.as_str()).unwrap_or(""), 100)))
                    .evidence(clip(&text, 1500))
                    .description(format!("{why} If you agree, the last command below silences the warning."))
                    .verify("grep -A5 Warning /var/log/rkhunter.log")
                    .verify(fix);
            }
            let sev = if lower.contains("rootkit") || lower.contains("possible") || lower.contains("hidden") {
                Severity::High
            } else {
                Severity::Medium
            };
            Finding::new(sev, &module, "EXT-RKHUNTER-WARN", format!("rkhunter: {}", clip(g.first().map(|s| s.as_str()).unwrap_or(""), 120)))
                .evidence(clip(&text, 1500))
                .description("rkhunter warns. Many warnings after package updates go away with 'rkhunter --propupd' – only run it when the system is known to be clean.")
                .verify("grep -A5 Warning /var/log/rkhunter.log")
        })
        .collect()
}

/// What a Lynis warning id means in plain words.
fn lynis_note(id: &str) -> String {
    match id {
        "PKGS-7392" => "Lynis found installed packages with known vulnerabilities, which usually means security updates are waiting. The \"updates\" check of this scanner lists them; install them with: apt update && apt upgrade (as root).".into(),
        "TIME-3185" => "systemd-timesyncd has not synchronised the clock recently (for example because the computer was offline). A wrong clock breaks logs and certificates. Check: timedatectl timesync-status.".into(),
        _ => "Lynis reports a warning in the security audit. Run the command below for Lynis's own explanation.".into(),
    }
}

/// Lynis: warnings from the report file (warning[]=ID|text|…) or from the output ("! text [ID]").
pub fn parse_lynis(stdout: &str, report_dat: &str) -> Vec<Finding> {
    let module = Tool::Lynis.module();
    let mut warnings: Vec<(String, String)> = report_dat
        .lines()
        .filter_map(|l| l.strip_prefix("warning[]="))
        .map(|w| {
            let mut p = w.split('|');
            let id = p.next().unwrap_or("").to_string();
            let text = p.next().unwrap_or("").to_string();
            (id, text)
        })
        .collect();
    if warnings.is_empty() {
        for l in stdout.lines().map(|l| l.trim()) {
            if let Some(rest) = l.strip_prefix("! ") {
                let id = rest.rsplit('[').next().map(|s| s.trim_end_matches(']').to_string()).unwrap_or_default();
                let text = rest.split(" [").next().unwrap_or(rest).to_string();
                warnings.push((id, text));
            }
        }
    }
    let suggestions = report_dat.lines().filter(|l| l.starts_with("suggestion[]=")).count();
    let mut out: Vec<Finding> = warnings
        .into_iter()
        .map(|(id, text)| {
            Finding::new(Severity::Medium, &module, "EXT-LYNIS-WARN", format!("Lynis: {}", clip(&text, 120)))
                .evidence(format!("{id}: {text}"))
                .description(lynis_note(&id))
                .verify(format!("sudo lynis show details {}", shq(&id)))
        })
        .collect();
    if suggestions > 0 {
        out.push(
            Finding::new(Severity::Low, &module, "EXT-LYNIS-SUGGEST", format!("Lynis has {suggestions} hardening suggestions"))
                .evidence({
                    let mut lines: Vec<String> = report_dat
                        .lines()
                        .filter_map(|l| l.strip_prefix("suggestion[]="))
                        .map(|l| {
                            let mut p = l.split('|');
                            format!("{}: {}", p.next().unwrap_or(""), p.next().unwrap_or(""))
                        })
                        .take(15)
                        .collect();
                    if suggestions > 15 {
                        lines.push(format!("… and {} more (see the verification command)", suggestions - 15));
                    }
                    lines.join("\n")
                })
                .description("Hardening suggestions – no signs of intrusion in themselves. The first ones are listed below; each ID can be looked up with lynis show details.")
                .verify("grep suggestion /var/log/lynis-report.dat"),
        );
    }
    out
}
