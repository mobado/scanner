//! A second look at warnings the scanner can check itself: rkhunter's "file properties have
//! changed" against what the package ships, Lynis' package check run again, and the same gap
//! in the login records reported twice.

use crate::finding::{Finding, Severity};
use crate::modules::common::clip;
use crate::pkgverify::{verify_paths, Verdict};
use crate::sys::SysRoot;
use std::time::{Duration, SystemTime};

/// An rkhunter "file properties" warning: (file, time of the file rkhunter remembers).
/// `None` for other warnings, and when permissions or owner changed too – a new package
/// version doesn't explain that by itself.
pub fn rkhunter_changed_file(evidence: &str) -> Option<(String, u64)> {
    if !evidence.starts_with("The file properties have changed") {
        return None;
    }
    let lower = evidence.to_ascii_lowercase();
    if ["permission", "user id", "group id", "uid:", "gid:", "symbolic link", "immutable"].iter().any(|w| lower.contains(w)) {
        return None;
    }
    let line = |start: &str| evidence.lines().find_map(|l| l.trim().strip_prefix(start)).map(str::trim);
    let path = line("File:")?.to_string();
    // "Stored file modification time : 1745058028 (19-Apr-2025 12:20:28)"
    let stored = line("Stored file modification time")?.trim_start_matches([' ', ':']).split_whitespace().next()?.parse().ok()?;
    path.starts_with('/').then_some((path, stored))
}

/// rkhunter remembers files from its last `--propupd`, so every package upgrade makes it warn.
/// Files that are exactly what their package ships, and that apt replaced since, become one
/// Low finding.
pub fn explain_rkhunter(sys: &SysRoot, findings: &mut Vec<Finding>) {
    let mut explained: Vec<(String, String)> = Vec::new();
    let mut kept = Vec::new();
    let mut module = String::new();
    for mut f in findings.drain(..) {
        let changed = (f.rule == "EXT-RKHUNTER-WARN").then(|| rkhunter_changed_file(&f.evidence)).flatten();
        let Some((path, stored)) = changed else {
            kept.push(f);
            continue;
        };
        let since = SystemTime::UNIX_EPOCH + Duration::from_secs(stored);
        match verify_paths(sys, std::slice::from_ref(&path), since).remove(&path) {
            Some(Verdict::Upgraded { package, how }) => {
                module = f.module.clone();
                explained.push((format!("{path} — {how}"), package));
                continue;
            }
            Some(Verdict::Differs { package }) => {
                f.severity = Severity::High;
                f.description = format!("Checked: the file does NOT match what package {package} ships, so an upgrade does not explain this change. Find out who changed it; do not run rkhunter --propupd.");
                f.verify.push(format!("debsums -s {}", package.split(':').next().unwrap_or(&package)));
            }
            Some(Verdict::MatchesButNoUpgrade { package }) => {
                f.description = format!("Checked: the file matches what package {package} ships, but there is no apt install or upgrade of it since rkhunter last looked (the dpkg log may be rotated).");
            }
            _ => f.description.push_str(" Checked: no installed package ships a checksum for this file."),
        }
        kept.push(f);
    }
    if !explained.is_empty() {
        let mut lines: Vec<String> = explained.iter().map(|e| e.0.clone()).collect();
        lines.sort();
        kept.push(
            Finding::new(Severity::Low, &module, "EXT-RKHUNTER-UPDATED", format!("rkhunter: {} changed file(s) are updates from apt", lines.len()))
                .evidence(clip(&lines.join("\n"), 1800))
                .description("Checked: each file is exactly what its package ships, and apt installed it after rkhunter last remembered it. rkhunter keeps warning until it is told to remember the new files; the last command does that.")
                .verify("debsums -c")
                .verify("sudo rkhunter --propupd"),
        );
    }
    *findings = kept;
}

/// Lynis runs `apt-get check` once; another package program holding the lock also makes it
/// fail. `check` gets the output of a second try: (succeeded, messages).
pub fn explain_apt_check(findings: &mut [Finding], check: impl FnOnce() -> Option<(bool, String)>) {
    let Some(f) = findings.iter_mut().find(|f| f.rule == "EXT-LYNIS-WARN" && f.evidence.starts_with("PKGS-7390")) else { return };
    match check() {
        Some((true, _)) => {
            f.severity = Severity::Low;
            f.description = "Checked again: the package system is fine now (apt-get check succeeds and dpkg reports nothing unfinished). During the audit another program, such as a software center looking for updates, most likely had the package lock.".into();
        }
        Some((false, messages)) => {
            f.evidence = format!("{}\napt-get check / dpkg --audit now:\n{}", f.evidence, clip(&messages, 900));
            f.description = "Checked again: the package system still has a problem. Usually an interrupted installation; 'sudo dpkg --configure -a' and 'sudo apt-get -f install' repair it.".into();
        }
        None => {}
    }
}

/// `apt-get check` and `dpkg --audit` without locks or caches, so nothing is written.
pub fn apt_check() -> Option<(bool, String)> {
    let apt = crate::external_tools::find_binary("apt-get")?;
    let dpkg = crate::external_tools::find_binary("dpkg")?;
    let a = crate::external_tools::run_capture(&apt, &["-q", "-o", "Debug::NoLocking=true", "-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache=", "check"], 90).ok()?;
    let d = crate::external_tools::run_capture(&dpkg, &["--audit"], 60).ok()?;
    let fine = a.status == Some(0) && d.status == Some(0) && d.stdout.trim().is_empty();
    Some((fine, format!("{}{}{}", a.stdout, a.stderr, d.stdout).trim().to_string()))
}

/// chkrootkit and the scanner both see empty login records; keep one finding with both.
pub fn merge_login_gaps(findings: &mut Vec<Finding>) {
    let Some(theirs) = findings.iter().position(|f| f.rule == "EXT-CHKROOTKIT-WTMP") else { return };
    if !findings.iter().any(|f| f.rule == "INT-WTMP" && f.evidence.starts_with("/var/log/wtmp")) {
        return;
    }
    let dates: Vec<String> = findings.remove(theirs).evidence.lines().filter(|l| l.contains("deletion")).map(|l| l.trim().to_string()).collect();
    if let Some(ours) = findings.iter_mut().find(|f| f.rule == "INT-WTMP" && f.evidence.starts_with("/var/log/wtmp")) {
        ours.evidence = format!("{}\nchkrootkit dates it: {}", ours.evidence, dates.join("; "));
        ours.verify.push("sudo chkrootkit chkwtmp".into());
    }
}
