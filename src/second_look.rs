//! A second look at a warning the scanner can check itself: Lynis' package check, run again.

use crate::finding::{Finding, Severity};
use crate::modules::common::clip;

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
