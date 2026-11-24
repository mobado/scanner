//! Automatic baseline: the scanner saves a baseline of the machine by itself after the first
//! complete scan as root, and compares against it afterwards, so nobody has to remember to.

use crate::baseline::Baseline;
use crate::finding::{Finding, Severity};
use crate::report::Report;
use crate::scan::ModuleId;
use std::path::PathBuf;

/// Where the automatic baseline lives (root only; the folder is mode 0700).
pub const DEFAULT_PATH: &str = "/var/lib/scanner/baseline.json";

pub fn default_path() -> PathBuf {
    PathBuf::from(DEFAULT_PATH)
}

/// The automatic baseline, if it exists and can be read by this user.
pub fn default_if_exists() -> Option<PathBuf> {
    let p = default_path();
    p.is_file().then_some(p)
}

/// What `auto_save` did.
#[derive(Debug, Clone, PartialEq)]
pub enum AutoBaseline {
    /// A baseline already exists (or this is not a scan of the live system) – nothing to do.
    NotNeeded,
    /// A new baseline was saved here.
    Saved(PathBuf),
    /// An existing baseline lacked these parts and they were added from this scan.
    Completed(PathBuf, Vec<String>),
    /// Not saved, and why (shown to the person).
    Skipped(String),
}

/// Save a baseline after the first complete scan as root. It is deliberately NOT saved when
/// the scan is incomplete or found something serious: a baseline made on a compromised
/// system would make the intrusion look normal.
pub fn auto_save(report: &Report) -> AutoBaseline {
    auto_save_to(report, &default_path())
}

pub fn auto_save_to(report: &Report, path: &std::path::Path) -> AutoBaseline {
    if report.scan_root != "/" {
        return AutoBaseline::NotNeeded;
    }
    if path.exists() {
        return complete_existing(report, path);
    }
    if !report.running_as_root {
        return AutoBaseline::Skipped("No baseline yet – run the scanner as root once and it saves one by itself.".into());
    }
    let missing: Vec<&str> = ModuleId::CORE
        .iter()
        .map(|m| m.id())
        .filter(|id| !report.modules.iter().any(|m| m == id))
        .collect();
    if !missing.is_empty() {
        return AutoBaseline::Skipped(format!("No baseline yet – it is saved after a scan that includes {}.", missing.join(", ")));
    }
    if report.summary.critical > 0 || report.summary.high > 0 {
        return AutoBaseline::Skipped(
            "No baseline saved automatically because this scan found critical or high findings – a baseline taken now would treat them as normal. Check them first, then use \"Save baseline\".".into(),
        );
    }
    if let Some(dir) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return AutoBaseline::Skipped(format!("The automatic baseline could not be saved: {e}"));
        }
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    match Baseline::from_report(report).save(path) {
        Ok(()) => AutoBaseline::Saved(path.to_path_buf()),
        Err(e) => AutoBaseline::Skipped(format!("The automatic baseline could not be saved: {e}")),
    }
}

/// Changes to SUID files or persistence files after package updates were installed are
/// usually the updates themselves: lower them one step and say so.
pub fn soften_after_updates(findings: &mut [Finding], baseline_created: &str, dpkg_status_modified: Option<std::time::SystemTime>) {
    let Some(modified) = dpkg_status_modified else { return };
    let Ok(created) = chrono::DateTime::parse_from_str(baseline_created, "%Y-%m-%d %H:%M:%S %z") else { return };
    let created: std::time::SystemTime = created.into();
    if modified <= created {
        return;
    }
    for f in findings.iter_mut() {
        if f.rule == "BASE-SUID-CHANGED" || f.rule == "BASE-PERSIST-CHANGED" {
            f.severity = Severity::Medium;
            f.description.push_str(" Packages were installed or updated after the baseline was saved, so this is probably the update itself: confirm with debsums (it compares against the package), then save a fresh baseline.");
            f.verify.push("debsums -s".into());
        }
    }
}

/// An old baseline may lack a part (made by a quick scan without the file system walk). After a
/// clean scan as root that did run the part, add it, so everything is compared from now on.
fn complete_existing(report: &Report, path: &std::path::Path) -> AutoBaseline {
    if !report.running_as_root || report.summary.critical > 0 || report.summary.high > 0 {
        return AutoBaseline::NotNeeded;
    }
    let Ok(mut base) = Baseline::load(path) else { return AutoBaseline::NotNeeded };
    let mut added = Vec::new();
    for m in ModuleId::CORE {
        let id = m.id();
        if base.modules.iter().any(|x| x == id) || !report.modules.iter().any(|x| x == id) {
            continue;
        }
        match m {
            ModuleId::FsPerms => base.suid = report.inventory.suid.clone(),
            ModuleId::NetProc => base.listeners = crate::baseline::listener_keys(&report.inventory),
            ModuleId::Persistence => base.persistence_files = report.inventory.persistence_files.clone(),
            _ => {}
        }
        base.modules.push(id.to_string());
        added.push(id.to_string());
    }
    if added.is_empty() {
        return AutoBaseline::NotNeeded;
    }
    match base.save(path) {
        Ok(()) => AutoBaseline::Completed(path.to_path_buf(), added),
        Err(_) => AutoBaseline::NotNeeded,
    }
}
