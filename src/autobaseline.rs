//! Automatic baseline: the scanner saves a baseline of the machine by itself after the first
//! complete scan as root, and compares against it afterwards, so nobody has to remember to.

use crate::baseline::Baseline;
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

/// Put the current state of files verified as apt upgrades into the baseline.
pub fn refresh_upgraded(report: &Report, path: &std::path::Path) -> Result<usize, crate::error::ScanError> {
    let mut base = Baseline::load(path)?;
    let mut n = 0;
    for file in &report.upgraded_files {
        if let Some(e) = report.inventory.suid.iter().find(|e| &e.path == file) {
            base.suid.retain(|x| &x.path != file);
            base.suid.push(e.clone());
            n += 1;
        }
        if let Some(hash) = report.inventory.persistence_files.get(file) {
            base.persistence_files.insert(file.clone(), hash.clone());
            n += 1;
        }
    }
    base.suid.sort_by(|a, b| a.path.cmp(&b.path));
    base.save(path)?;
    Ok(n)
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
            ModuleId::Persistence => base.persistence_files.extend(report.inventory.persistence_files.clone()),
            ModuleId::DesktopSession => {
                // older versions recorded the same files under persistence; only add what is missing
                let had_persistence = base.modules.iter().any(|x| x == "persistence");
                for (path, hash) in &report.inventory.persistence_files {
                    if crate::modules::desktop_session::is_desktop_path(path) && (!had_persistence || crate::baseline::newly_tracked(path)) {
                        base.persistence_files.entry(path.clone()).or_insert_with(|| hash.clone());
                    }
                }
                base.desktop = report.inventory.desktop.clone();
            }
            _ => {}
        }
        base.modules.push(id.to_string());
        added.push(id.to_string());
    }
    // Kinds of files that later versions started to track.
    if base.scanner_version != env!("CARGO_PKG_VERSION") && report.modules.iter().any(|m| m == "persistence") {
        let mut new_files = 0;
        for (path, hash) in &report.inventory.persistence_files {
            if crate::baseline::newly_tracked(path) && !base.persistence_files.contains_key(path) {
                base.persistence_files.insert(path.clone(), hash.clone());
                new_files += 1;
            }
        }
        if new_files > 0 {
            added.push(format!("{new_files} newly tracked file(s)"));
        }
        if base.accounts.is_empty() && !report.inventory.accounts.is_empty() {
            base.accounts = report.inventory.accounts.clone();
            added.push("the account list".to_string());
        }
        if base.boot.is_empty() && !report.inventory.boot.is_empty() {
            base.boot = report.inventory.boot.clone();
            if !base.modules.iter().any(|m| m == "kernel") {
                base.modules.push("kernel".to_string());
            }
            added.push("the boot settings".to_string());
        }
        base.scanner_version = env!("CARGO_PKG_VERSION").to_string();
        if added.is_empty() && base.save(path).is_ok() {
            return AutoBaseline::NotNeeded;
        }
    }
    if added.is_empty() {
        return AutoBaseline::NotNeeded;
    }
    match base.save(path) {
        Ok(()) => AutoBaseline::Completed(path.to_path_buf(), added),
        Err(_) => AutoBaseline::NotNeeded,
    }
}
