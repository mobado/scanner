//! Baseline: a JSON snapshot of SUID/SGID files, listening ports and
//! persistence files. A later scan is compared against it and new
//! SUID/SGID files are flagged as `Critical`.

use crate::error::ScanError;
use crate::finding::{Finding, Severity};
use crate::modules::common::shq;
use crate::modules::fs_perms::SuidEntry;
use crate::modules::Inventory;
use crate::report::Report;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const MODULE: &str = "baseline";
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ListenerKey {
    pub proto: String,
    pub port: u16,
    pub process: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Baseline {
    pub format_version: u32,
    pub created_at: String,
    pub hostname: String,
    pub kernel: String,
    pub os: String,
    pub scanner_version: String,
    /// Modules that ran when the baseline was created.
    pub modules: Vec<String>,
    pub suid: Vec<SuidEntry>,
    pub listeners: Vec<ListenerKey>,
    pub persistence_files: BTreeMap<String, String>,
}

pub fn listener_keys(inv: &Inventory) -> Vec<ListenerKey> {
    let set: BTreeSet<ListenerKey> = inv
        .connections
        .iter()
        .filter(|c| c.listening)
        .map(|c| ListenerKey {
            proto: if c.proto.starts_with("tcp") { "tcp".into() } else { "udp".into() },
            port: c.local_port,
            process: c.process.clone().unwrap_or_else(|| "?".into()),
        })
        .collect();
    set.into_iter().collect()
}

impl Baseline {
    pub fn from_report(r: &Report) -> Baseline {
        Baseline {
            format_version: FORMAT_VERSION,
            created_at: r.generated_at.clone(),
            hostname: r.hostname.clone(),
            kernel: r.kernel.clone(),
            os: r.os.clone(),
            scanner_version: r.version.clone(),
            modules: r.modules.clone(),
            suid: r.inventory.suid.clone(),
            listeners: listener_keys(&r.inventory),
            persistence_files: r.inventory.persistence_files.clone(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), ScanError> {
        let json = serde_json::to_string_pretty(self).map_err(|e| ScanError::Baseline(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| ScanError::io(path, e))
    }

    pub fn load(path: &Path) -> Result<Baseline, ScanError> {
        let text = std::fs::read_to_string(path).map_err(|e| ScanError::io(path, e))?;
        let b: Baseline = serde_json::from_str(&text).map_err(|e| ScanError::Baseline(format!("{}: {e}", path.display())))?;
        if b.format_version > FORMAT_VERSION {
            return Err(ScanError::Baseline(format!("the baseline has a newer version ({}) than the scanner supports", b.format_version)));
        }
        Ok(b)
    }
}

/// Compare the current inventory against the baseline. Only categories scanned
/// both then and now are compared; the others give a note.
pub fn compare(base: &Baseline, inv: &Inventory, modules_now: &[String]) -> (Vec<Finding>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let both = |m: &str| base.modules.iter().any(|x| x == m) && modules_now.iter().any(|x| x == m);
    let src = format!("baseline from {} ({})", base.created_at, base.hostname);

    if both("fs_perms") {
        let old: BTreeMap<&str, &SuidEntry> = base.suid.iter().map(|e| (e.path.as_str(), e)).collect();
        let new: BTreeMap<&str, &SuidEntry> = inv.suid.iter().map(|e| (e.path.as_str(), e)).collect();
        for (path, e) in &new {
            let ev = format!("{path} mode {} owner {}:{} sha256 {}", e.mode, e.uid, e.gid, e.sha256.as_deref().unwrap_or("?"));
            let verify = vec![
                format!("stat {}", shq(path)),
                format!("dpkg -S {}", shq(path)),
                format!("sha256sum {}", shq(path)),
            ];
            match old.get(path) {
                None => out.push(
                    Finding::new(Severity::Critical, MODULE, "BASE-SUID-NEW", format!("New SUID/SGID file since the baseline: {path}"))
                        .evidence(format!("{ev}\n(missing from {src})"))
                        .description("The file got SUID/SGID after the baseline was created. Unless it comes from a known package installation, this is a strong sign of a root backdoor.")
                        .verify_all(verify),
                ),
                Some(o) if o.sha256.is_some() && e.sha256.is_some() && o.sha256 != e.sha256 => out.push(
                    Finding::new(Severity::Critical, MODULE, "BASE-SUID-CHANGED", format!("SUID/SGID file content changed: {path}"))
                        .evidence(format!("{ev}\npreviously sha256 {}", o.sha256.as_deref().unwrap_or("?")))
                        .description("The content of a SUID/SGID file has changed since the baseline. After a package update that is expected (check with debsums); otherwise the binary may have been replaced.")
                        .verify_all(verify)
                        .verify("grep -E ' (upgrade|install) ' /var/log/dpkg.log | tail -20"),
                ),
                Some(o) if o.mode != e.mode || o.uid != e.uid || o.gid != e.gid => out.push(
                    Finding::new(Severity::High, MODULE, "BASE-SUID-PERMS", format!("SUID/SGID file permissions changed: {path}"))
                        .evidence(format!("now: {} {}:{}  before: {} {}:{}", e.mode, e.uid, e.gid, o.mode, o.uid, o.gid))
                        .description("Permissions or owner have changed since the baseline.")
                        .verify_all(verify),
                ),
                _ => {}
            }
        }
        for path in old.keys().filter(|p| !new.contains_key(*p)) {
            out.push(
                Finding::new(Severity::Low, MODULE, "BASE-SUID-REMOVED", format!("SUID/SGID file gone since the baseline: {path}"))
                    .evidence(format!("{path} was in {src}"))
                    .description("The file was removed or lost SUID/SGID – usually an uninstall.")
                    .verify(format!("ls -l {}", shq(path))),
            );
        }
    } else {
        notes.push("SUID/SGID was not compared with the baseline (fs_perms did not run in both scans)".into());
    }

    if both("net_proc") {
        let old: BTreeSet<(String, u16)> = base.listeners.iter().map(|l| (l.proto.clone(), l.port)).collect();
        // Programs such as KDE Connect, Tailscale or the NFS client pick a random (ephemeral)
        // port at every start. A random port of a program that already listened at baseline
        // time is not news; any other new port is, grouped per program.
        let known: BTreeSet<(String, String)> = base.listeners.iter().map(|l| (l.proto.clone(), l.process.clone())).collect();
        let mut fresh: BTreeMap<String, Vec<ListenerKey>> = BTreeMap::new();
        for l in listener_keys(inv) {
            if old.contains(&(l.proto.clone(), l.port)) {
                continue;
            }
            if l.port >= 32768 && known.contains(&(l.proto.clone(), l.process.clone())) {
                continue;
            }
            fresh.entry(l.process.clone()).or_default().push(l);
        }
        for (process, list) in fresh {
            let fixed = list.iter().any(|l| l.port < 32768);
            let ports: Vec<String> = list.iter().map(|l| format!("{}/{}", l.proto, l.port)).collect();
            out.push(
                Finding::new(
                    if fixed { Severity::High } else { Severity::Medium },
                    MODULE,
                    "BASE-LISTEN-NEW",
                    format!("New listening port(s) since the baseline: {} ({process})", ports.join(", ")),
                )
                .evidence(format!("{} owned by {process}\n(missing from {src})", ports.join(", ")))
                .description(if fixed {
                    "A service listens on a port that did not exist when the baseline was created."
                } else {
                    "A program that did not listen at baseline time now listens on random ports. Check that you know it."
                })
                .verify(format!("ss -tulpn | grep '{process}'")),
            );
        }
    } else {
        notes.push("Listening ports were not compared with the baseline (net_proc did not run in both scans)".into());
    }

    if both("persistence") {
        for (path, hash) in &inv.persistence_files {
            match base.persistence_files.get(path) {
                None => out.push(
                    Finding::new(Severity::High, MODULE, "BASE-PERSIST-NEW", format!("New persistence file since the baseline: {path}"))
                        .evidence(format!("{path} sha256 {hash}\n(missing from {src})"))
                        .description("A file that controls automatic execution (systemd, cron, ssh, pam, shell files …) has appeared.")
                        .verify(format!("cat {}", shq(path)))
                        .verify(format!("dpkg -S {}", shq(path))),
                ),
                Some(old) if old != hash => out.push(
                    Finding::new(Severity::High, MODULE, "BASE-PERSIST-CHANGED", format!("Persistence file changed since the baseline: {path}"))
                        .evidence(format!("{path}\nnow sha256 {hash}\npreviously sha256 {old}"))
                        .description("The file controls automatic execution or login and has changed. Check the change.")
                        .verify(format!("cat {}", shq(path)))
                        .verify(format!("ls -l --time-style=full-iso {}", shq(path))),
                ),
                _ => {}
            }
        }
        for path in base.persistence_files.keys().filter(|p| !inv.persistence_files.contains_key(*p)) {
            out.push(
                Finding::new(Severity::Low, MODULE, "BASE-PERSIST-REMOVED", format!("Persistence file gone since the baseline: {path}"))
                    .evidence(format!("{path} was in {src}"))
                    .description("The file has been removed since the baseline.")
                    .verify(format!("ls -l {}", shq(path))),
            );
        }
    } else {
        notes.push("Persistence files were not compared with the baseline (persistence did not run in both scans)".into());
    }
    // A baseline made by an older version did not track every kind of file yet (the library
    // path files /etc/ld.so.conf* were added later). Those are "newly tracked", not suspicious.
    if base.scanner_version != env!("CARGO_PKG_VERSION") {
        for f in out.iter_mut() {
            if f.rule == "BASE-PERSIST-NEW" && f.evidence.starts_with("/etc/ld.so.conf") {
                f.severity = Severity::Low;
                f.description = "This kind of file was not tracked yet when the baseline was made by an older scanner version, so it is new to the baseline, not necessarily new on the machine. It is added to the baseline automatically after a clean scan as root.".into();
            }
        }
    }
    (out, notes)
}
