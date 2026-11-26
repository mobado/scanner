//! Was a changed file changed by apt? When the baseline comparison finds a changed (or new)
//! SUID or persistence file, this checks it against dpkg's own records:
//!
//! 1. which installed package owns the file (`/var/lib/dpkg/info/*.md5sums`, and the
//!    conffile checksums in `/var/lib/dpkg/status`),
//! 2. whether the file's content is exactly what that package ships (MD5, which is what dpkg
//!    records – the same check debsums does), and
//! 3. whether apt/dpkg installed or upgraded that package after the baseline was made
//!    (`/var/log/dpkg.log`, otherwise the time the package's file list was written).
//!
//! Only a file that passes all three is accepted as "changed by an upgrade". Everything else is
//! still reported, with the reason.

use crate::finding::{Finding, Severity};
use crate::sys::SysRoot;
use chrono::TimeZone;
use md5::{Digest, Md5};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::SystemTime;

/// The rules this module checks.
const CHECKED: [&str; 4] = ["BASE-SUID-CHANGED", "BASE-SUID-NEW", "BASE-PERSIST-CHANGED", "BASE-PERSIST-NEW"];

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// Content equals the package's file and the package was installed/upgraded after the baseline.
    Upgraded { package: String, how: String },
    /// Content equals the package's file, but there is no apt/dpkg operation since the baseline.
    MatchesButNoUpgrade { package: String },
    /// A package owns the file, but the content differs from what the package ships.
    Differs { package: String },
    /// No installed package owns the file.
    NotPackaged,
}

/// "/usr/bin/su" → the ways dpkg may list it (merged-/usr moved files from /bin to /usr/bin).
fn dpkg_names(path: &str) -> Vec<String> {
    let rel = path.trim_start_matches('/').to_string();
    let mut v = vec![rel.clone()];
    let moved = ["bin/", "sbin/", "lib/", "lib64/"];
    if let Some(rest) = rel.strip_prefix("usr/") {
        if moved.iter().any(|m| rest.starts_with(m)) {
            v.push(rest.to_string());
        }
    } else if moved.iter().any(|m| rel.starts_with(m)) {
        v.push(format!("usr/{rel}"));
    }
    v
}

fn md5_hex(data: &[u8]) -> String {
    Md5::digest(data).iter().map(|b| format!("{b:02x}")).collect()
}

/// For each wanted path: the (package, md5) records dpkg has for it.
fn package_records(sys: &SysRoot, paths: &[String]) -> HashMap<String, Vec<(String, String)>> {
    let mut wanted: HashMap<String, String> = HashMap::new(); // dpkg name → path
    for p in paths {
        for n in dpkg_names(p) {
            wanted.insert(n, p.clone());
        }
    }
    let mut out: HashMap<String, Vec<(String, String)>> = HashMap::new();
    for file in sys.dir_names("/var/lib/dpkg/info") {
        let Some(pkg) = file.strip_suffix(".md5sums") else { continue };
        let Ok(text) = sys.read_string(format!("/var/lib/dpkg/info/{file}")) else { continue };
        for line in text.lines() {
            let Some((sum, name)) = line.split_once("  ") else { continue };
            if let Some(path) = wanted.get(name.trim_start_matches("./")) {
                out.entry(path.clone()).or_default().push((pkg.to_string(), sum.to_string()));
            }
        }
    }
    // Configuration files (conffiles) have their checksum in the status file.
    if let Ok(status) = sys.read_string("/var/lib/dpkg/status") {
        let mut pkg = String::new();
        let mut in_conf = false;
        for line in status.lines() {
            if let Some(name) = line.strip_prefix("Package: ") {
                pkg = name.trim().to_string();
                in_conf = false;
            } else if line.starts_with("Conffiles:") {
                in_conf = true;
            } else if in_conf && line.starts_with(' ') {
                let mut f = line.split_whitespace();
                if let (Some(path), Some(sum)) = (f.next(), f.next()) {
                    if paths.iter().any(|p| p == path) && f.next() != Some("obsolete") {
                        out.entry(path.to_string()).or_default().push((pkg.clone(), sum.to_string()));
                    }
                }
            } else {
                in_conf = false;
            }
        }
    }
    out
}

fn bare(pkg: &str) -> &str {
    pkg.split(':').next().unwrap_or(pkg)
}

/// Packages that dpkg.log says were installed or upgraded after `since`.
fn log_operations(sys: &SysRoot, since: SystemTime) -> BTreeMap<String, String> {
    let mut ops = BTreeMap::new();
    for log in ["/var/log/dpkg.log.1", "/var/log/dpkg.log"] {
        let Ok(text) = sys.read_string(log) else { continue };
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 || !matches!(f[2], "install" | "upgrade") {
                continue;
            }
            let stamp = format!("{} {}", f[0], f[1]);
            let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&stamp, "%Y-%m-%d %H:%M:%S") else { continue };
            let Some(local) = chrono::Local.from_local_datetime(&naive).earliest() else { continue };
            if SystemTime::from(local) >= since {
                ops.insert(bare(f[3]).to_string(), format!("{} {} {} → {} on {stamp}", f[2], f[3], f[4], f[5]));
            }
        }
    }
    ops
}

/// Check one set of paths against dpkg's records.
pub fn verify_paths(sys: &SysRoot, paths: &[String], baseline_time: SystemTime) -> HashMap<String, Verdict> {
    let records = package_records(sys, paths);
    let ops = log_operations(sys, baseline_time);
    paths
        .iter()
        .map(|path| {
            let verdict = match records.get(path) {
                None => Verdict::NotPackaged,
                Some(list) => {
                    let actual = sys.read_bytes(path).ok().map(|b| md5_hex(&b));
                    match list.iter().find(|(_, sum)| Some(sum) == actual.as_ref()) {
                        None => Verdict::Differs { package: list[0].0.clone() },
                        Some((pkg, _)) => {
                            let list_file = sys.path(format!("/var/lib/dpkg/info/{pkg}.list"));
                            let rewritten = std::fs::metadata(list_file)
                                .and_then(|m| m.modified())
                                .map(|m| m > baseline_time)
                                .unwrap_or(false);
                            if let Some(op) = ops.get(bare(pkg)) {
                                Verdict::Upgraded { package: pkg.clone(), how: op.clone() }
                            } else if rewritten {
                                Verdict::Upgraded { package: pkg.clone(), how: format!("{pkg} was (re)installed after the baseline") }
                            } else {
                                Verdict::MatchesButNoUpgrade { package: pkg.clone() }
                            }
                        }
                    }
                }
            };
            (path.clone(), verdict)
        })
        .collect()
}

/// Which of these paths does an installed package own (listed in its file list, shipped
/// with a checksum, or registered as a configuration file)?
pub fn owned_paths(sys: &SysRoot, paths: &[String]) -> HashSet<String> {
    if paths.is_empty() {
        return HashSet::new();
    }
    let mut owned: HashSet<String> = package_records(sys, paths).into_keys().collect();
    let mut wanted: HashMap<String, &String> = HashMap::new(); // dpkg name → path
    for p in paths {
        for n in dpkg_names(p) {
            wanted.insert(n, p);
        }
    }
    for file in sys.dir_names("/var/lib/dpkg/info") {
        if !file.ends_with(".list") {
            continue;
        }
        let Ok(text) = sys.read_string(format!("/var/lib/dpkg/info/{file}")) else { continue };
        for line in text.lines() {
            if let Some(path) = wanted.get(line.trim_start_matches('/')) {
                owned.insert((*path).clone());
            }
        }
    }
    owned
}

/// The path a baseline finding is about (it starts the evidence).
fn path_of(f: &Finding) -> Option<String> {
    let first = f.evidence.lines().next()?;
    let end = [" mode ", " sha256 "].iter().filter_map(|s| first.find(s)).min().unwrap_or(first.len());
    first.starts_with('/').then(|| first[..end].trim().to_string())
}

/// What `apply` did.
#[derive(Debug, Default)]
pub struct Applied {
    /// Files confirmed as changed by apt (removed from the findings), with the package.
    pub upgraded: Vec<(String, String)>,
    /// One line per confirmed package operation, for the report notes.
    pub operations: Vec<String>,
}

/// Drop the baseline findings that apt explains; annotate the others with what was checked.
pub fn apply(sys: &SysRoot, findings: &mut Vec<Finding>, baseline_created: &str) -> Applied {
    let mut applied = Applied::default();
    let Ok(created) = chrono::DateTime::parse_from_str(baseline_created, "%Y-%m-%d %H:%M:%S %z") else { return applied };
    let created: SystemTime = created.into();
    let paths: Vec<String> = findings.iter().filter(|f| CHECKED.contains(&f.rule.as_str())).filter_map(path_of).collect();
    if paths.is_empty() {
        return applied;
    }
    let verdicts = verify_paths(sys, &paths, created);
    let mut ops: HashSet<String> = HashSet::new();
    let mut kept = Vec::new();
    for mut f in findings.drain(..) {
        let Some(path) = path_of(&f).filter(|_| CHECKED.contains(&f.rule.as_str())) else {
            kept.push(f);
            continue;
        };
        match verdicts.get(&path) {
            Some(Verdict::Upgraded { package, how }) => {
                applied.upgraded.push((path.clone(), package.clone()));
                ops.insert(how.clone());
                // A brand-new SUID program is still worth knowing about, even from apt.
                if f.rule == "BASE-SUID-NEW" {
                    f.severity = Severity::Low;
                    f.title = format!("New SUID/SGID file installed by package {}: {path}", bare(package));
                    f.description = format!("Checked: the file is exactly what package {} ships, and apt installed it after the baseline ({how}).", bare(package));
                    kept.push(f);
                }
            }
            Some(Verdict::MatchesButNoUpgrade { package }) => {
                if f.rule == "BASE-SUID-NEW" {
                    f.description = format!("Checked: the content matches package {}, but apt did not install or upgrade it after the baseline – so the SUID/SGID bit was most likely set by hand (chmod). Treat this as serious.", bare(package));
                } else {
                    f.severity = Severity::Medium;
                    f.description = format!("Checked: the content matches package {}, but there is no apt install or upgrade of it since the baseline (the dpkg log may have been rotated). Check when it changed.", bare(package));
                }
                kept.push(f);
            }
            Some(Verdict::Differs { package }) => {
                f.severity = Severity::Critical;
                f.description = format!("Checked: the file does NOT match what package {} ships. It was changed outside apt – an upgrade does not explain this. Reinstalling the package restores the original, but investigate first.", bare(package));
                f.verify.push(format!("debsums -s {}", bare(package)));
                kept.push(f);
            }
            Some(Verdict::NotPackaged) | None => {
                f.description.push_str(" Checked: no installed package owns this file, so an apt upgrade does not explain it.");
                kept.push(f);
            }
        }
    }
    *findings = kept;
    let mut ops: Vec<String> = ops.into_iter().collect();
    ops.sort();
    applied.operations = ops;
    applied
}
