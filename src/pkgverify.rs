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

use crate::baseline::{FROM_A_SOURCE, PACKAGE_CHANGED};
use crate::finding::{Finding, Severity};
use crate::modules::persistence::packages::explained_by_apt;
use crate::sys::SysRoot;
use chrono::TimeZone;
use md5::{Digest, Md5};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
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

/// "/a/b/../c" → "/a/c"
pub(crate) fn tidy(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
        if part == ".." {
            parts.pop();
        } else {
            parts.push(part);
        }
    }
    format!("/{}", parts.join("/"))
}

/// Links that a package ships (debian-archive-keyring has "x.gpg → x.pgp") have no checksum of
/// their own, so the file behind them is checked: (link, file), only when one package owns both.
fn packaged_links(sys: &SysRoot, paths: &[String]) -> HashMap<String, String> {
    let links: Vec<(String, String)> = paths
        .iter()
        .filter_map(|path| {
            let mut at = path.clone();
            for _ in 0..8 {
                let Some(target) = sys.read_link(&at) else { break };
                at = tidy(&sys.resolve_link_target(&at, &target));
            }
            (at != *path).then(|| (path.clone(), at))
        })
        .collect();
    let all: Vec<String> = links.iter().flat_map(|(a, b)| [a.clone(), b.clone()]).collect();
    let owners = packages_of(sys, &all);
    links.into_iter().filter(|(link, file)| owners.get(link).is_some_and(|p| owners.get(file).is_some_and(|q| bare(p) == bare(q)))).collect()
}

/// Check one set of paths against dpkg's records.
pub fn verify_paths(sys: &SysRoot, paths: &[String], baseline_time: SystemTime) -> HashMap<String, Verdict> {
    let links = packaged_links(sys, paths);
    if !links.is_empty() {
        let files: Vec<String> = paths.iter().map(|p| links.get(p).unwrap_or(p).clone()).collect();
        let verdicts = verify_files(sys, &files, baseline_time);
        return paths.iter().filter_map(|p| Some((p.clone(), verdicts.get(links.get(p).unwrap_or(p))?.clone()))).collect();
    }
    verify_files(sys, paths, baseline_time)
}

fn verify_files(sys: &SysRoot, paths: &[String], baseline_time: SystemTime) -> HashMap<String, Verdict> {
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

/// The package that owns each path (from the file lists and the recorded checksums).
pub fn packages_of(sys: &SysRoot, paths: &[String]) -> HashMap<String, String> {
    if paths.is_empty() {
        return HashMap::new();
    }
    let mut owners: HashMap<String, String> = package_records(sys, paths).into_iter().filter_map(|(path, list)| Some((path, list.first()?.0.clone()))).collect();
    let mut wanted: HashMap<String, &String> = HashMap::new(); // dpkg name → path
    for p in paths {
        for n in dpkg_names(p) {
            wanted.insert(n, p);
        }
    }
    for file in sys.dir_names("/var/lib/dpkg/info") {
        let Some(pkg) = file.strip_suffix(".list") else { continue };
        let Ok(text) = sys.read_string(format!("/var/lib/dpkg/info/{file}")) else { continue };
        for line in text.lines() {
            if let Some(path) = wanted.get(line.trim_start_matches('/')) {
                // folders are in many lists; the first owner is enough
                owners.entry((*path).clone()).or_insert_with(|| pkg.to_string());
            }
        }
    }
    owners
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
    /// Kinds of files the baseline did not hold yet that are exactly what their package ships
    /// (removed from the findings), with the package.
    pub matching: Vec<(String, String)>,
    /// One line per confirmed package operation, for the report notes.
    pub operations: Vec<String>,
    /// Boot files written again after their package was updated (kept as Info findings).
    pub rewritten: Vec<String>,
    /// Packages whose present version apt installed from a source after the baseline.
    pub packages: Vec<String>,
}

/// Drop the package changes that apt's history explains and gather the others in one finding.
fn explain_packages(sys: &SysRoot, findings: &mut Vec<Finding>, created: SystemTime, applied: &mut Applied) {
    let (changed, mut kept): (Vec<Finding>, Vec<Finding>) = findings.drain(..).partition(|f| f.rule == PACKAGE_CHANGED);
    // evidence: the name, "before: x  now: y", whether a source offers it
    let parts = |f: &Finding| {
        let mut lines = f.evidence.lines();
        let name = lines.next().unwrap_or("").to_string();
        let change = lines.next().unwrap_or("").to_string();
        let offered = lines.next() == Some(FROM_A_SOURCE);
        (name, change, offered)
    };
    let versions = |change: &str| {
        let now = change.split_once("now: ").map(|(_, v)| v.split(" (new files").next().unwrap_or(v)).unwrap_or("");
        now.split(", ").map(String::from).collect::<Vec<_>>()
    };
    let wanted: Vec<(String, String)> = changed.iter().map(parts).filter(|p| p.2).flat_map(|(name, change, _)| versions(&change).into_iter().map(move |v| (name.clone(), v))).collect();
    let explained = explained_by_apt(sys, created, &wanted);
    let mut open = Vec::new();
    for finding in &changed {
        let (name, change, offered) = parts(finding);
        if offered && explained.contains(&name) {
            applied.packages.push(name);
        } else {
            open.push(format!("{name}: {change}{}", if offered { "" } else { "  (no source offers it)" }));
        }
    }
    if let Some(first) = changed.iter().map(parts).find(|p| !applied.packages.contains(&p.0)) {
        let more = open.len().saturating_sub(40);
        open.truncate(40);
        if more > 0 {
            open.push(format!("… and {more} more"));
        }
        let count = changed.len() - applied.packages.len();
        kept.push(
            Finding::new(Severity::Medium, crate::baseline::MODULE, PACKAGE_CHANGED, format!("{count} package(s) changed since the baseline without apt installing them from a source"))
                .evidence(open.join("\n"))
                .description("apt's history does not show that apt installed these versions from a software source after the baseline, or dpkg's files for them were written again afterwards. Installing a .deb file or using dpkg does this, so does very old history that has been removed. Check each one; when they are yours, save a new baseline.")
                .verify(format!("apt-cache policy {}", crate::modules::common::shq(&first.0)))
                .verify(format!("grep -B4 -A2 '{}:' /var/log/apt/history.log", first.0))
                .verify(format!("dpkg -V {}", crate::modules::common::shq(&first.0))),
        );
    }
    *findings = kept;
}

/// A boot file that GRUB or fwupd writes itself: Info when dpkg.log shows that its package was
/// installed or upgraded after the baseline.
fn explain_boot_files(sys: &SysRoot, findings: &mut [Finding], created: SystemTime, applied: &mut Applied) {
    if !findings.iter().any(|f| f.rule == "BASE-EFI-FILE-CHANGED") {
        return;
    }
    let ops = log_operations(sys, created);
    for f in findings.iter_mut().filter(|f| f.rule == "BASE-EFI-FILE-CHANGED") {
        let Some(path) = path_of(f) else { continue };
        let file = crate::procinfo::basename(&path).to_ascii_lowercase();
        // the packages whose installation writes this file again
        let writers: &[&str] = if file.starts_with("grub") {
            &["grub-efi", "grub-common", "grub2-common"]
        } else if file.starts_with("fwupd") {
            &["fwupd"]
        } else {
            &[]
        };
        if let Some((_, how)) = ops.iter().find(|(package, _)| writers.iter().any(|w| package.starts_with(w))) {
            f.severity = Severity::Info;
            f.description = format!("Checked: dpkg.log shows an update after the baseline that writes this file again ({how}).");
            applied.rewritten.push(path);
        }
    }
}

/// Drop the baseline findings that apt explains; annotate the others with what was checked.
pub fn apply(sys: &SysRoot, findings: &mut Vec<Finding>, baseline_created: &str) -> Applied {
    let mut applied = Applied::default();
    let Ok(created) = chrono::DateTime::parse_from_str(baseline_created, "%Y-%m-%d %H:%M:%S %z") else { return applied };
    let created: SystemTime = created.into();
    explain_boot_files(sys, findings, created, &mut applied);
    explain_packages(sys, findings, created, &mut applied);
    let paths: Vec<String> = findings.iter().filter(|f| CHECKED.contains(&f.rule.as_str())).filter_map(path_of).collect();
    if paths.is_empty() {
        return applied;
    }
    let verdicts = verify_paths(sys, &paths, created);
    let mut ops: HashSet<String> = HashSet::new();
    let mut kept = Vec::new();
    // newly watched files of no package that have not changed since before the baseline
    let mut watched = Vec::new();
    let since = created.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    // the change time can't be set back without changing the clock
    let unchanged = |path: &str| std::fs::symlink_metadata(sys.path(path)).map(|m| m.ctime() <= since).unwrap_or(false);
    for mut f in findings.drain(..) {
        let Some(path) = path_of(&f).filter(|_| CHECKED.contains(&f.rule.as_str())) else {
            kept.push(f);
            continue;
        };
        // the comparison marks kinds of files that older versions did not record as Low
        let new_kind = f.rule == "BASE-PERSIST-NEW" && f.severity == Severity::Low;
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
            Some(Verdict::MatchesButNoUpgrade { package }) if new_kind => applied.matching.push((path.clone(), package.clone())),
            Some(Verdict::MatchesButNoUpgrade { package }) => {
                if f.rule == "BASE-PERSIST-NEW" {
                    f.severity = Severity::Low;
                    f.description = format!("Checked: the file is new to the baseline, but its content is exactly what package {} ships.", bare(package));
                } else if f.rule == "BASE-SUID-NEW" {
                    f.description = format!("Checked: the content matches package {}, but apt did not install or upgrade it after the baseline – so the SUID/SGID bit was most likely set by hand (chmod). Treat this as serious.", bare(package));
                } else {
                    f.severity = Severity::Medium;
                    f.description = format!("Checked: the content matches package {}, but there is no apt install or upgrade of it since the baseline (the dpkg log may have been rotated). Check when it changed.", bare(package));
                }
                kept.push(f);
            }
            Some(Verdict::Differs { package }) if new_kind && unchanged(&path) => {
                f.severity = Severity::Medium;
                f.description = format!("Checked: the file differs from what package {} ships, but it has not changed since before the baseline was made – usually a setting changed on purpose. Look at it once.", bare(package));
                kept.push(f);
            }
            Some(Verdict::Differs { package }) => {
                f.severity = Severity::Critical;
                f.description = format!("Checked: the file does NOT match what package {} ships. It was changed outside apt – an upgrade does not explain this. Reinstalling the package restores the original, but investigate first.", bare(package));
                f.verify.push(format!("debsums -s {}", bare(package)));
                kept.push(f);
            }
            Some(Verdict::NotPackaged) | None if new_kind && unchanged(&path) => watched.push(path.clone()),
            Some(Verdict::NotPackaged) | None => {
                f.description.push_str(" Checked: no installed package owns this file, so an apt upgrade does not explain it.");
                kept.push(f);
            }
        }
    }
    if !watched.is_empty() {
        watched.sort();
        kept.push(
            Finding::new(Severity::Info, crate::baseline::MODULE, "BASE-PERSIST-WATCHED", format!("{} file(s) are watched from now on", watched.len()))
                .evidence(format!("not in the baseline, unchanged since before it was made, from no package:\n{}", watched.join("\n")))
                .description("An older version of the scanner made the baseline and did not record these kinds of files. They are added to it after a clean scan as root, and changes are reported from then on.")
                .verify("ls -l --time-style=full-iso <file>"),
        );
    }
    *findings = kept;
    let mut ops: Vec<String> = ops.into_iter().collect();
    ops.sort();
    applied.operations = ops;
    applied
}
