//! Installed packages that no software source offers: a `.deb` installed from a file, or a
//! version newer than anything the sources have. Compared with apt's package lists.

use super::MODULE;
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, shq};
use crate::modules::{Collector, ScanCtx};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

/// apt's own tool for reading files in any format apt can store them in.
const APT_HELPER: &str = "/usr/lib/apt/apt-helper";

/// How the baseline list marks a Debian package that the sources no longer carry.
pub const RETIRED: &str = " (retired by Debian)";

/// Packages whose replacement by a "newer" local build would matter most.
const CORE: [&str; 17] = [
    "openssh-server", "openssh-client", "sudo", "libpam-modules", "libpam-runtime", "libpam0g", "systemd", "libc6", "coreutils",
    "bash", "login", "passwd", "apt", "dpkg", "polkitd", "gpgv", "curl",
];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Installed {
    pub name: String,
    pub version: String,
    pub maintainer: String,
}

/// The installed packages in `/var/lib/dpkg/status`.
pub fn installed_packages(status: &str) -> Vec<Installed> {
    status
        .split("\n\n")
        .filter_map(|block| {
            let field = |key: &str| block.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_string());
            if !field("Status:")?.ends_with(" ok installed") {
                return None;
            }
            Some(Installed { name: field("Package:")?, version: field("Version:")?, maintainer: field("Maintainer:").unwrap_or_default() })
        })
        .collect()
}

fn order(c: Option<u8>) -> i32 {
    match c {
        None => 0,
        Some(b'~') => -1,
        Some(c) if c.is_ascii_digit() => 0,
        Some(c) if c.is_ascii_alphabetic() => c as i32,
        Some(c) => c as i32 + 256,
    }
}

/// dpkg's comparison of one part of a version: text and numbers in turn, "~" before anything.
fn compare_part(a: &[u8], b: &[u8]) -> Ordering {
    let digit = |s: &[u8], i: usize| s.get(i).is_some_and(u8::is_ascii_digit);
    let (mut i, mut j) = (0, 0);
    while i < a.len() || j < b.len() {
        while (i < a.len() && !digit(a, i)) || (j < b.len() && !digit(b, j)) {
            let (x, y) = (order(a.get(i).copied()), order(b.get(j).copied()));
            if x != y {
                return x.cmp(&y);
            }
            i += 1;
            j += 1;
        }
        while a.get(i) == Some(&b'0') {
            i += 1;
        }
        while b.get(j) == Some(&b'0') {
            j += 1;
        }
        let mut first = Ordering::Equal;
        while digit(a, i) && digit(b, j) {
            first = first.then(a[i].cmp(&b[j]));
            i += 1;
            j += 1;
        }
        if digit(a, i) {
            return Ordering::Greater;
        }
        if digit(b, j) {
            return Ordering::Less;
        }
        if first != Ordering::Equal {
            return first;
        }
    }
    Ordering::Equal
}

/// Compare two Debian versions ("epoch:upstream-revision") as dpkg does.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let parts = |v: &str| {
        let (epoch, rest) = v.split_once(':').map(|(e, r)| (e.parse().unwrap_or(0u64), r.to_string())).unwrap_or((0, v.to_string()));
        let (upstream, revision) = rest.rsplit_once('-').map(|(u, r)| (u.to_string(), r.to_string())).unwrap_or((rest.clone(), String::new()));
        (epoch, upstream, revision)
    };
    let (a, b) = (parts(a), parts(b));
    a.0.cmp(&b.0).then_with(|| compare_part(a.1.as_bytes(), b.1.as_bytes())).then_with(|| compare_part(a.2.as_bytes(), b.2.as_bytes()))
}

/// A package list that apt keeps packed (`Acquire::GzipIndexes`, usual in containers).
fn compressed(name: &str) -> bool {
    [".lz4", ".gz", ".xz", ".zst", ".bz2", ".lzma"].iter().any(|e| name.strip_suffix(e).is_some_and(|n| n.ends_with("_Packages")))
}

/// Add the versions a package list offers for the wanted packages.
fn read_list(reader: &mut impl BufRead, wanted: &HashMap<&str, &str>, out: &mut HashMap<String, Vec<String>>) {
    let mut line = Vec::new();
    let mut package: Option<String> = None;
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if let Some(value) = line.strip_prefix(b"Package: ") {
            let value = String::from_utf8_lossy(value).trim().to_string();
            package = wanted.contains_key(value.as_str()).then_some(value);
        } else if let (Some(p), Some(value)) = (&package, line.strip_prefix(b"Version: ")) {
            out.entry(p.clone()).or_default().push(String::from_utf8_lossy(value).trim().to_string());
        }
    }
}

/// Unpack a list with apt's own helper, which only writes it to its output.
fn read_compressed(path: &Path, wanted: &HashMap<&str, &str>, out: &mut HashMap<String, Vec<String>>) -> Result<(), String> {
    let mut child = Command::new(APT_HELPER)
        .arg("cat-file")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{APT_HELPER}: {e}"))?;
    if let Some(stdout) = child.stdout.take() {
        read_list(&mut BufReader::new(stdout), wanted, out);
    }
    match child.wait() {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(format!("{APT_HELPER} ended with {status}")),
        Err(e) => Err(e.to_string()),
    }
}

/// The versions apt's lists offer for the wanted packages. `None` when there are no lists.
fn offered(ctx: &ScanCtx, col: &mut Collector, wanted: &HashMap<&str, &str>) -> Option<HashMap<String, Vec<String>>> {
    let lists: Vec<String> = ctx.sys.dir_names("/var/lib/apt/lists").into_iter().filter(|n| n.ends_with("_Packages") || compressed(n)).collect();
    if lists.is_empty() {
        return None;
    }
    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for name in lists {
        let path = ctx.sys.path(format!("/var/lib/apt/lists/{name}"));
        if !std::fs::metadata(&path).is_ok_and(|m| m.is_file()) {
            continue;
        }
        if !compressed(&name) {
            let Ok(file) = std::fs::File::open(&path) else { continue };
            read_list(&mut BufReader::new(file), wanted, &mut out);
        } else if let Err(why) = read_compressed(&path, wanted, &mut out) {
            col.note(format!("The compressed package list {name} could not be read: {why}"));
        }
    }
    Some(out)
}

/// Is the package maintained by Debian itself (a debian.org address or a Debian team list)?
pub fn from_debian(maintainer: &str) -> bool {
    let Some((_, address)) = maintainer.rsplit_once('@') else { return false };
    let domain = address.trim_end().trim_end_matches('>').to_ascii_lowercase();
    domain == "debian.org" || domain.ends_with(".debian.org") || domain == "alioth-lists.debian.net"
}

/// The installed packages no source offers as expected.
#[derive(Debug, Default)]
pub struct Local {
    /// Offered by no source.
    pub unknown: Vec<Installed>,
    /// Newer than any offered version, with that version.
    pub newer: Vec<(Installed, String)>,
    /// Kernels of earlier updates.
    pub kernels: Vec<String>,
    /// Packages of Debian that the sources no longer carry, usually since an upgrade.
    pub retired: Vec<Installed>,
}

/// Sort the installed packages against what the sources offer.
pub fn local_packages(installed: &[Installed], offered: &HashMap<String, Vec<String>>) -> Local {
    let mut out = Local::default();
    for p in installed {
        match offered.get(&p.name) {
            // kernels of earlier updates leave the sources while they stay installed
            None if p.name.starts_with("linux-") && p.maintainer.contains("Debian Kernel") => out.kernels.push(p.name.clone()),
            None if from_debian(&p.maintainer) => out.retired.push(p.clone()),
            None => out.unknown.push(p.clone()),
            Some(versions) if !versions.contains(&p.version) => {
                // older than offered is an update that is waiting
                if let Some(highest) = versions.iter().max_by(|a, b| compare_versions(a, b)) {
                    if compare_versions(&p.version, highest) == Ordering::Greater {
                        out.newer.push((p.clone(), highest.clone()));
                    }
                }
            }
            Some(_) => {}
        }
    }
    out
}

pub fn check_packages(ctx: &ScanCtx, col: &mut Collector) {
    let Ok(status) = ctx.sys.read_string("/var/lib/dpkg/status") else { return };
    let installed = installed_packages(&status);
    if installed.is_empty() {
        return;
    }
    let wanted: HashMap<&str, &str> = installed.iter().map(|p| (p.name.as_str(), p.version.as_str())).collect();
    let Some(offered) = offered(ctx, col, &wanted) else {
        col.note("Locally installed packages were not looked for: apt has no package lists here (run apt update)");
        return;
    };
    // without the lists of the distribution everything would look local
    if !offered.contains_key("dpkg") && wanted.contains_key("dpkg") {
        col.note("Locally installed packages were not looked for: apt's package lists look incomplete (run apt update)");
        return;
    }
    let Local { unknown, newer, kernels, retired } = local_packages(&installed, &offered);
    let line = |p: &Installed| format!("{} {} (maintainer: {})", p.name, p.version, if p.maintainer.is_empty() { "not stated" } else { &p.maintainer });
    // the baseline remembers Debian's retired packages too, marked so that they stay quiet
    col.inventory.local_packages = Some(
        unknown.iter().map(|p| p.name.clone()).chain(newer.iter().map(|n| n.0.name.clone())).chain(retired.iter().map(|p| format!("{}{RETIRED}", p.name))).collect(),
    );
    if !kernels.is_empty() {
        col.note(format!("{} installed kernel package(s) are no longer offered by any source (kernels of earlier updates)", kernels.len()));
    }
    if !retired.is_empty() {
        let names: Vec<&str> = retired.iter().map(|p| p.name.as_str()).collect();
        col.push(
            Finding::new(Severity::Info, MODULE, "PERS-RETIRED-PACKAGE", format!("{} Debian package(s) installed that the sources no longer carry", retired.len()))
                .evidence(clip(&names.join(", "), 1500))
                .description("Packages with a Debian maintainer that no source offers, usually left over from an upgrade to a new Debian release. They get no more updates; apt autoremove or apt purge removes the ones you do not need.")
                .verify("apt list '~o'")
                .verify(format!("apt-cache policy {}", shq(&retired[0].name))),
        );
    }
    if !unknown.is_empty() {
        let lines: Vec<String> = unknown.iter().map(line).collect();
        col.push(
            Finding::new(Severity::Low, MODULE, "PERS-LOCAL-PACKAGE", format!("{} package(s) installed that no software source offers", unknown.len()))
                .evidence(clip(&lines.join("\n"), 1500))
                .description("These were installed from a .deb file, or their source has been removed. apt never updates them and nothing checks who made them. Their install scripts ran as root: check that you know each one.")
                .verify(format!("apt-cache policy {}", shq(&unknown[0].name)))
                .verify("grep ' install ' /var/log/dpkg.log | tail -30"),
        );
    }
    if !newer.is_empty() {
        let core = newer.iter().any(|(p, _)| CORE.contains(&p.name.as_str()));
        let lines: Vec<String> = newer.iter().map(|(p, highest)| format!("{} – newest offered: {highest}", line(p))).collect();
        col.push(
            Finding::new(if core { Severity::Medium } else { Severity::Low }, MODULE, "PERS-PKG-NEWER", format!("{} package(s) newer than anything the sources offer", newer.len()))
                .evidence(clip(&lines.join("\n"), 1500))
                .description(if core {
                    "A central system package has a version no source offers, so apt will not replace it. A removed backports source can leave this; so can a planted build."
                } else {
                    "These versions come from a file or from a source that is gone, so apt does not update them."
                })
                .verify(format!("apt-cache policy {}", shq(&newer[0].0.name))),
        );
    }
}
