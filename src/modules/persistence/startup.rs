//! More things that run or reroute by themselves: login message scripts, log rotation
//! scripts, proxy settings of command line tools, proxy auto-config files, and programs in
//! system folders that no package installed.

use super::hooks::serious_lines;
use super::{record, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{capped, clip, cut_short, max_severity, reasons, shq};
use crate::modules::secrets::{hide_secrets, judge_proxy};
use crate::modules::{debianfs, homeindex, Collector, ScanCtx};
use crate::pkgverify::{verify_paths, Verdict};
use md5::{Digest, Md5};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::time::SystemTime;
use walkdir::WalkDir;

type Homes = [(String, u32, String)];

/// What dpkg says about a script: `None` when it is exactly what its package ships.
fn changed_or_foreign(verdict: Option<&Verdict>) -> Option<Option<String>> {
    match verdict {
        Some(Verdict::Upgraded { .. } | Verdict::MatchesButNoUpgrade { .. }) => None,
        Some(Verdict::Differs { package }) => Some(Some(package.clone())),
        _ => Some(None),
    }
}

fn origin(package: &Option<String>) -> String {
    package.as_ref().map(|p| format!("differs from what package {p} ships")).unwrap_or_else(|| "from no package".into())
}

// ---------------------------------------------------------------- login message scripts

fn check_motd(ctx: &ScanCtx, col: &mut Collector, has_dpkg: bool) {
    let files: Vec<String> = ctx.sys.dir_names("/etc/update-motd.d").into_iter().map(|n| format!("/etc/update-motd.d/{n}")).collect();
    let verdicts = verify_paths(ctx.sys, &files, SystemTime::UNIX_EPOCH);
    for path in files {
        record(ctx, col, &path);
        let Some(package) = changed_or_foreign(verdicts.get(&path)) else { continue };
        if !std::fs::metadata(ctx.sys.path(&path)).map(|m| m.is_file() && m.mode() & 0o111 != 0).unwrap_or(false) {
            continue;
        }
        let (issues, lines) = serious_lines(ctx, &ctx.sys.read_string(&path).unwrap_or_default());
        let severity = match max_severity(&issues) {
            Some(s) => s,
            None if has_dpkg => Severity::Medium,
            None => continue,
        };
        let why = if issues.is_empty() { String::new() } else { format!("\n{}", reasons(&issues)) };
        col.push(
            Finding::new(severity, MODULE, "PERS-MOTD", format!("Script that runs as root at every login: {path}"))
                .evidence(format!("{path}\n{}\n{}{why}", origin(&package), clip(&lines.join("\n"), 600)))
                .description("The scripts in /etc/update-motd.d build the login message and run as root whenever someone logs in on the console or over SSH.")
                .verify(format!("cat {}", shq(&path)))
                .verify(format!("dpkg -S {}", shq(&path))),
        );
    }
}

// ---------------------------------------------------------------- log rotation

/// The command lines between "postrotate" (or "prerotate" …) and "endscript".
pub fn logrotate_scripts(text: &str) -> Vec<String> {
    let mut inside = false;
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        let first = line.split_whitespace().next().unwrap_or("");
        if ["postrotate", "prerotate", "firstaction", "lastaction", "preremove"].contains(&first) {
            inside = true;
        } else if first == "endscript" {
            inside = false;
        } else if inside && !line.is_empty() && !line.starts_with('#') {
            out.push(line.to_string());
        }
    }
    out
}

fn check_logrotate(ctx: &ScanCtx, col: &mut Collector, has_dpkg: bool) {
    let mut files: Vec<String> = vec!["/etc/logrotate.conf".to_string()];
    files.extend(ctx.sys.dir_names("/etc/logrotate.d").into_iter().map(|n| format!("/etc/logrotate.d/{n}")));
    let verdicts = verify_paths(ctx.sys, &files, SystemTime::UNIX_EPOCH);
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        let Some(package) = changed_or_foreign(verdicts.get(&path)) else { continue };
        let script = logrotate_scripts(&text);
        if script.is_empty() {
            continue;
        }
        let (issues, _) = serious_lines(ctx, &script.join("\n"));
        let severity = match max_severity(&issues) {
            Some(s) => s,
            None if !has_dpkg => continue,
            // an edited configuration of an installed package
            None if package.is_some() => Severity::Low,
            None => Severity::Medium,
        };
        let why = if issues.is_empty() { String::new() } else { format!("\n{}", reasons(&issues)) };
        col.push(
            Finding::new(severity, MODULE, "PERS-LOGROTATE", format!("Log rotation runs a script from this file: {path}"))
                .evidence(format!("{path}\n{}\n{}{why}", origin(&package), clip(&script.join("\n"), 600)))
                .description("logrotate runs these commands as root, usually once a day. Check that they belong to a program you installed.")
                .verify(format!("cat {}", shq(&path)))
                .verify(format!("dpkg -S {}", shq(&path))),
        );
    }
}

// ---------------------------------------------------------------- proxies

/// Proxy settings of curl, wget or git: (the line, the proxy).
pub fn proxy_settings(path: &str, text: &str) -> Vec<(String, String)> {
    let git = path.ends_with("gitconfig") || path.ends_with("git/config");
    let curl = path.ends_with("curlrc");
    let mut section = String::new();
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with(['#', ';'])) {
        if let Some(name) = line.strip_prefix('[') {
            section = name.to_ascii_lowercase();
            continue;
        }
        let (key, value) = line.split_once(['=', ' ', '\t']).unwrap_or((line, ""));
        let key = key.trim_start_matches('-').to_ascii_lowercase();
        let value = value.trim_start_matches([' ', '=', '\t']).trim().trim_matches('"');
        let wanted = if git {
            section.starts_with("http") && key == "proxy"
        } else if curl {
            ["proxy", "x", "preproxy", "socks5", "socks5-hostname"].contains(&key.as_str())
        } else {
            ["http_proxy", "https_proxy", "ftp_proxy"].contains(&key.as_str())
        };
        if wanted && !value.is_empty() {
            out.push((line.to_string(), value.to_string()));
        }
    }
    out
}

fn check_proxy_files(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let mut files: Vec<String> = ["/etc/curlrc", "/etc/wgetrc", "/etc/gitconfig"].map(String::from).to_vec();
    for (_, _, home) in homes {
        files.extend([".curlrc", ".wgetrc", ".gitconfig", ".config/git/config"].iter().map(|f| format!("{home}/{f}")));
    }
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        if !path.contains("git") {
            record(ctx, col, &path);
        }
        let found: Vec<(Severity, String)> = proxy_settings(&path, &text).into_iter().map(|(line, value)| (judge_proxy(&value), hide_secrets(&line))).collect();
        let Some(severity) = found.iter().map(|f| f.0).max() else { continue };
        let lines: Vec<String> = found.into_iter().map(|f| f.1).collect();
        col.push(
            Finding::new(severity, MODULE, "PERS-ENV-PROXY", format!("A command line tool sends its traffic through a proxy: {path}"))
                .evidence(format!("{path}\n{}", clip(&lines.join("\n"), 500)))
                .description("Downloads and uploads of this tool pass through the named server, which can watch or change them. Company networks and debugging tools use proxies; check that you set it.")
                .verify(format!("grep -i proxy {} | sed -E 's#//[^@/]*@#//#'", shq(&path))),
        );
    }
}

/// Proxy auto-config files, which decide for browsers which server their traffic takes.
fn check_pac_files(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let walk = WalkDir::new(ctx.sys.path("/etc"))
        .max_depth(3)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.depth() == 0 || !e.file_type().is_dir() || !e.file_name().to_string_lossy().starts_with('.'))
        .filter_map(|e| e.ok());
    let mut candidates: Vec<String> = capped(walk, 30_000, "/etc for proxy auto-config files (files and folders)")
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_ascii_lowercase();
            e.file_type().is_file() && (name.ends_with(".pac") || name == "wpad.dat")
        })
        .map(|e| ctx.sys.display(e.path()))
        .collect();
    for (_, _, home) in homes {
        candidates.extend(homeindex::of(ctx, home).pac_files.iter().cloned());
    }
    let mut found = Vec::new();
    for path in candidates {
        if ctx.sys.read_string(&path).map(|t| t.contains("FindProxyForURL")).unwrap_or(false) {
            record(ctx, col, &path);
            found.push(path);
        }
    }
    if !found.is_empty() {
        found.sort();
        found.dedup();
        col.push(
            Finding::new(Severity::Low, MODULE, "PERS-PAC-FILE", "Proxy auto-config files are on this computer")
                .evidence(clip(&found.join("\n"), 700))
                .description("Such a file tells browsers which server to send each address through. It only acts where a browser or the desktop is set to use it; check that you know why it is here.")
                .verify(format!("cat {}", shq(&found[0]))),
        );
    }
}

// ---------------------------------------------------------------- files of no package

/// "/lib/x" and "/usr/lib/x" are the same file on a merged system.
fn merged(path: &str) -> String {
    match path.strip_prefix("/lib/") {
        Some(rest) => format!("/usr/lib/{rest}"),
        None => path.to_string(),
    }
}

/// Every path in the packages' file lists that lies in the swept folders.
fn listed_paths(ctx: &ScanCtx) -> HashSet<String> {
    let mut owned = HashSet::new();
    for file in ctx.sys.dir_names("/var/lib/dpkg/info").into_iter().filter(|n| n.ends_with(".list")) {
        let Ok(text) = ctx.sys.read_string(format!("/var/lib/dpkg/info/{file}")) else { continue };
        owned.extend(text.lines().filter(|l| l.starts_with("/usr/lib/") || l.starts_with("/lib/") || l.starts_with("/etc/systemd/")).map(merged));
    }
    // a diverted file lives under its new name
    if let Ok(text) = ctx.sys.read_string("/var/lib/dpkg/diversions") {
        owned.extend(debianfs::diversions(&text).into_iter().map(|d| merged(&d.1)));
    }
    owned
}

fn checksum(ctx: &ScanCtx, path: &str) -> Option<String> {
    let mut data = Vec::new();
    std::fs::File::open(ctx.sys.path(path)).ok()?.take(64 * 1024 * 1024).read_to_end(&mut data).ok()?;
    Some(Md5::digest(&data).iter().map(|b| format!("{b:02x}")).collect())
}

/// Leaves out copies and hard links of files that a package ships (some packages make them
/// when they are installed).
fn without_copies(ctx: &ScanCtx, candidates: Vec<String>) -> Vec<String> {
    if candidates.is_empty() {
        return candidates;
    }
    // several candidates may hold the same content (two links to one file)
    let sums: HashMap<String, String> = candidates.iter().filter_map(|p| Some((p.clone(), checksum(ctx, p)?))).collect();
    let wanted: HashSet<&str> = sums.values().map(String::as_str).collect();
    let mut shipped = HashSet::new();
    for file in ctx.sys.dir_names("/var/lib/dpkg/info").into_iter().filter(|n| n.ends_with(".md5sums")) {
        let Ok(text) = ctx.sys.read_string(format!("/var/lib/dpkg/info/{file}")) else { continue };
        shipped.extend(text.lines().filter_map(|l| l.split_once("  ")).filter(|(sum, _)| wanted.contains(sum)).map(|(sum, _)| sum.to_string()));
    }
    candidates.into_iter().filter(|p| !sums.get(p).is_some_and(|sum| shipped.contains(sum))).collect()
}

fn is_program(ctx: &ScanCtx, path: &str, mode: u32) -> bool {
    let name = crate::procinfo::basename(path);
    let mut head = [0u8; 4];
    mode & 0o111 != 0 || name.ends_with(".so") || name.contains(".so.") || std::fs::File::open(ctx.sys.path(path)).and_then(|mut f| f.read_exact(&mut head)).is_ok() && head == *b"\x7fELF"
}

fn check_unowned(ctx: &ScanCtx, col: &mut Collector) {
    let owned = listed_paths(ctx);
    if owned.is_empty() {
        return;
    }
    // Python packages and kernel modules have their own checks
    const SKIPPED: [&str; 5] = ["__pycache__", "dist-packages", "site-packages", "node_modules", "modules"];
    let walk = WalkDir::new(ctx.sys.path("/usr/lib"))
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !(e.file_type().is_dir() && SKIPPED.iter().any(|s| e.file_name() == *s) && (e.file_name() != "modules" || e.depth() == 1)))
        .filter_map(|e| e.ok());
    let walk = capped(walk, 600_000, "/usr/lib for programs of no package (files and folders)");
    let mut candidates = Vec::new();
    for entry in walk.filter(|e| e.file_type().is_file()) {
        let path = ctx.sys.display(entry.path());
        if owned.contains(&path) {
            continue;
        }
        let mode = entry.metadata().map(|m| m.mode()).unwrap_or(0);
        if is_program(ctx, &path, mode) {
            candidates.push(path);
            if candidates.len() >= 2000 {
                cut_short("/usr/lib for programs of no package (unlisted programs)", 2000);
                break;
            }
        }
    }
    let mut found = without_copies(ctx, candidates);
    found.sort();
    let serious = |p: &String| ["/security/", "/systemd/"].iter().any(|d| p.contains(d)) || p.split('/').any(|part| part.starts_with('.'));
    for (severity, files, title) in [
        (Severity::High, found.iter().filter(|p| serious(p)).cloned().collect::<Vec<_>>(), "Programs of no package among the login and system service files"),
        (Severity::Medium, found.iter().filter(|p| !serious(p)).cloned().collect::<Vec<_>>(), "Programs and libraries in /usr/lib that no package installed"),
    ] {
        if files.is_empty() {
            continue;
        }
        let first = files[0].clone();
        let more = files.len().saturating_sub(30);
        let mut lines: Vec<String> = files.into_iter().take(30).collect();
        if more > 0 {
            lines.push(format!("… and {more} more"));
        }
        col.push(
            Finding::new(severity, MODULE, "PERS-UNOWNED-LIB", title)
                .evidence(lines.join("\n"))
                .description("apt did not put these files in the system's library folder, and apt never checks or updates them. Software installed by hand does this; so does a planted program.")
                .verify(format!("ls -l --time-style=full-iso {}", shq(&first)))
                .verify(format!("dpkg -S {}", shq(&first))),
        );
    }
    // other files an administrator, or someone else, added to systemd's folders
    let mut added = Vec::new();
    for dir in ["/etc/systemd/system", "/etc/systemd/user"] {
        let walk = WalkDir::new(ctx.sys.path(dir)).max_depth(3).follow_links(false).into_iter().filter_map(|e| e.ok());
        for entry in capped(walk, 2000, dir).filter(|e| e.file_type().is_file()) {
            let path = ctx.sys.display(entry.path());
            // units, drop-ins and generators have their own checks
            let covered = [".service", ".timer", ".socket", ".path", ".conf"].iter().any(|e| path.ends_with(e)) || path.contains("-generators/");
            if !covered && !owned.contains(&path) {
                let program = entry.metadata().map(|m| m.mode() & 0o111 != 0).unwrap_or(false);
                record(ctx, col, &path);
                added.push((program, path));
            }
        }
    }
    if !added.is_empty() {
        added.sort();
        let severity = if added.iter().any(|a| a.0) { Severity::Medium } else { Severity::Low };
        let lines: Vec<String> = added.iter().map(|(program, p)| format!("{p}{}", if *program { " (can be run)" } else { "" })).collect();
        col.push(
            Finding::new(severity, MODULE, "PERS-UNOWNED-SYSTEM", "Other files of no package in systemd's folders")
                .evidence(clip(&lines.join("\n"), 800))
                .description("Mount units, targets and scripts here change what the system starts. Check that you or an administrator added them.")
                .verify(format!("ls -l --time-style=full-iso {}", shq(&added[0].1))),
        );
    }
}

pub fn check_startup(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let has_dpkg = !ctx.sys.dir_names("/var/lib/dpkg/info").is_empty();
    check_motd(ctx, col, has_dpkg);
    check_logrotate(ctx, col, has_dpkg);
    check_proxy_files(ctx, col, homes);
    check_pac_files(ctx, col, homes);
    if has_dpkg {
        check_unowned(ctx, col);
    }
}
