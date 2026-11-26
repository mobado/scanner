//! Quieter ways to start code: systemd generators and drop-ins, extra file formats
//! (binfmt_misc), git hooks, installer settings (dpkg, pip, npm) and the boot image
//! (initramfs). Files are only read; `lsinitramfs` only lists what is in a boot image.

use super::{parse_unit, record, EXEC_KEYS, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_command, analyze_user_command, clip, max_severity, reasons, shq, CmdIssue};
use crate::modules::{Collector, ScanCtx};
use crate::pkgverify::owned_paths;
use std::collections::{BTreeSet, HashSet};
use std::os::unix::fs::MetadataExt;
use walkdir::WalkDir;

type Homes = [(String, u32, String)];

fn files_below(ctx: &ScanCtx, dir: &str, depth: usize) -> Vec<String> {
    let mut out: Vec<String> = WalkDir::new(ctx.sys.path(dir))
        .max_depth(depth)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.file_type().is_dir())
        .take(2000)
        .map(|e| ctx.sys.display(e.path()))
        .collect();
    out.sort();
    out
}

/// Problems of at least High on the non-comment lines of a file: (problems, lines).
fn serious_lines(ctx: &ScanCtx, text: &str) -> (Vec<CmdIssue>, Vec<String>) {
    let mut issues: Vec<CmdIssue> = Vec::new();
    let mut lines = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let found: Vec<CmdIssue> = analyze_command(line, ctx.cfg).into_iter().filter(|i| i.severity >= Severity::High).collect();
        if !found.is_empty() {
            lines.push(line.to_string());
        }
        for i in found {
            if !issues.contains(&i) {
                issues.push(i);
            }
        }
    }
    (issues, lines)
}

fn simple(severity: Severity, rule: &str, title: String, path: &str, evidence: String, description: String) -> Finding {
    Finding::new(severity, MODULE, rule, title)
        .evidence(evidence)
        .description(description)
        .verify(format!("cat {}", shq(path)))
        .verify(format!("dpkg -S {}", shq(path)))
}

// ---------------------------------------------------------------- systemd generators and drop-ins

const GENERATOR_DIRS: [&str; 8] = [
    "/etc/systemd/system-generators", "/etc/systemd/user-generators", "/run/systemd/system-generators", "/run/systemd/user-generators",
    "/usr/local/lib/systemd/system-generators", "/usr/local/lib/systemd/user-generators", "/usr/lib/systemd/system-generators",
    "/usr/lib/systemd/user-generators",
];

fn check_generators(ctx: &ScanCtx, col: &mut Collector, has_dpkg: bool) {
    let files: Vec<String> = GENERATOR_DIRS.iter().flat_map(|d| files_below(ctx, d, 1)).collect();
    let owned = owned_paths(ctx.sys, &files);
    for path in files {
        let packaged_dir = path.starts_with("/usr/lib/");
        if ctx.sys.read_link(&path).as_deref() == Some("/dev/null") {
            continue; // switched off
        }
        if !packaged_dir {
            record(ctx, col, &path);
        }
        if owned.contains(&path) || (packaged_dir && !has_dpkg) {
            continue;
        }
        let (issues, lines) = serious_lines(ctx, &ctx.sys.read_string(&path).unwrap_or_default());
        let severity = max_severity(&issues).unwrap_or(Severity::High).max(Severity::High);
        col.push(simple(
            severity,
            "PERS-SYSTEMD-GENERATOR",
            format!("systemd generator that no package installed: {path}"),
            &path,
            format!("{path}\n{}", clip(&lines.join("\n"), 600)),
            "systemd runs generators as root very early at every boot and reload, and they can create services out of thin air. Local ones are rare; make sure you know this one.".into(),
        ));
    }
}

const DROPIN_DIRS: [&str; 7] = [
    "/etc/systemd/system", "/etc/systemd/user", "/run/systemd/system", "/usr/local/lib/systemd/system",
    "/usr/local/lib/systemd/user", "/usr/lib/systemd/system", "/usr/lib/systemd/user",
];

fn check_dropins(ctx: &ScanCtx, col: &mut Collector, homes: &Homes, has_dpkg: bool) {
    let mut dirs: Vec<(String, bool)> = DROPIN_DIRS.iter().map(|d| (d.to_string(), false)).collect();
    for (_, _, home) in homes {
        dirs.push((format!("{home}/.config/systemd/user"), true));
        dirs.push((format!("{home}/.local/share/systemd/user"), true));
    }
    let mut found: Vec<(String, bool)> = Vec::new();
    let mut seen = HashSet::new();
    for (dir, own) in dirs {
        for path in files_below(ctx, &dir, 2) {
            let in_dropin = path.rsplit('/').nth(1).map(|d| d.ends_with(".d")).unwrap_or(false);
            if in_dropin && path.ends_with(".conf") && seen.insert(path.clone()) {
                found.push((path, own));
            }
        }
    }
    let owned = owned_paths(ctx.sys, &found.iter().map(|f| f.0.clone()).collect::<Vec<_>>());
    for (path, own) in found {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        let from_package = owned.contains(&path);
        if !path.starts_with("/usr/lib/") && !path.starts_with("/run/") {
            record(ctx, col, &path);
        }
        let lines: Vec<(String, String)> = parse_unit(&text)
            .into_iter()
            .filter(|(_, k, v)| !v.is_empty() && (EXEC_KEYS.contains(&k.as_str()) || k == "Environment" || k == "EnvironmentFile"))
            .map(|(_, k, v)| (k, v))
            .collect();
        let mut issues: Vec<CmdIssue> = Vec::new();
        for (_, value) in &lines {
            let command = value.trim_start_matches(['-', '@', ':', '+', '!', '|']);
            let more = if own { analyze_user_command(command, ctx.cfg) } else { analyze_command(command, ctx.cfg) };
            for i in more {
                if !issues.contains(&i) {
                    issues.push(i);
                }
            }
        }
        let unit = path.rsplit('/').nth(1).unwrap_or("?").trim_end_matches(".d").to_string();
        let body: Vec<String> = lines.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let evidence = format!("{path} changes {unit}\n{}", clip(&body.join("\n"), 600));
        let adds_code = lines.iter().any(|(k, v)| EXEC_KEYS.contains(&k.as_str()) || v.contains("LD_PRELOAD") || v.contains("LD_LIBRARY_PATH"));
        let worst = max_severity(&issues);
        // package files are only reported for clear backdoor patterns
        let severity = match worst {
            Some(s) if s >= Severity::High && (!from_package || s == Severity::Critical) => s,
            _ if adds_code && !from_package && has_dpkg && !path.starts_with("/run/") => Severity::Medium,
            _ => continue,
        };
        let why = if issues.is_empty() { String::new() } else { format!(" Suspicious: {}.", reasons(&issues)) };
        col.push(simple(
            severity,
            "PERS-SYSTEMD-DROPIN",
            format!("Drop-in adds commands to {unit}: {path}"),
            &path,
            evidence,
            format!("A drop-in changes a service without touching its file, so the service looks untouched. This one adds a command or loads a library, and no package accounts for it.{why}"),
        ).verify(format!("systemctl cat {}", shq(&unit))));
    }
}

// ---------------------------------------------------------------- binfmt_misc

/// (enabled, interpreter, flags) from a `/proc/sys/fs/binfmt_misc/<name>` file.
pub fn parse_binfmt(text: &str) -> Option<(bool, String, String)> {
    let enabled = text.lines().next()?.trim() == "enabled";
    let value = |key: &str| text.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_string());
    Some((enabled, value("interpreter ")?, value("flags:").unwrap_or_default()))
}

fn check_binfmt(ctx: &ScanCtx, col: &mut Collector, has_dpkg: bool) {
    for dir in ["/etc/binfmt.d", "/usr/local/lib/binfmt.d"] {
        for path in files_below(ctx, dir, 1) {
            record(ctx, col, &path);
        }
    }
    let base = "/proc/sys/fs/binfmt_misc";
    let formats: Vec<(String, String, String)> = ctx
        .sys
        .dir_names(base)
        .into_iter()
        .filter(|n| n != "register" && n != "status")
        .filter_map(|name| {
            let (enabled, interpreter, flags) = parse_binfmt(&ctx.sys.read_string(format!("{base}/{name}")).ok()?)?;
            enabled.then_some((name, interpreter, flags))
        })
        .collect();
    let owned = owned_paths(ctx.sys, &formats.iter().map(|f| f.1.clone()).collect::<Vec<_>>());
    for (name, interpreter, flags) in formats {
        let odd_place = ctx.cfg.is_temp_path(&interpreter) || ["/home/", "/root/", "/var/www/"].iter().any(|p| interpreter.starts_with(p));
        let system = ["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/"].iter().any(|p| interpreter.starts_with(p)) && !interpreter.starts_with("/usr/local/");
        // 'C' runs the interpreter with the rights of the started file (SUID included)
        let severity = if odd_place {
            Severity::Critical
        } else if has_dpkg && !owned.contains(&interpreter) && (flags.contains('C') || !system) {
            Severity::High
        } else if has_dpkg && !owned.contains(&interpreter) {
            Severity::Medium
        } else {
            continue;
        };
        col.push(
            Finding::new(severity, MODULE, "PERS-BINFMT", format!("Extra file format runs a program of its own: {name}"))
                .evidence(format!("{base}/{name}\ninterpreter {interpreter}\nflags: {flags}"))
                .description("The kernel starts this interpreter automatically whenever a matching file is run. Registering one is a quiet way to have your code started by other people's programs; check where the interpreter came from.")
                .verify(format!("cat {base}/{}", shq(&name)))
                .verify(format!("dpkg -S {}", shq(&interpreter)))
                .verify("grep -r . /etc/binfmt.d /usr/lib/binfmt.d 2>/dev/null"),
        );
    }
}

// ---------------------------------------------------------------- git

/// Settings in a git configuration that make git run something: "core.hooksPath = …".
pub fn git_run_settings(text: &str) -> Vec<(String, String)> {
    let mut section = String::new();
    let mut out = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.starts_with(['#', ';'])) {
        if let Some(name) = line.strip_prefix('[') {
            section = name.trim_end_matches(']').to_ascii_lowercase();
        } else if let Some((key, value)) = line.split_once('=') {
            let (key, value) = (key.trim().to_ascii_lowercase(), value.trim().trim_matches('"'));
            let runs = section == "core" && ["hookspath", "fsmonitor", "sshcommand"].contains(&key.as_str());
            if runs && !["", "true", "false"].contains(&value) {
                out.push((format!("core.{key}"), value.to_string()));
            }
        }
    }
    out
}

fn check_git(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let mut repos: Vec<String> = vec!["/etc".into(), "/root".into()];
    for parent in ["/opt", "/srv", "/usr/local", "/usr/local/src", "/var/www"] {
        repos.push(parent.into());
        repos.extend(ctx.sys.dir_names(parent).into_iter().map(|n| format!("{parent}/{n}")));
    }
    let mut configs: Vec<(String, bool)> = vec![("/etc/gitconfig".into(), true)];
    for (_, _, home) in homes {
        configs.push((format!("{home}/.gitconfig"), false));
        configs.push((format!("{home}/.config/git/config"), false));
    }
    let mut seen = BTreeSet::new();
    for repo in repos {
        let git = format!("{repo}/.git");
        if !seen.insert(git.clone()) || !ctx.sys.exists(&git) {
            continue;
        }
        configs.push((format!("{git}/config"), false));
        for path in files_below(ctx, &format!("{git}/hooks"), 1) {
            if path.ends_with(".sample") {
                continue;
            }
            let Ok(meta) = std::fs::metadata(ctx.sys.path(&path)) else { continue };
            if meta.mode() & 0o111 == 0 {
                continue;
            }
            record(ctx, col, &path);
            let text = ctx.sys.read_string(&path).unwrap_or_default();
            let (issues, lines) = serious_lines(ctx, &text);
            // etckeeper installs its own pre-commit hook in /etc
            if issues.is_empty() && git == "/etc/.git" && text.contains("etckeeper") {
                continue;
            }
            let why = if issues.is_empty() { String::new() } else { format!(" Suspicious: {}.", reasons(&issues)) };
            col.push(simple(
                max_severity(&issues).unwrap_or(Severity::Low),
                "PERS-GIT-HOOK",
                format!("Git hook in a system folder: {path}"),
                &path,
                format!("{path}\n{}", clip(&lines.join("\n"), 600)),
                format!("Git runs this script, with the rights of whoever uses the repository (often root here).{why}"),
            ));
        }
    }
    for (path, system) in configs {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        if system {
            record(ctx, col, &path);
        }
        for (key, value) in git_run_settings(&text) {
            let issues = analyze_user_command(&value, ctx.cfg);
            col.push(simple(
                max_severity(&issues).unwrap_or(Severity::Medium).max(Severity::Medium),
                "PERS-GIT-HOOK",
                format!("Git is set to run something: {key} in {path}"),
                &path,
                format!("{path}\n{key} = {}", clip(&value, 300)),
                "With this setting git runs a program or hooks from another place whenever it is used. Some developer tools set it; so can someone who wants their code run.".into(),
            ));
        }
    }
}

// ---------------------------------------------------------------- dpkg, pip, npm

/// "https://user:token@host/x" → "https://host/x"
fn hide_credentials(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
            format!("{scheme}://{}{path}", authority.rsplit('@').next().unwrap_or(authority))
        }
        None => url.to_string(),
    }
}

/// Settings in a pip or npm configuration that change where packages come from or what runs.
/// Tokens and passwords are never returned.
pub fn package_settings(text: &str, npm: bool) -> Vec<(Severity, String)> {
    let usual = |url: &str| {
        let host = super::apt::host_of(url).unwrap_or_default();
        ["pypi.org", "files.pythonhosted.org", "pypi.python.org", "registry.npmjs.org", "www.piwheels.org"].contains(&host.as_str())
    };
    let mut out = Vec::new();
    let mut key = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(['#', ';', '[']) {
            continue;
        }
        // pip continues a value on indented lines
        let value = match trimmed.split_once('=') {
            Some((k, v)) if !line.starts_with(char::is_whitespace) => {
                key = k.trim().to_ascii_lowercase().replace('_', "-");
                v.trim()
            }
            _ if line.starts_with(char::is_whitespace) => trimmed,
            _ => continue,
        }
        .trim_matches('"');
        if value.is_empty() {
            continue;
        }
        let urls = value.split_whitespace().filter(|v| v.contains("://"));
        if !npm && ["index-url", "extra-index-url", "find-links"].contains(&key.as_str()) {
            out.extend(urls.filter(|u| !usual(u)).map(|u| (Severity::Medium, format!("{key} = {}", hide_credentials(u)))));
        } else if !npm && key == "trusted-host" {
            out.push((Severity::Medium, format!("trusted-host = {value} (no certificate check)")));
        } else if npm && key == "registry" && !usual(value) {
            out.push((Severity::Medium, format!("registry = {}", hide_credentials(value))));
        } else if npm && key.ends_with(":registry") && !usual(value) {
            out.push((Severity::Low, format!("{key} = {}", hide_credentials(value))));
        } else if npm && ["script-shell", "onload-script", "init-module"].contains(&key.as_str()) {
            out.push((Severity::High, format!("{key} = {}", hide_credentials(value))));
        } else if npm && key == "strict-ssl" && value == "false" {
            out.push((Severity::Medium, "strict-ssl = false (no certificate check)".into()));
        }
    }
    out
}

fn check_package_tools(ctx: &ScanCtx, col: &mut Collector, homes: &Homes, has_dpkg: bool) {
    let mut files: Vec<(String, bool, bool)> = vec![
        ("/etc/pip.conf".into(), false, true), ("/etc/xdg/pip/pip.conf".into(), false, true),
        ("/etc/npmrc".into(), true, true), ("/usr/etc/npmrc".into(), true, true), ("/usr/local/etc/npmrc".into(), true, true),
    ];
    for (_, _, home) in homes {
        files.push((format!("{home}/.pip/pip.conf"), false, false));
        files.push((format!("{home}/.config/pip/pip.conf"), false, false));
        files.push((format!("{home}/.npmrc"), true, false));
    }
    for (path, npm, system) in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        if system {
            record(ctx, col, &path);
        }
        let found = package_settings(&text, npm);
        let Some(severity) = found.iter().map(|f| f.0).max() else { continue };
        let lines: Vec<String> = found.into_iter().map(|f| f.1).collect();
        col.push(
            Finding::new(severity, MODULE, "PERS-PKG-CONFIG", format!("{} is set to use other sources or run scripts: {path}", if npm { "npm" } else { "pip" }))
                .evidence(format!("{path}\n{}", clip(&lines.join("\n"), 600)))
                .description("Packages installed with this tool come from another server, skip the certificate check or run an extra script. Company and test setups do this; an attacker does it to slip in their own code.")
                // only the settings, never the lines that hold tokens
                .verify(format!("grep -vi -E 'token|auth|password' {}", shq(&path))),
        );
    }
    let mut dpkg = vec!["/etc/dpkg/dpkg.cfg".to_string()];
    dpkg.extend(files_below(ctx, "/etc/dpkg/dpkg.cfg.d", 1));
    let owned = owned_paths(ctx.sys, &dpkg);
    for path in dpkg {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        let hooks: Vec<&str> = text.lines().map(str::trim).filter(|l| ["pre-invoke", "post-invoke", "status-logger"].iter().any(|k| l.starts_with(k))).collect();
        if hooks.is_empty() {
            continue;
        }
        let issues: Vec<CmdIssue> = hooks.iter().filter_map(|l| l.split_once([' ', '='])).flat_map(|(_, c)| analyze_command(c, ctx.cfg)).collect();
        let severity = match max_severity(&issues) {
            Some(s) if s >= Severity::High => s,
            _ if has_dpkg && !owned.contains(&path) => Severity::Medium,
            _ => continue,
        };
        col.push(simple(severity, "PERS-DPKG-HOOK", format!("dpkg runs a command at every installation: {path}"), &path, format!("{path}\n{}", clip(&hooks.join("\n"), 600)), "dpkg runs this as root whenever a package is installed or removed.".into()));
    }
}

// ---------------------------------------------------------------- initramfs

fn check_initramfs_sources(ctx: &ScanCtx, col: &mut Collector, has_dpkg: bool) {
    let local: Vec<String> = ["/etc/initramfs-tools/hooks", "/etc/initramfs-tools/scripts"].iter().flat_map(|d| files_below(ctx, d, 3)).collect();
    let shipped: Vec<String> = ["/usr/share/initramfs-tools/hooks", "/usr/share/initramfs-tools/scripts"].iter().flat_map(|d| files_below(ctx, d, 3)).collect();
    let all: Vec<String> = local.iter().chain(shipped.iter()).cloned().collect();
    let owned = owned_paths(ctx.sys, &all);
    for path in all {
        let is_local = path.starts_with("/etc/");
        if is_local {
            record(ctx, col, &path);
        }
        if owned.contains(&path) {
            continue;
        }
        let text = ctx.sys.read_string(&path).unwrap_or_default();
        let (issues, lines) = serious_lines(ctx, &text);
        let severity = match max_severity(&issues) {
            Some(s) => s,
            None if !has_dpkg => continue,
            None if is_local => Severity::Medium,
            None => Severity::High,
        };
        col.push(simple(
            severity,
            "PERS-INITRAMFS-HOOK",
            format!("Script added to the boot image that no package installed: {path}"),
            &path,
            format!("{path}\n{}", clip(&lines.join("\n"), 600)),
            "Scripts here are built into the boot image (initramfs) and run as root before the system disk is even mounted. Disk unlocking and special hardware use this; so can a boot-level backdoor.".into(),
        ));
    }
}

/// Entries of a boot image (as `lsinitramfs` lists them) that no source on the system explains.
/// `exists` answers whether a path is present on the system; `applets` are busybox's commands.
pub fn unknown_in_initramfs(entries: &[&str], exists: &dyn Fn(&str) -> bool, applets: &HashSet<String>) -> Vec<String> {
    let entries: Vec<&str> = entries.iter().map(|e| e.trim().trim_start_matches("./")).collect();
    let folders: HashSet<&str> = entries.iter().filter_map(|e| e.rsplit_once('/').map(|(d, _)| d)).collect();
    let mut out = BTreeSet::new();
    for entry in &entries {
        if entry.is_empty() || *entry == "." || folders.contains(entry) {
            continue;
        }
        let plain = entry.strip_prefix("usr/").unwrap_or(entry);
        let name = crate::procinfo::basename(entry);
        if let Some(script) = plain.strip_prefix("scripts/") {
            let known = name == "ORDER" || ["/usr/share/initramfs-tools/scripts", "/etc/initramfs-tools/scripts"].iter().any(|d| exists(&format!("{d}/{script}")));
            if !known {
                out.insert(entry.to_string());
            }
        } else if (plain.starts_with("bin/") || plain.starts_with("sbin/")) && !applets.is_empty() {
            let known = applets.contains(name)
                || ["/usr/bin", "/usr/sbin", "/usr/lib/klibc/bin", "/usr/lib/initramfs-tools/bin"].iter().any(|d| exists(&format!("{d}/{name}")));
            if !known {
                out.insert(entry.to_string());
            }
        } else if plain.starts_with("tmp/") || plain.starts_with("home/") || plain.starts_with("root/") {
            out.insert(entry.to_string());
        }
    }
    out.into_iter().collect()
}

/// Was a package installed or changed within two days of this time?
fn package_activity_near(log: &str, time: chrono::NaiveDateTime) -> Option<bool> {
    let times: Vec<chrono::NaiveDateTime> = log.lines().filter_map(|l| chrono::NaiveDateTime::parse_from_str(l.get(..19)?, "%Y-%m-%d %H:%M:%S").ok()).collect();
    // an older image than the log says nothing
    if times.iter().min().map(|first| *first > time).unwrap_or(true) {
        return None;
    }
    Some(times.iter().any(|t| (*t - time).num_hours().abs() <= 48))
}

fn check_boot_images(ctx: &ScanCtx, col: &mut Collector) {
    let mut images: Vec<(std::time::SystemTime, String)> = ctx
        .sys
        .dir_names("/boot")
        .into_iter()
        .filter(|n| n.starts_with("initrd.img-"))
        .filter_map(|n| {
            let path = format!("/boot/{n}");
            Some((std::fs::metadata(ctx.sys.path(&path)).ok()?.modified().ok()?, path))
        })
        .collect();
    images.sort_by(|a, b| b.0.cmp(&a.0));
    let log: String = ["/var/log/dpkg.log.1", "/var/log/dpkg.log"].iter().filter_map(|p| ctx.sys.read_string(p).ok()).collect::<Vec<_>>().join("\n");
    for (modified, path) in &images {
        let time = chrono::DateTime::<chrono::Local>::from(*modified).naive_local();
        if package_activity_near(&log, time) == Some(false) {
            col.push(
                Finding::new(Severity::Low, MODULE, "PERS-INITRAMFS-REBUILT", format!("Boot image changed without any package activity: {path}"))
                    .evidence(format!("{path} was written {}; /var/log/dpkg.log shows nothing within two days of that", time.format("%Y-%m-%d %H:%M")))
                    .description("The boot image is normally rebuilt when a kernel or a driver package is installed. Running update-initramfs by hand also does this; if nobody did, find out what changed it.")
                    .verify(format!("ls -l --time-style=full-iso {}", shq(path)))
                    .verify("grep -E ' (install|upgrade|trigproc) ' /var/log/dpkg.log | tail -20"),
            );
        }
    }
    // listing the contents takes a few seconds per image: full scan only
    if !ctx.sys.is_live() || images.is_empty() {
        return;
    }
    if !ctx.deep_pid_scan || !ctx.privileged {
        col.note("The contents of the boot images are checked in a full scan as root");
        return;
    }
    let Some(lister) = crate::external_tools::find_binary("lsinitramfs") else {
        col.note("lsinitramfs is missing – the contents of the boot images were not checked");
        return;
    };
    let applets: HashSet<String> = ["/usr/lib/initramfs-tools/bin/busybox", "/usr/bin/busybox"]
        .iter()
        .find_map(|b| crate::external_tools::run_capture(std::path::Path::new(b), &["--list"], 20).ok().filter(|o| o.status == Some(0)))
        .map(|o| o.stdout.lines().map(|l| l.trim().to_string()).collect())
        .unwrap_or_default();
    for (_, path) in images.iter().take(2) {
        let listing = match crate::external_tools::run_capture(&lister, &[path], 120) {
            Ok(o) if o.status == Some(0) => o.stdout,
            _ => {
                col.note(format!("The contents of {path} could not be listed"));
                continue;
            }
        };
        let entries: Vec<&str> = listing.lines().collect();
        let unknown = unknown_in_initramfs(&entries, &|p| ctx.sys.exists(p), &applets);
        if !unknown.is_empty() {
            col.push(
                Finding::new(Severity::Medium, MODULE, "PERS-INITRAMFS-UNKNOWN", format!("Files in the boot image that the system does not explain: {path}"))
                    .evidence(clip(&unknown.join("\n"), 1500))
                    .description("These scripts or programs are inside the boot image but have no source on the system. A removed package can leave an old image like this; a file planted in the image runs before anything else. Rebuilding with update-initramfs -u removes foreign files, so keep a copy first.")
                    .verify(format!("lsinitramfs {}", shq(path)))
                    .verify(format!("unmkinitramfs {} /root/initramfs-copy   # unpack a copy to look at", shq(path))),
            );
        }
    }
}

pub fn check_hooks(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let has_dpkg = !ctx.sys.dir_names("/var/lib/dpkg/info").is_empty();
    check_generators(ctx, col, has_dpkg);
    check_dropins(ctx, col, homes, has_dpkg);
    check_binfmt(ctx, col, has_dpkg);
    check_git(ctx, col, homes);
    check_package_tools(ctx, col, homes, has_dpkg);
    check_initramfs_sources(ctx, col, has_dpkg);
    check_boot_images(ctx, col);
    // saved firewall rules belong in the baseline too
    for path in ["/etc/nftables.conf", "/etc/iptables/rules.v4", "/etc/iptables/rules.v6"] {
        record(ctx, col, path);
    }
}
