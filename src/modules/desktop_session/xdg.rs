//! Shared XDG standards: autostart entries, session scripts and display manager hooks.

use super::MODULE;
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_command, analyze_user_command, clip, max_severity, program_words, reasons, risky_home_place, shq, CmdIssue};
use crate::modules::persistence::record;
use crate::modules::persistence::rules::{check_system_scripts, files_at, script_issues, session_finding};
use crate::modules::{Collector, ScanCtx};
use crate::pkgverify::owned_paths;
use std::collections::{HashMap, HashSet};

/// Folders and files with scripts that run when a graphical session or login screen starts.
const SESSION_DIRS: [&str; 9] = [
    "/etc/X11/Xsession.d", "/etc/X11/xinit/xinitrc.d", "/etc/gdm3/Init", "/etc/gdm3/PostLogin", "/etc/gdm3/PreSession",
    "/etc/gdm3/PostSession", "/etc/sddm", "/etc/X11/xinit/xinitrc", "/etc/X11/Xsession",
];

/// The same in a home folder.
const HOME_SESSION: [&str; 8] = [
    ".config/plasma-workspace/env", ".config/plasma-workspace/shutdown", ".config/autostart-scripts", ".config/xfce4/xinitrc",
    ".xinitrc", ".xsession", ".xsessionrc", ".xprofile",
];

const DM_KEYS: [&str; 9] = [
    "greeter-setup-script", "session-setup-script", "session-cleanup-script", "display-setup-script", "display-stopped-script",
    "DisplayCommand", "DisplayStopCommand", "SessionCommand", "EnterCommand",
];

const SYSTEM_PREFIXES: [&str; 6] = ["/usr/", "/bin/", "/sbin/", "/opt/", "/snap/", "/var/lib/flatpak/"];

fn check_session_scripts(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)], has_dpkg: bool) {
    check_system_scripts(ctx, col, &SESSION_DIRS, has_dpkg);
    for (user, _, home) in homes {
        for place in HOME_SESSION {
            for path in files_at(ctx, &format!("{home}/{place}")) {
                let Ok(text) = ctx.sys.read_string(&path) else { continue };
                record(ctx, col, &path);
                let (issues, lines) = script_issues(ctx, &text, true);
                if let Some(severity) = max_severity(&issues) {
                    col.push(session_finding(
                        severity,
                        format!("Suspicious command in a session script: {path}"),
                        format!("{path}\n{}", clip(&lines.join("\n"), 600)),
                        format!("The script runs when {user}'s desktop session starts or ends. Suspicious: {}.", reasons(&issues)),
                        &path,
                    ));
                } else {
                    col.push(session_finding(
                        Severity::Low,
                        format!("Own script that runs with the desktop session: {path}"),
                        path.clone(),
                        format!("The script runs when {user}'s desktop session starts or ends. Check that you know it."),
                        &path,
                    ));
                }
            }
        }
    }
}

fn check_display_manager(ctx: &ScanCtx, col: &mut Collector) {
    let mut files: Vec<String> = ["/etc/lightdm/lightdm.conf", "/etc/sddm.conf", "/etc/gdm3/daemon.conf"].map(String::from).to_vec();
    for dir in ["/etc/lightdm/lightdm.conf.d", "/etc/sddm.conf.d"] {
        files.extend(ctx.sys.dir_names(dir).into_iter().map(|n| format!("{dir}/{n}")));
    }
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        for (i, line) in text.lines().enumerate() {
            let Some((key, value)) = line.trim().split_once('=') else { continue };
            let (key, value) = (key.trim(), value.trim());
            if !DM_KEYS.contains(&key) || value.is_empty() {
                continue;
            }
            let issues: Vec<CmdIssue> = analyze_command(value, ctx.cfg);
            let program = value.split_whitespace().next().unwrap_or("");
            let usual = ["/usr/", "/etc/X11/", "/etc/sddm/"].iter().any(|d| program.starts_with(d));
            let severity = match max_severity(&issues) {
                Some(s) if s >= Severity::High => s,
                _ if !usual => Severity::Medium,
                _ => continue,
            };
            col.push(
                Finding::new(severity, MODULE, "PERS-DM-SCRIPT", format!("The login screen runs a script: {path}"))
                    .evidence(format!("{path}:{}: {}", i + 1, clip(line.trim(), 300)))
                    .description("The display manager runs this command, often as root, every time the login screen starts or someone logs in. An unusual program here is a way to survive reboots.")
                    .verify(format!("cat {}", shq(&path)))
                    .verify(format!("ls -l {}", shq(program))),
            );
        }
    }
}

/// The first `Exec=` and whether the entry is switched off, from the `[Desktop Entry]` group.
fn desktop_entry(text: &str) -> (Option<String>, bool) {
    let (mut exec, mut hidden, mut inside) = (None, false, true);
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == "[Desktop Entry]";
        } else if inside {
            if let Some(v) = line.strip_prefix("Exec=") {
                exec.get_or_insert_with(|| v.to_string());
            } else if let Some(v) = line.strip_prefix("Hidden=") {
                hidden = v.trim().eq_ignore_ascii_case("true");
            }
        }
    }
    (exec, hidden)
}

/// Does the command start an installed program (and not a script of its own)?
fn starts_installed_program(ctx: &ScanCtx, exec: &str) -> bool {
    let words = program_words(exec);
    words.iter().all(|w| {
        if w.starts_with('/') {
            SYSTEM_PREFIXES.iter().any(|d| w.starts_with(d))
        } else {
            // a bare name is looked up in the system folders
            ["/usr/bin", "/usr/sbin", "/bin", "/usr/games"].iter().any(|d| ctx.sys.exists(format!("{d}/{w}")))
        }
    }) && !words.is_empty()
}

/// Folders whose entries start for every user.
const SYSTEM_AUTOSTART: [&str; 4] = ["/etc/xdg/autostart", "/usr/share/autostart", "/usr/share/gnome/autostart", "/usr/local/share/autostart"];

/// The file a program word stands for, following links; `None` when there is no such program.
fn program_file(ctx: &ScanCtx, word: &str) -> Option<String> {
    let mut path = if word.starts_with('/') {
        word.to_string()
    } else {
        ["/usr/local/bin", "/usr/bin", "/usr/sbin", "/bin", "/usr/games"].iter().map(|d| format!("{d}/{word}")).find(|p| ctx.sys.exists(p))?
    };
    for _ in 0..8 {
        let Some(target) = ctx.sys.read_link(&path) else { break };
        path = ctx.sys.resolve_link_target(&path, &target);
    }
    // "dir/../x" would not match a package's file list
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/').filter(|p| !p.is_empty() && *p != ".") {
        if part == ".." {
            parts.pop();
        } else {
            parts.push(part);
        }
    }
    let path = format!("/{}", parts.join("/"));
    ctx.sys.exists(&path).then_some(path)
}

struct Entry {
    path: String,
    exec: String,
    in_home: bool,
    /// Programs in system folders that the command starts.
    programs: Vec<String>,
}

fn check_autostart(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)], has_dpkg: bool) {
    let mut dirs: Vec<(String, bool)> = SYSTEM_AUTOSTART.iter().map(|d| (d.to_string(), false)).collect();
    for (_, _, home) in homes {
        dirs.push((format!("{home}/.config/autostart"), true));
    }
    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    // file name → program of the system-wide entry with that name
    let mut system_programs: HashMap<String, String> = HashMap::new();
    for (dir, in_home) in dirs {
        for name in ctx.sys.dir_names(&dir).into_iter().filter(|n| n.ends_with(".desktop")) {
            let path = format!("{dir}/{name}");
            if !seen.insert(path.clone()) {
                continue;
            }
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            let (Some(exec), hidden) = desktop_entry(&text) else { continue };
            let words = program_words(&exec);
            if !in_home {
                if let Some(first) = words.first() {
                    system_programs.insert(name.clone(), crate::procinfo::basename(first).to_string());
                }
            }
            if hidden {
                continue;
            }
            let programs = words
                .iter()
                .filter_map(|w| program_file(ctx, w))
                .filter(|p| ["/usr/", "/bin/", "/sbin/", "/opt/"].iter().any(|d| p.starts_with(d)))
                .collect();
            entries.push(Entry { path, exec, in_home, programs });
        }
    }
    let wanted: Vec<String> = entries.iter().flat_map(|e| std::iter::once(e.path.clone()).chain(e.programs.iter().cloned())).collect();
    let owned = owned_paths(ctx.sys, &wanted);
    for Entry { path, exec, in_home, programs } in entries {
        // what a package installed system-wide is checked against its package, not here
        let packaged = !in_home && owned.contains(&path);
        let issues = if in_home { analyze_user_command(&exec, ctx.cfg) } else { analyze_command(&exec, ctx.cfg) };
        let unknown: Vec<&String> = programs.iter().filter(|p| has_dpkg && !owned.contains(*p)).collect();
        let name = crate::procinfo::basename(&path).to_string();
        let first = program_words(&exec).first().map(|w| crate::procinfo::basename(w).to_string()).unwrap_or_default();
        let replaced = system_programs.get(&name).filter(|p| in_home && **p != first);
        let mut evidence = format!("{path}\nExec={}", clip(&exec, 400));
        let (severity, title, description) = match max_severity(&issues) {
            Some(severity) if severity >= Severity::Medium && (in_home || severity >= Severity::High) => (
                severity,
                format!("Suspicious autostart entry: {path}"),
                format!("The program starts automatically when a user logs in to the desktop. Suspicious: {}.", reasons(&issues)),
            ),
            _ if !packaged && !unknown.is_empty() => {
                evidence.push_str(&format!("\nno package installed: {}", unknown.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(", ")));
                (
                    Severity::Medium,
                    format!("Autostart runs a program that no package installed: {name}"),
                    "At every desktop login this runs a program from a system folder that apt did not put there. Software installed by hand looks like this; so does a planted program.".to_string(),
                )
            }
            _ if replaced.is_some() => {
                evidence.push_str(&format!("\nthe system-wide entry of the same name starts {}", replaced.map(String::as_str).unwrap_or("?")));
                (
                    Severity::Medium,
                    format!("Autostart entry replaces a system entry: {name}"),
                    "A file in the home folder takes the place of a system autostart entry with the same name and starts something else. Check that you changed it.".to_string(),
                )
            }
            _ if in_home && starts_installed_program(ctx, &exec) => (
                Severity::Low,
                format!("Autostart entry in a home directory: {name}"),
                "An installed program starts when the user logs in to the desktop. Usually normal; check that you know it.".to_string(),
            ),
            _ if in_home => (
                Severity::Medium,
                format!("Autostart runs a script or program of its own: {name}"),
                "At every desktop login this runs something that is not an installed program (a file in a home folder, a command line, or a program that is not found). Check that you set it up.".to_string(),
            ),
            _ if has_dpkg && !packaged => (
                Severity::Medium,
                format!("Autostart entry for all users that no package installed: {name}"),
                "This starts for every user who logs in to the desktop and did not come with a package. Check that an administrator added it.".to_string(),
            ),
            _ => continue,
        };
        col.push(Finding::new(severity, MODULE, "PERS-AUTOSTART", title).evidence(evidence).description(description).verify(format!("cat {}", shq(&path))));
    }
}

/// Menu entries in a user's own folder: they can replace an installed program's entry, so that
/// clicking the usual icon starts something else.
pub(super) fn check_user_launchers(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)]) {
    for (_, _, home) in homes {
        let dir = format!("{home}/.local/share/applications");
        for name in ctx.sys.dir_names(&dir).into_iter().filter(|n| n.ends_with(".desktop")).take(500) {
            let path = format!("{dir}/{name}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            let (Some(exec), hidden) = desktop_entry(&text) else { continue };
            if hidden {
                continue;
            }
            let issues: Vec<CmdIssue> = analyze_user_command(&exec, ctx.cfg).into_iter().filter(|i| i.severity >= Severity::High).collect();
            let words = program_words(&exec);
            let odd: Vec<&String> = words.iter().filter(|w| w.starts_with('/') && risky_home_place(w, ctx.cfg).is_some()).collect();
            let first = words.first().map(|w| crate::procinfo::basename(w).to_string()).unwrap_or_default();
            let usual = ctx
                .sys
                .read_string(format!("/usr/share/applications/{name}"))
                .ok()
                .and_then(|t| desktop_entry(&t).0)
                .and_then(|e| program_words(&e).first().map(|w| crate::procinfo::basename(w).to_string()));
            let mut evidence = format!("{path}\nExec={}", clip(&exec, 400));
            let (severity, title) = if let Some(severity) = max_severity(&issues) {
                evidence.push_str(&format!("\n{}", reasons(&issues)));
                (severity, format!("Menu entry with a suspicious command: {name}"))
            } else if !odd.is_empty() {
                (Severity::Medium, format!("Menu entry starts something from a hidden, cache or download folder: {name}"))
            } else if let Some(usual) = usual.filter(|u| *u != first && !starts_installed_program(ctx, &exec)) {
                evidence.push_str(&format!("\nthe installed entry of the same name starts {usual}"));
                (Severity::Medium, format!("Menu entry replaces an installed program: {name}"))
            } else {
                continue;
            };
            col.push(
                Finding::new(severity, MODULE, "PERS-LAUNCHER", title)
                    .evidence(evidence)
                    .description("This file in your own folder decides what starts when you click the entry or open a file with it. Programs you installed by hand add such entries; so can malware.")
                    .verify(format!("cat {}", shq(&path))),
            );
        }
    }
}

pub(super) fn check_xdg(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)]) {
    let has_dpkg = !ctx.sys.dir_names("/var/lib/dpkg/info").is_empty();
    check_autostart(ctx, col, homes, has_dpkg);
    check_session_scripts(ctx, col, homes, has_dpkg);
    check_display_manager(ctx, col);
}
