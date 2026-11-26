//! What starts with a desktop: XDG autostart entries, login-session and sleep scripts, display
//! manager hooks and polkit rules.

use super::{check_perms, record, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_command, analyze_user_command, clip, max_severity, program_words, reasons, shq, CmdIssue};
use crate::modules::{Collector, ScanCtx};
use crate::pkgverify::owned_paths;
use std::collections::HashSet;
use walkdir::WalkDir;

/// Folders with scripts that the system runs at login, logout, sleep or network changes.
const SESSION_DIRS: [&str; 10] = [
    "/etc/X11/Xsession.d", "/etc/X11/xinit/xinitrc.d", "/etc/gdm3/Init", "/etc/gdm3/PostLogin", "/etc/gdm3/PreSession",
    "/etc/gdm3/PostSession", "/etc/sddm", "/etc/NetworkManager/dispatcher.d", "/etc/systemd/system-sleep", "/usr/lib/systemd/system-sleep",
];

/// The same in a home folder.
const HOME_SESSION: [&str; 5] = [".config/plasma-workspace/env", ".config/plasma-workspace/shutdown", ".config/autostart-scripts", ".xinitrc", ".xsession"];

const DM_KEYS: [&str; 9] = [
    "greeter-setup-script", "session-setup-script", "session-cleanup-script", "display-setup-script", "display-stopped-script",
    "DisplayCommand", "DisplayStopCommand", "SessionCommand", "EnterCommand",
];

const SYSTEM_PREFIXES: [&str; 6] = ["/usr/", "/bin/", "/sbin/", "/opt/", "/snap/", "/var/lib/flatpak/"];

/// The files at or below a path.
fn files_at(ctx: &ScanCtx, path: &str) -> Vec<String> {
    let mut out: Vec<String> = WalkDir::new(ctx.sys.path(path))
        .max_depth(3)
        .follow_links(false)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| !e.file_type().is_dir())
        .take(500)
        .map(|e| ctx.sys.display(e.path()))
        .collect();
    out.sort();
    out
}

/// Serious problems on any non-comment line of a script: (problems, lines).
fn script_issues(ctx: &ScanCtx, text: &str, in_home: bool) -> (Vec<CmdIssue>, Vec<String>) {
    let mut issues: Vec<CmdIssue> = Vec::new();
    let mut lines = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let found = if in_home { analyze_user_command(line, ctx.cfg) } else { analyze_command(line, ctx.cfg) };
        let found: Vec<CmdIssue> = found.into_iter().filter(|i| i.severity >= Severity::High).collect();
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

fn session_finding(severity: Severity, title: String, evidence: String, description: String, path: &str) -> Finding {
    Finding::new(severity, MODULE, "PERS-SESSION-SCRIPT", title)
        .evidence(evidence)
        .description(description)
        .verify(format!("cat {}", shq(path)))
        .verify(format!("dpkg -S {}", shq(path)))
}

fn check_session_scripts(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)], has_dpkg: bool) {
    let system: Vec<String> = SESSION_DIRS
        .iter()
        .chain(["/etc/X11/xinit/xinitrc", "/etc/X11/Xsession"].iter())
        .flat_map(|d| files_at(ctx, d))
        .collect();
    let owned = owned_paths(ctx.sys, &system);
    for path in system {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        check_perms(ctx, col, &path, "PERS-SESSION-PERMS", "Session script");
        let (issues, lines) = script_issues(ctx, &text, false);
        if let Some(severity) = max_severity(&issues) {
            // package scripts are checked against their package elsewhere; show only clear backdoors
            if !owned.contains(&path) || severity == Severity::Critical {
                col.push(session_finding(
                    severity,
                    format!("Suspicious command in a session script: {path}"),
                    format!("{path}\n{}", clip(&lines.join("\n"), 600)),
                    format!("The system runs this script by itself at login, sleep or network changes. Suspicious: {}.", reasons(&issues)),
                    &path,
                ));
            }
        } else if has_dpkg && !owned.contains(&path) {
            col.push(session_finding(
                Severity::Low,
                format!("Session script that no package installed: {path}"),
                path.clone(),
                "The system runs this script by itself, and it was not installed by a package. Check that you or an administrator added it.".into(),
                &path,
            ));
        }
    }
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

/// What a polkit rule does that is worth knowing: (severity, why). `None` for harmless rules.
pub fn judge_polkit_rule(text: &str) -> Option<(Severity, &'static str)> {
    // drop comments so an explanation does not count as code
    let mut code = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("/*") {
        code.push_str(&rest[..start]);
        rest = rest[start..].find("*/").map(|end| &rest[start + end + 2..]).unwrap_or("");
    }
    code.push_str(rest);
    let code: String = code.lines().map(|l| if l.trim_start().starts_with("//") { "" } else { l }).collect::<Vec<_>>().join("\n");
    if code.contains("polkit.spawn(") {
        return Some((Severity::High, "runs a program when someone asks for permission"));
    }
    if code.contains("polkit.Result.YES") || code.contains("return \"yes\"") {
        let limits_action = code.contains("action.id") || code.contains("action.lookup");
        let limits_who = code.contains("subject.");
        return Some(match (limits_action, limits_who) {
            (false, false) => (Severity::Critical, "lets everyone do everything without a password"),
            (false, true) => (Severity::High, "lets a user or group do every administrator action without a password"),
            _ => (Severity::Medium, "allows some administrator actions without a password"),
        });
    }
    code.contains("addAdminRule").then_some((Severity::Medium, "changes who counts as administrator"))
}

fn check_polkit(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)], has_dpkg: bool) {
    let files: Vec<String> = ["/etc/polkit-1", "/usr/local/share/polkit-1", "/run/polkit-1"].iter().flat_map(|d| files_at(ctx, d)).collect();
    let owned = owned_paths(ctx.sys, &files);
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        check_perms(ctx, col, &path, "PERS-POLKIT-PERMS", "polkit file");
        if owned.contains(&path) {
            continue;
        }
        let judged = if path.ends_with(".rules") {
            judge_polkit_rule(&text)
        } else if path.ends_with(".pkla") && text.lines().any(|l| l.trim().starts_with("Result") && l.trim().ends_with("=yes")) {
            Some((Severity::Medium, "allows actions without a password"))
        } else {
            None
        };
        let (severity, why) = match judged {
            Some(found) => found,
            None if has_dpkg && (path.ends_with(".rules") || path.ends_with(".policy")) => (Severity::Low, "is a local rule that no package installed"),
            None => continue,
        };
        col.push(
            Finding::new(severity, MODULE, "PERS-POLKIT", format!("polkit rule to check: {path}"))
                .evidence(format!("{path}: {why}\n{}", clip(text.trim(), 600)))
                .description(format!("polkit decides who may do administrator tasks from the desktop. This rule {why}. Attackers add such rules to get root back without a password."))
                .verify(format!("cat {}", shq(&path)))
                .verify(format!("dpkg -S {}", shq(&path))),
        );
    }
    for (_, _, home) in homes {
        for place in [".local/share/polkit-1", ".config/polkit-1"] {
            let found = files_at(ctx, &format!("{home}/{place}"));
            if found.is_empty() {
                continue;
            }
            for path in &found {
                record(ctx, col, path);
            }
            col.push(
                Finding::new(Severity::Low, MODULE, "PERS-POLKIT", format!("polkit files in a home folder: {home}/{place}"))
                    .evidence(clip(&found.join("\n"), 600))
                    .description("polkit does not read rules from home folders, so these have no effect there. Something put them there anyway; check what.")
                    .verify(format!("ls -laR {}", shq(&format!("{home}/{place}")))),
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

fn check_autostart(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)], has_dpkg: bool) {
    let mut dirs: Vec<(String, bool)> = vec![("/etc/xdg/autostart".into(), false)];
    for (_, _, home) in homes {
        dirs.push((format!("{home}/.config/autostart"), true));
    }
    let mut seen = HashSet::new();
    for (dir, in_home) in dirs {
        let files: Vec<String> = ctx.sys.dir_names(&dir).into_iter().filter(|n| n.ends_with(".desktop")).map(|n| format!("{dir}/{n}")).collect();
        let owned = if in_home { HashSet::new() } else { owned_paths(ctx.sys, &files) };
        for path in files {
            if !seen.insert(path.clone()) {
                continue;
            }
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            let (Some(exec), false) = desktop_entry(&text) else { continue };
            let issues = if in_home { analyze_user_command(&exec, ctx.cfg) } else { analyze_command(&exec, ctx.cfg) };
            let name = crate::procinfo::basename(&path).to_string();
            let evidence = format!("{path}\nExec={}", clip(&exec, 400));
            let finding = |severity: Severity, title: String, description: String| {
                Finding::new(severity, MODULE, "PERS-AUTOSTART", title).evidence(evidence.clone()).description(description).verify(format!("cat {}", shq(&path)))
            };
            match max_severity(&issues) {
                Some(severity) if severity >= Severity::Medium && (in_home || severity >= Severity::High) => col.push(finding(
                    severity,
                    format!("Suspicious autostart entry: {path}"),
                    format!("The program starts automatically when a user logs in to the desktop. Suspicious: {}.", reasons(&issues)),
                )),
                _ if in_home && starts_installed_program(ctx, &exec) => col.push(finding(
                    Severity::Low,
                    format!("Autostart entry in a home directory: {name}"),
                    "An installed program starts when the user logs in to the desktop. Usually normal; check that you know it.".into(),
                )),
                _ if in_home => col.push(finding(
                    Severity::Medium,
                    format!("Autostart runs a script or program of its own: {name}"),
                    "At every desktop login this runs something that is not an installed program (a file in a home folder, a command line, or a program that is not found). Check that you set it up.".into(),
                )),
                _ if has_dpkg && !owned.contains(&path) => col.push(finding(
                    Severity::Medium,
                    format!("Autostart entry for all users that no package installed: {name}"),
                    "This starts for every user who logs in to the desktop and did not come with a package. Check that an administrator added it.".into(),
                )),
                _ => {}
            }
        }
    }
}

pub fn check_desktop(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)]) {
    let has_dpkg = !ctx.sys.dir_names("/var/lib/dpkg/info").is_empty();
    check_autostart(ctx, col, homes, has_dpkg);
    check_session_scripts(ctx, col, homes, has_dpkg);
    check_display_manager(ctx, col);
    check_polkit(ctx, col, homes, has_dpkg);
}
