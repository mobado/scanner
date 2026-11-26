//! Machine-wide hooks that matter on servers too: network and sleep scripts, and polkit rules.
//! The script helpers are shared with the desktop_session module.

use super::{check_perms, record, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_command, analyze_user_command, clip, max_severity, reasons, shq, CmdIssue};
use crate::modules::{Collector, ScanCtx};
use crate::pkgverify::owned_paths;
use walkdir::WalkDir;

/// Folders with scripts that the system runs at network changes and at sleep.
const MACHINE_DIRS: [&str; 3] = ["/etc/NetworkManager/dispatcher.d", "/etc/systemd/system-sleep", "/usr/lib/systemd/system-sleep"];

/// The files at or below a path.
pub(crate) fn files_at(ctx: &ScanCtx, path: &str) -> Vec<String> {
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
pub(crate) fn script_issues(ctx: &ScanCtx, text: &str, in_home: bool) -> (Vec<CmdIssue>, Vec<String>) {
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

pub(crate) fn session_finding(severity: Severity, title: String, evidence: String, description: String, path: &str) -> Finding {
    Finding::new(severity, MODULE, "PERS-SESSION-SCRIPT", title)
        .evidence(evidence)
        .description(description)
        .verify(format!("cat {}", shq(path)))
        .verify(format!("dpkg -S {}", shq(path)))
}

/// Scripts in system folders that run by themselves: suspicious ones, and ones from no package.
pub(crate) fn check_system_scripts(ctx: &ScanCtx, col: &mut Collector, places: &[&str], has_dpkg: bool) {
    let system: Vec<String> = places.iter().flat_map(|d| files_at(ctx, d)).collect();
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

pub(crate) fn check_machine_rules(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)]) {
    let has_dpkg = !ctx.sys.dir_names("/var/lib/dpkg/info").is_empty();
    check_system_scripts(ctx, col, &MACHINE_DIRS, has_dpkg);
    check_polkit(ctx, col, homes, has_dpkg);
}
