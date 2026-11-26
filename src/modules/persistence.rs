//! persistence: how an attacker can survive a reboot.
//!
//! * systemd units and timers (system and user)
//! * cron (/etc/crontab, /etc/cron.d, /etc/cron.*, /var/spool/cron/crontabs), at
//! * /etc/rc.local and /etc/ld.so.preload
//! * SSH: authorized_keys and sshd_config ([`ssh`])
//! * PAM, shell files, autostart, accounts and sudo ([`system`])
//!
//! Every file that controls persistence is hashed (SHA-256) into the inventory so that
//! a baseline can show what changed.

pub mod apt;
pub mod desktop;
pub mod extra;
pub mod history;
pub mod hooks;
pub mod ssh;
pub mod system;

use super::common::{analyze_command, analyze_user_command, clip,max_severity, mode_string, reasons, shq, writable_by_others, CmdIssue};
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::procinfo::{read_accounts, Account};
use crate::sys::sha256_file;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use walkdir::WalkDir;

pub use ssh::{parse_authorized_key, AuthKey};
pub use system::parse_pam_line;

pub const MODULE: &str = "persistence";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UnitSummary {
    pub name: String,
    pub path: String,
    /// "system" or "user"
    pub scope: String,
    pub enabled: bool,
    pub active: Option<bool>,
    /// Created locally (in /etc or a home directory) instead of by a package.
    pub local: bool,
    pub exec: Vec<String>,
}

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    let accounts = read_accounts(ctx.sys);
    if accounts.is_empty() {
        col.note("/etc/passwd could not be read – per-user checks will be incomplete");
    }
    let homes = home_dirs(ctx, &accounts);

    check_systemd(ctx, col, &homes);
    check_cron(ctx, col);
    check_rc_local(ctx, col);
    check_ld_preload(ctx, col);
    check_ld_conf(ctx, col);
    let akf = ssh::check_sshd_config(ctx, col);
    ssh::check_authorized_keys(ctx, col, &homes, &akf);
    system::check_pam(ctx, col);
    system::check_shell_files(ctx, col, &homes);
    system::check_accounts(ctx, col, &accounts);
    extra::check_udev(ctx, col);
    extra::check_at_jobs(ctx, col);
    extra::check_keys_and_certificates(ctx, col);
    desktop::check_desktop(ctx, col, &homes);
    apt::check_apt(ctx, col);
    hooks::check_hooks(ctx, col, &homes);
    history::check_histories(ctx, col, &homes);
    system::check_duplicate_ids(ctx, col, &accounts);
    col.inventory.accounts = extra::collect_accounts(ctx, &accounts);
}

/// (user name, uid, home directory) for root, normal users, directories under /home
/// and service accounts that have a .ssh directory. uid = u32::MAX when the account is not in passwd.
pub(crate) fn home_dirs(ctx: &ScanCtx, accounts: &[Account]) -> Vec<(String, u32, String)> {
    let mut out: Vec<(String, u32, String)> = Vec::new();
    let mut seen = HashSet::new();
    for a in accounts {
        if a.home.is_empty() || a.home == "/" || a.home == "/nonexistent" {
            continue;
        }
        let wanted = a.uid == 0 || a.uid >= 1000 || a.home.starts_with("/home/") || ctx.sys.exists(format!("{}/.ssh", a.home));
        if wanted && ctx.sys.exists(&a.home) && seen.insert(a.home.clone()) {
            out.push((a.name.clone(), a.uid, a.home.clone()));
        }
    }
    if ctx.sys.exists("/root") && seen.insert("/root".into()) {
        out.push(("root".into(), 0, "/root".into()));
    }
    for name in ctx.sys.dir_names("/home") {
        let h = format!("/home/{name}");
        if seen.insert(h.clone()) {
            out.push((name, u32::MAX, h));
        }
    }
    out
}

/// Put the file's SHA-256 into the inventory (for the baseline).
pub(crate) fn record(ctx: &ScanCtx, col: &mut Collector, abs: &str) {
    let real = ctx.sys.path(abs);
    if let Ok(m) = std::fs::metadata(&real) {
        if m.is_file() {
            if let Some(h) = sha256_file(&real, 64 * 1024 * 1024) {
                col.inventory.persistence_files.insert(abs.to_string(), h);
            }
        }
    }
}

pub(crate) fn check_perms(ctx: &ScanCtx, col: &mut Collector, abs: &str, rule: &str, what: &str) {
    if let Ok(m) = std::fs::symlink_metadata(ctx.sys.path(abs)) {
        if m.file_type().is_symlink() {
            return;
        }
        if writable_by_others(&m) {
            col.push(
                Finding::new(Severity::High, MODULE, rule, format!("{what} can be changed by others than the owner: {abs}"))
                    .evidence(format!("{abs} mode {} owner {}:{}", mode_string(m.mode()), m.uid(), m.gid()))
                    .description("The file controls what runs automatically. If the group or everyone can write to it, anyone can add their own commands.")
                    .verify(format!("stat {}", shq(abs))),
            );
        }
    }
}

pub(crate) fn issue_finding(rule: &str, title: String, issues: &[CmdIssue], evidence: String, base_desc: &str) -> Option<Finding> {
    let sev = max_severity(issues)?;
    Some(
        Finding::new(sev, MODULE, rule, title)
            .evidence(evidence)
            .description(format!("{base_desc} Suspicious: {}.", reasons(issues))),
    )
}

fn merge_issues(into: &mut Vec<CmdIssue>, found: Vec<CmdIssue>) {
    for i in found {
        if !into.contains(&i) {
            into.push(i);
        }
    }
}

// ---------------------------------------------------------------- systemd

/// Parse a unit file into (section, key, value). Handles line continuation with '\'.
pub fn parse_unit(text: &str) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut section = String::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let line = raw.trim_end();
        if pending.is_empty() {
            let t = line.trim_start();
            if t.is_empty() || t.starts_with('#') || t.starts_with(';') {
                continue;
            }
            if t.starts_with('[') && t.ends_with(']') {
                section = t[1..t.len() - 1].to_string();
                continue;
            }
        }
        if let Some(stripped) = line.strip_suffix('\\') {
            pending.push_str(stripped);
            pending.push(' ');
            continue;
        }
        pending.push_str(line);
        let full = std::mem::take(&mut pending);
        if let Some((k, v)) = full.split_once('=') {
            out.push((section.clone(), k.trim().to_string(), v.trim().to_string()));
        }
    }
    out
}

pub const EXEC_KEYS: [&str; 7] = ["ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload", "ExecCondition"];

fn is_unit_name(n: &str) -> bool {
    [".service", ".timer", ".socket", ".path"].iter().any(|e| n.ends_with(e))
}

const STANDARD_UNIT_DIRS: [&str; 8] = [
    "/etc/systemd/", "/usr/lib/systemd/", "/lib/systemd/", "/run/systemd/", "/usr/local/lib/systemd/", "/dev/null", "/usr/share/", "/var/lib/systemd/",
];

fn active_units(ctx: &ScanCtx, col: &mut Collector) -> Option<HashSet<String>> {
    if !ctx.sys.is_live() {
        return None;
    }
    let bin = crate::external_tools::find_binary("systemctl")?;
    let args = ["list-units", "--all", "--type=service,timer,socket,path", "--state=active", "--no-legend", "--plain", "--no-pager"];
    match crate::external_tools::run_capture(&bin, &args, 30) {
        Ok(o) => Some(o.stdout.lines().filter_map(|l| l.split_whitespace().next()).map(|s| s.to_string()).collect()),
        Err(e) => {
            col.note(format!("systemctl could not run: {e}"));
            None
        }
    }
}

struct UnitRef {
    abs: String,
    name: String,
    scope: &'static str,
    local: bool,
}

fn check_systemd(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)]) {
    let active = active_units(ctx, col);
    let mut dirs: Vec<(String, &'static str, bool)> = vec![
        ("/etc/systemd/system".into(), "system", true),
        ("/run/systemd/system".into(), "system", true),
        ("/usr/local/lib/systemd/system".into(), "system", true),
        ("/usr/lib/systemd/system".into(), "system", false),
        ("/lib/systemd/system".into(), "system", false),
        ("/etc/systemd/user".into(), "user", true),
        ("/usr/lib/systemd/user".into(), "user", false),
    ];
    for (_, _, home) in homes {
        dirs.push((format!("{home}/.config/systemd/user"), "user", true));
        dirs.push((format!("{home}/.local/share/systemd/user"), "user", true));
    }

    // Step 1: find unit files and enabled units (symlinks in *.wants/*.requires)
    let mut enabled: HashSet<String> = HashSet::new();
    let mut seen_real = HashSet::new();
    let mut units: Vec<UnitRef> = Vec::new();
    for (dir, scope, local) in &dirs {
        let real = ctx.sys.path(dir);
        let canon = std::fs::canonicalize(&real).unwrap_or_else(|_| real.clone());
        if !seen_real.insert(canon) {
            continue;
        }
        for e in WalkDir::new(&real).max_depth(2).follow_links(false).into_iter().filter_map(|e| e.ok()) {
            let name = e.file_name().to_string_lossy().into_owned();
            if !is_unit_name(&name) {
                continue;
            }
            let abs = ctx.sys.display(e.path());
            let parent = e
                .path()
                .parent()
                .and_then(|p| p.file_name())
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            let in_wants = e.depth() == 2 && (parent.ends_with(".wants") || parent.ends_with(".requires") || parent.ends_with(".upholds"));
            if in_wants {
                enabled.insert(name.clone());
                if e.path_is_symlink() {
                    if let Some(t) = ctx.sys.read_link(&abs) {
                        let target = ctx.sys.resolve_link_target(&abs, &t);
                        let ok_place = STANDARD_UNIT_DIRS.iter().any(|d| target.starts_with(d))
                            || homes.iter().any(|(_, _, h)| target.starts_with(&format!("{h}/.config/systemd")) || target.starts_with(&format!("{h}/.local/share/systemd")));
                        if !ok_place {
                            col.push(
                                Finding::new(Severity::High, MODULE, "PERS-SYSTEMD-LINK", format!("Enabled unit points to an unusual location: {name}"))
                                    .evidence(format!("{abs} -> {t}"))
                                    .description("The unit is enabled through a symlink pointing outside systemd's normal directories. That way a unit file can be hidden in e.g. /tmp or /opt.")
                                    .verify(format!("ls -l {}", shq(&abs)))
                                    .verify(format!("systemctl cat {}", shq(&name))),
                            );
                            units.push(UnitRef { abs: target, name: name.clone(), scope, local: true });
                        }
                    }
                }
                continue;
            }
            if e.depth() == 1 {
                units.push(UnitRef { abs, name, scope, local: *local });
            }
        }
    }

    // Step 2: read and assess every unit file
    let mut summaries = Vec::new();
    for u in units {
        let is_link = std::fs::symlink_metadata(ctx.sys.path(&u.abs)).map(|m| m.file_type().is_symlink()).unwrap_or(false);
        let mut read_from = u.abs.clone();
        if is_link {
            if let Some(t) = ctx.sys.read_link(&u.abs) {
                let target = ctx.sys.resolve_link_target(&u.abs, &t);
                if target == "/dev/null" {
                    continue; // masked unit
                }
                read_from = target;
            }
        }
        let Ok(text) = ctx.sys.read_string(&read_from) else { continue };
        let entries = parse_unit(&text);
        let exec: Vec<String> = entries.iter().filter(|(_, k, _)| EXEC_KEYS.contains(&k.as_str())).map(|(_, k, v)| format!("{k}={v}")).collect();
        let envs: Vec<String> = entries.iter().filter(|(_, k, _)| k == "Environment" || k == "EnvironmentFile").map(|(_, k, v)| format!("{k}={v}")).collect();
        let timer_info: Vec<String> = entries.iter().filter(|(s, _, _)| s == "Timer").map(|(_, k, v)| format!("{k}={v}")).collect();
        let is_enabled = enabled.contains(&u.name);
        let is_active = active.as_ref().map(|a| a.contains(&u.name));
        let real_local = u.local && !is_link;

        if real_local {
            record(ctx, col, &u.abs);
            check_perms(ctx, col, &u.abs, "PERS-SYSTEMD-PERMS", "systemd unit");
        }

        let mut issues = Vec::new();
        // a user's own services naturally point into the home folder
        let own = u.scope == "user" && (u.abs.starts_with("/home/") || u.abs.starts_with("/root/"));
        for line in exec.iter().chain(envs.iter()) {
            let cmd = line.split_once('=').map(|(_, v)| v.trim_start_matches(['-', '@', ':', '+', '!', '|'])).unwrap_or(line);
            merge_issues(&mut issues, if own { analyze_user_command(cmd, ctx.cfg) } else { analyze_command(cmd, ctx.cfg) });
        }
        if !u.local {
            // Units from packages (/usr/lib/systemd) – changes are caught by debsums; only alert on clear backdoor patterns
            issues.retain(|i| i.severity == Severity::Critical);
        }
        let state = format!(
            "{}{}",
            if is_enabled { "enabled" } else { "not enabled" },
            match is_active {
                Some(true) => ", active",
                Some(false) => ", inactive",
                None => "",
            }
        );
        let body: Vec<String> = exec.iter().chain(envs.iter()).chain(timer_info.iter()).cloned().collect();
        let evidence = format!(
            "{}{} ({}, {state})\n{}",
            u.abs,
            if read_from != u.abs { format!(" -> {read_from}") } else { String::new() },
            u.scope,
            clip(&body.join("\n"), 800)
        );
        let kind = if u.name.ends_with(".timer") { "timer" } else { "unit" };

        if let Some(mut f) = issue_finding(
            "PERS-SYSTEMD-EXEC",
            format!("Suspicious command in systemd {kind}: {}", u.name),
            &issues,
            evidence.clone(),
            "The unit starts something that looks like a backdoor or a downloaded script.",
        ) {
            if is_enabled && f.severity == Severity::High {
                f.severity = Severity::Critical;
            }
            col.push(
                f.verify(format!("systemctl cat {}", shq(&u.name)))
                    .verify(format!("systemctl status {}", shq(&u.name)))
                    .verify(format!("dpkg -S {}", shq(&read_from))),
            );
        } else if real_local && u.scope == "system" && !ctx.cfg.allowed_systemd_units.contains(&u.name) {
            let sev = if is_enabled && kind == "timer" { Severity::Medium } else { Severity::Low };
            col.push(
                Finding::new(sev, MODULE, "PERS-SYSTEMD-LOCAL", format!("Locally created systemd {kind}: {}", u.name))
                    .evidence(evidence.clone())
                    .description("The unit file is in /etc/systemd/system (or /usr/local) and does not come from a package. Check that it is intended and otherwise add it to allowed_systemd_units.")
                    .verify(format!("systemctl cat {}", shq(&u.name)))
                    .verify(format!("dpkg -S {}", shq(&u.abs)))
                    .verify("systemctl list-timers --all"),
            );
        } else if real_local && u.scope == "user" && !u.abs.starts_with("/etc/") && !ctx.cfg.allowed_systemd_units.contains(&u.name) {
            col.push(
                Finding::new(if is_enabled { Severity::Medium } else { Severity::Low }, MODULE, "PERS-SYSTEMD-USER", format!("systemd user unit in a home directory: {}", u.name))
                    .evidence(evidence.clone())
                    .description("User units start when the user logs in (or at boot with lingering) and need no root privileges – a common way to survive reboots.")
                    .verify(format!("cat {}", shq(&u.abs)))
                    .verify("loginctl list-users; ls /var/lib/systemd/linger"),
            );
        }

        if u.local {
            summaries.push(UnitSummary {
                name: u.name,
                path: u.abs,
                scope: u.scope.to_string(),
                enabled: is_enabled,
                active: is_active,
                local: real_local,
                exec,
            });
        }
    }
    summaries.sort_by(|a, b| a.name.cmp(&b.name));
    col.inventory.units = summaries;
}

// ---------------------------------------------------------------- cron

/// Split a cron line into (schedule, user, command). `None` for comments and variables.
pub fn parse_cron_line(line: &str, has_user: bool) -> Option<(String, Option<String>, String)> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let first = t.split_whitespace().next()?;
    if first.contains('=') && !first.starts_with('@') {
        return None; // MAILTO=root, SHELL=/bin/sh
    }
    let n_sched = if first.starts_with('@') { 1 } else { 5 };
    let n = n_sched + usize::from(has_user);
    let mut rest = t;
    let mut fields = Vec::new();
    for _ in 0..n {
        rest = rest.trim_start();
        let end = rest.find(char::is_whitespace)?;
        fields.push(&rest[..end]);
        rest = &rest[end..];
    }
    let cmd = rest.trim().to_string();
    if cmd.is_empty() {
        return None;
    }
    let sched = fields[..n_sched].join(" ");
    let user = has_user.then(|| fields[n_sched].to_string());
    Some((sched, user, cmd))
}

fn check_cron(ctx: &ScanCtx, col: &mut Collector) {
    // (path, has user field, system file)
    let mut files: Vec<(String, bool, bool)> = vec![("/etc/crontab".into(), true, true)];
    for n in ctx.sys.dir_names("/etc/cron.d") {
        files.push((format!("/etc/cron.d/{n}"), true, true));
    }
    let spool = ctx.sys.dir_names("/var/spool/cron/crontabs");
    if spool.is_empty() && ctx.sys.exists("/var/spool/cron/crontabs") && !ctx.privileged {
        col.note("/var/spool/cron/crontabs could not be read (needs root)");
    }
    for n in spool {
        files.push((format!("/var/spool/cron/crontabs/{n}"), false, false));
    }

    for (path, has_user, system) in files {
        let text = match ctx.sys.read_string(&path) {
            Ok(t) => t,
            Err(e) => {
                if !e.is_not_found() {
                    col.note(e.to_string());
                }
                continue;
            }
        };
        record(ctx, col, &path);
        check_perms(ctx, col, &path, "PERS-CRON-PERMS", "Cron file");
        let fname = path.rsplit('/').next().unwrap_or("").to_string();
        let allowed = ctx.cfg.allowed_cron_files.iter().any(|a| (system && *a == fname) || (!system && *a == format!("crontabs/{fname}")));
        let mut entries = Vec::new();
        for line in text.lines() {
            let Some((sched, user, cmd)) = parse_cron_line(line, has_user) else { continue };
            entries.push(line.trim().to_string());
            let issues = if system { analyze_command(&cmd, ctx.cfg) } else { analyze_user_command(&cmd, ctx.cfg) };
            let who =user.clone().unwrap_or_else(|| fname.clone());
            if let Some(f) = issue_finding(
                "PERS-CRON-CMD",
                format!("Suspicious cron job in {path}"),
                &issues,
                format!("{path}: {}\n(runs as {who}, schedule {sched})", line.trim()),
                "The cron job looks like it starts a backdoor or a downloaded script.",
            ) {
                col.push(f.verify(format!("cat {}", shq(&path))).verify(format!("crontab -l -u {}", shq(&who))));
            } else if sched == "@reboot" && !allowed {
                col.push(
                    Finding::new(Severity::Medium, MODULE, "PERS-CRON-REBOOT", format!("Cron job that runs at every boot ({path})"))
                        .evidence(format!("{path}: {}", line.trim()))
                        .description("@reboot jobs start automatically at every reboot and are an easy way to keep a foothold.")
                        .verify(format!("cat {}", shq(&path))),
                );
            }
        }
        if !system && !entries.is_empty() && !allowed {
            col.push(
                Finding::new(Severity::Medium, MODULE, "PERS-CRON-USER", format!("User crontab for {fname}"))
                    .evidence(format!("{path}\n{}", clip(&entries.join("\n"), 800)))
                    .description("The user has their own scheduled jobs. Check that they are known and otherwise add \"crontabs/<user>\" to allowed_cron_files.")
                    .verify(format!("crontab -l -u {}", shq(&fname))),
            );
        } else if system && path != "/etc/crontab" && !allowed {
            col.push(
                Finding::new(Severity::Low, MODULE, "PERS-CRON-UNKNOWN", format!("Unknown file in /etc/cron.d: {fname}"))
                    .evidence(format!("{path}\n{}", clip(&entries.join("\n"), 800)))
                    .description("The file is not among the known Debian default files. Check which package it belongs to.")
                    .verify(format!("dpkg -S {}", shq(&path)))
                    .verify(format!("cat {}", shq(&path))),
            );
        }
    }

    for period in ["hourly", "daily", "weekly", "monthly", "yearly"] {
        let dir = format!("/etc/cron.{period}");
        for name in ctx.sys.dir_names(&dir) {
            let path = format!("{dir}/{name}");
            record(ctx, col, &path);
            check_perms(ctx, col, &path, "PERS-CRON-PERMS", "Cron script");
            let text = ctx.sys.read_string(&path).unwrap_or_default();
            let mut issues: Vec<CmdIssue> = Vec::new();
            let mut lines = Vec::new();
            for line in text.lines().filter(|l| !l.trim_start().starts_with('#')) {
                let found = analyze_command(line, ctx.cfg);
                if !found.is_empty() {
                    lines.push(line.trim().to_string());
                }
                merge_issues(&mut issues, found);
            }
            // Debian's own scripts sometimes download with curl/wget – require at least High for known files
            let known = ctx.cfg.allowed_cron_files.contains(&name);
            if known {
                issues.retain(|i| i.severity >= Severity::High);
            }
            if let Some(f) = issue_finding("PERS-CRON-CMD", format!("Suspicious content in cron script: {path}"), &issues, format!("{path}\n{}", clip(&lines.join("\n"), 800)), "The script runs automatically from cron/anacron.") {
                col.push(f.verify(format!("cat {}", shq(&path))).verify(format!("dpkg -S {}", shq(&path))));
            } else if !known {
                col.push(
                    Finding::new(Severity::Low, MODULE, "PERS-CRON-UNKNOWN", format!("Unknown cron script: {path}"))
                        .evidence(path.clone())
                        .description("The script runs regularly but is not among the known Debian default scripts.")
                        .verify(format!("dpkg -S {}", shq(&path)))
                        .verify(format!("cat {}", shq(&path))),
                );
            }
        }
    }

    let at_jobs = ctx.sys.dir_names("/var/spool/cron/atjobs").into_iter().filter(|n| !n.starts_with('.')).count();
    if at_jobs > 0 {
        col.push(
            Finding::new(Severity::Medium, MODULE, "PERS-AT-JOBS", format!("{at_jobs} pending at job(s)"))
                .evidence("/var/spool/cron/atjobs")
                .description("at jobs run once at a given time and can be used to restart a backdoor.")
                .verify("atq")
                .verify("at -c <jobbnummer>"),
        );
    }
}

// ---------------------------------------------------------------- rc.local / ld.so.preload

fn check_rc_local(ctx: &ScanCtx, col: &mut Collector) {
    let path = "/etc/rc.local";
    let Ok(text) = ctx.sys.read_string(path) else { return };
    record(ctx, col, path);
    let active: Vec<&str> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && *l != "exit 0")
        .collect();
    if active.is_empty() {
        return;
    }
    let mut issues: Vec<CmdIssue> = Vec::new();
    for l in &active {
        merge_issues(&mut issues, analyze_command(l, ctx.cfg));
    }
    let executable = std::fs::metadata(ctx.sys.path(path)).map(|m| m.mode() & 0o111 != 0).unwrap_or(false);
    let sev = max_severity(&issues).unwrap_or(Severity::Medium).max(Severity::Medium);
    col.push(
        Finding::new(sev, MODULE, "PERS-RC-LOCAL", "/etc/rc.local contains commands")
            .evidence(format!(
                "{path} ({})\n{}",
                if executable { "executable – started by systemd at boot" } else { "not executable" },
                clip(&active.join("\n"), 800)
            ))
            .description(if issues.is_empty() {
                "rc.local is rarely used in Debian 13. Commands here run as root at every boot if the file is executable.".to_string()
            } else {
                format!("rc.local runs as root at boot. Suspicious: {}.", reasons(&issues))
            })
            .verify(format!("cat {path}"))
            .verify("systemctl status rc-local.service"),
    );
}

/// /etc/ld.so.conf and /etc/ld.so.conf.d/*: library search paths. One that points to a
/// temporary or home directory lets an attacker's library be loaded by every program.
fn check_ld_conf(ctx: &ScanCtx, col: &mut Collector) {
    let mut files = vec!["/etc/ld.so.conf".to_string()];
    files.extend(ctx.sys.dir_names("/etc/ld.so.conf.d").into_iter().map(|n| format!("/etc/ld.so.conf.d/{n}")));
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        for (i, line) in text.lines().enumerate() {
            let dir = line.trim();
            if dir.is_empty() || dir.starts_with('#') || dir.starts_with("include") {
                continue;
            }
            let bad = ctx.cfg.is_temp_path(dir) || ["/home/", "/root/", "/var/www/"].iter().any(|p| dir.starts_with(p));
            if bad {
                col.push(
                    Finding::new(Severity::High, MODULE, "PERS-LDCONF", format!("Library search path in an unusual place: {dir}"))
                        .evidence(format!("{path}:{}: {dir}", i + 1))
                        .description("ld.so.conf lists folders where the system looks for shared libraries. A temporary or home folder here lets an attacker's library replace a real one for every program – a rootkit technique.")
                        .verify(format!("cat {}", shq(&path)))
                        .verify(format!("ls -la {}", shq(dir)))
                        .verify("ldconfig -p | grep -v ' /usr/lib\\| /lib'"),
                );
            }
        }
    }
}

fn check_ld_preload(ctx: &ScanCtx, col: &mut Collector) {
    let path = "/etc/ld.so.preload";
    let Ok(text) = ctx.sys.read_string(path) else { return };
    record(ctx, col, path);
    let libs: Vec<&str> = text.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    if libs.is_empty() {
        return;
    }
    col.push(
        Finding::new(Severity::Critical, MODULE, "PERS-LDPRELOAD", "/etc/ld.so.preload loads libraries into every program")
            .evidence(format!("{path}:\n{}", libs.join("\n")))
            .description("Libraries in /etc/ld.so.preload are loaded into every dynamically linked program. It is the most common method for user-mode rootkits to hide files, processes and connections.")
            .verify(format!("cat {path}"))
            .verify_all(libs.iter().map(|l| format!("ls -l {} && dpkg -S {}", shq(l), shq(l)))),
    );
}
