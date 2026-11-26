//! auth_logs: failed and suspicious logins in the system logs.
//!
//! Debian 13 keeps logins in the systemd journal; `/var/log/auth.log` exists when rsyslog is
//! installed. The live system is read through `journalctl` (falling back to the files); a
//! mounted disk or test root is read from the files.

use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, shq};
use std::collections::BTreeMap;

pub const MODULE: &str = "auth_logs";

/// Failed attempts from one address before a successful login that make it critical.
const SUCCESS_AFTER_FAILS: usize = 5;

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    SshFailed,
    SshInvalidUser,
    SshAccepted { method: String },
    SudoWrongPassword { attempts: usize },
    SudoDenied,
    SuFailed { target: String },
    /// Login on the machine itself: console, desktop login or screen unlock, polkit ...
    LocalFailed { service: String },
    /// A user or group was created (`user` holds the name).
    Created { what: &'static str },
    /// A user was added to a group.
    GroupAdded { group: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    pub time: String,
    pub kind: Kind,
    pub user: String,
    /// Remote address for SSH, empty for local events.
    pub source: String,
    pub line: String,
}

/// Split a syslog or `journalctl -o short-iso` line into (time, program, message). The message
/// is taken only from after the program tag, so text an attacker puts in a user name can't
/// pose as another log message.
fn split_line(line: &str) -> Option<(String, &str, &str)> {
    let mut rest = line;
    let mut next = || -> Option<&str> {
        rest = rest.trim_start();
        let end = rest.find(' ')?;
        let (tok, tail) = rest.split_at(end);
        rest = tail;
        Some(tok)
    };
    let first = next()?;
    let time = if first.starts_with(|c: char| c.is_ascii_digit()) {
        first.to_string()
    } else {
        let day = next()?;
        let clock = next()?;
        format!("{first} {day} {clock}")
    };
    let _host = next()?;
    let tag = next()?;
    let message = rest.trim_start();
    let program = tag.trim_end_matches(':').split('[').next()?;
    tag.ends_with(':').then_some((time, program, message))
}

/// "invalid user bob from 1.2.3.4 port 22 ssh2" → ("bob", "1.2.3.4")
fn user_and_source(rest: &str) -> Option<(String, String)> {
    let at = rest.rfind(" from ")?;
    let user = rest[..at].trim_start_matches("invalid user ").trim().to_string();
    let source = rest[at + 6..].split_whitespace().next()?.to_string();
    Some((user, source))
}

/// "key=value" from a PAM message; `user` does not match `ruser`.
fn pam_value(message: &str, key: &str) -> String {
    message
        .split_whitespace()
        .find_map(|t| t.strip_prefix(key).and_then(|t| t.strip_prefix('=')))
        .unwrap_or("")
        .to_string()
}

pub fn parse_line(line: &str) -> Option<Event> {
    let (time, program, message) = split_line(line)?;
    let event = |kind: Kind, user: String, source: String| Some(Event { time: time.clone(), kind, user, source, line: line.to_string() });

    if program.starts_with("sshd") {
        for method in ["password", "publickey", "keyboard-interactive/pam"] {
            if let Some(rest) = message.strip_prefix(&format!("Failed {method} for ")) {
                let (user, source) = user_and_source(rest)?;
                return event(Kind::SshFailed, user, source);
            }
        }
        if let Some(rest) = message.strip_prefix("Invalid user ") {
            let (user, source) = user_and_source(rest)?;
            return event(Kind::SshInvalidUser, user, source);
        }
        if let Some(rest) = message.strip_prefix("Accepted ") {
            let (method, rest) = rest.split_once(" for ")?;
            let (user, source) = user_and_source(rest)?;
            return event(Kind::SshAccepted { method: method.to_string() }, user, source);
        }
        return None;
    }
    if program == "sudo" {
        if let Some((user, detail)) = message.split_once(" : ") {
            let user = user.trim().to_string();
            if let Some(at) = detail.find(" incorrect password attempt") {
                let attempts = detail[..at].split_whitespace().last().and_then(|n| n.parse().ok()).unwrap_or(1);
                return event(Kind::SudoWrongPassword { attempts }, user, String::new());
            }
            if detail.starts_with("user NOT in sudoers") || detail.starts_with("command not allowed") {
                return event(Kind::SudoDenied, user, String::new());
            }
        }
        return None;
    }
    if program == "su" {
        if let Some(rest) = message.strip_prefix("FAILED SU (to ") {
            let (target, rest) = rest.split_once(") ")?;
            let user = rest.split_whitespace().next()?.to_string();
            return event(Kind::SuFailed { target: target.to_string() }, user, String::new());
        }
        return None;
    }
    if program == "useradd" {
        if let Some(rest) = message.strip_prefix("new user: name=") {
            let name = rest.split(',').next().unwrap_or("").to_string();
            return event(Kind::Created { what: "user" }, name, String::new());
        }
    }
    if program == "groupadd" {
        if let Some(rest) = message.strip_prefix("new group: name=") {
            let name = rest.split(',').next().unwrap_or("").to_string();
            return event(Kind::Created { what: "group" }, name, String::new());
        }
    }
    // usermod: "add 'bob' to group 'sudo'"; gpasswd: "user bob added by root to group sudo"
    if program == "usermod" {
        if let Some(rest) = message.strip_prefix("add '") {
            let (user, rest) = rest.split_once("' to group '")?;
            let group = rest.trim_end_matches('\'').to_string();
            return event(Kind::GroupAdded { group }, user.to_string(), String::new());
        }
    }
    if program == "gpasswd" {
        if let Some(rest) = message.strip_prefix("user ") {
            let (user, rest) = rest.split_once(" added by ")?;
            let group = rest.split(" to group ").nth(1)?.to_string();
            return event(Kind::GroupAdded { group }, user.to_string(), String::new());
        }
    }
    // Other logins (console, desktop, screen unlock, polkit) report through PAM.
    if let Some(rest) = message.strip_prefix("pam_unix(") {
        let (service, detail) = rest.split_once(':')?;
        if detail.contains("authentication failure") && !["sshd", "sudo", "sudo-i", "su", "su-l"].contains(&service) {
            let user = pam_value(detail, "user");
            let user = if user.is_empty() { pam_value(detail, "ruser") } else { user };
            return event(Kind::LocalFailed { service: service.to_string() }, user, pam_value(detail, "rhost"));
        }
    }
    None
}

/// Read the log lines: the journal on the live system, else the auth.log files.
fn read_lines(ctx: &ScanCtx, col: &mut Collector) -> Vec<String> {
    if ctx.sys.is_live() {
        if let Some(journalctl) = crate::external_tools::find_binary("journalctl") {
            let since = format!("--since=-{}days", ctx.cfg.login_days.max(1));
            let args = ["--no-pager", "-q", "-o", "short-iso", "-n", "300000", since.as_str(), "SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"];
            match crate::external_tools::run_capture(&journalctl, &args, 120) {
                Ok(o) if !o.stdout.trim().is_empty() => {
                    col.note(format!("auth_logs: read the journal for the last {} days", ctx.cfg.login_days.max(1)));
                    return o.stdout.lines().map(|l| l.to_string()).collect();
                }
                Ok(_) => {}
                Err(e) => col.note(format!("auth_logs: journalctl could not run: {e}")),
            }
        }
    }
    // Rotated file first, so the events stay in order of time.
    let mut lines = Vec::new();
    let mut used = Vec::new();
    for path in ["/var/log/auth.log.1", "/var/log/auth.log"] {
        match ctx.sys.read_string(path) {
            Ok(text) => {
                lines.extend(text.lines().map(|l| l.to_string()));
                used.push(path);
            }
            Err(e) if e.is_permission_denied() => col.note(format!("auth_logs: {path} could not be read (needs root)")),
            Err(_) => {}
        }
    }
    if used.is_empty() {
        col.note("auth_logs: no login log could be read (journal empty or unreadable and no /var/log/auth.log) – run as root");
    } else {
        col.note(format!("auth_logs: read {}", used.join(" and ")));
    }
    lines
}

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    if !ctx.privileged {
        col.note("auth_logs: without root only your own log messages may be visible");
    }
    let lines = read_lines(ctx, col);
    let events: Vec<Event> = lines.iter().filter_map(|l| parse_line(l)).collect();
    evaluate(&events, ctx.cfg.login_fail_threshold.max(1), col);
}

/// "12 attempts, first … last …" plus the latest log lines.
fn describe_events(events: &[&Event], attempts: usize) -> String {
    let first = events.first().map(|e| e.time.as_str()).unwrap_or("?");
    let last = events.last().map(|e| e.time.as_str()).unwrap_or("?");
    let mut users: Vec<&str> = events.iter().map(|e| e.user.as_str()).filter(|u| !u.is_empty()).collect();
    users.sort();
    users.dedup();
    let shown: Vec<&str> = users.iter().take(15).copied().collect();
    let more = if users.len() > 15 { format!(" (+{} more)", users.len() - 15) } else { String::new() };
    let latest: Vec<String> = events.iter().rev().take(3).rev().map(|e| clip(&e.line, 220)).collect();
    format!("{attempts} attempt(s) between {first} and {last}\nuser names: {}{more}\nlatest:\n{}", clip(&shown.join(", "), 300), latest.join("\n"))
}

fn level(count: usize, threshold: usize) -> Severity {
    if count >= threshold {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Turn the events into findings.
pub fn evaluate(events: &[Event], threshold: usize, col: &mut Collector) {
    let journal = |filter: &str| format!("sudo journalctl --since=-30days SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 | grep -F -- {}", shq(filter));

    // SSH, per source address, in order of time.
    let mut by_source: BTreeMap<&str, Vec<&Event>> = BTreeMap::new();
    for e in events.iter().filter(|e| matches!(e.kind, Kind::SshFailed | Kind::SshInvalidUser | Kind::SshAccepted { .. })) {
        by_source.entry(e.source.as_str()).or_default().push(e);
    }
    let mut few: Vec<(usize, &str, Vec<&Event>)> = Vec::new();
    let mut many: Vec<(usize, &str, Vec<&Event>)> = Vec::new();
    for (source, list) in &by_source {
        let (mut failed, mut invalid) = (0usize, 0usize);
        let mut success: Option<(&Event, usize)> = None;
        for e in list {
            match &e.kind {
                Kind::SshFailed => failed += 1,
                Kind::SshInvalidUser => invalid += 1,
                Kind::SshAccepted { method } => {
                    let before = failed.max(invalid);
                    if before >= SUCCESS_AFTER_FAILS && success.is_none() {
                        success = Some((e, before));
                    }
                    if e.user == "root" && method == "password" {
                        col.push(
                            Finding::new(Severity::High, MODULE, "AUTH-SSH-ROOT-PASSWORD", format!("root logged in over SSH with a password from {source}"))
                                .evidence(clip(&e.line, 300))
                                .description("Someone logged in as root with a password over the network. If that was not you, the password is known to someone else. Use SSH keys and keep PermitRootLogin at prohibit-password.")
                                .verify(journal(source))
                                .verify("sudo last -x | head -40"),
                        );
                    }
                }
                _ => {}
            }
        }
        if let Some((e, before)) = success {
            col.push(
                Finding::new(Severity::Critical, MODULE, "AUTH-SSH-SUCCESS-AFTER-FAIL", format!("SSH login succeeded after many failed attempts from {source}"))
                    .evidence(format!("{before} failed attempt(s) before this login by {}:\n{}", e.user, clip(&e.line, 300)))
                    .description("An address that kept guessing eventually got in. Unless this was you mistyping, treat the account as taken over: change the password, check authorized_keys, and look at what the session did.")
                    .verify(journal(source))
                    .verify("sudo last -x | head -40")
                    .verify(format!("sudo grep -rn . /root/.ssh/authorized_keys /home/{}/.ssh/authorized_keys", shq(&e.user))),
            );
        }
        let failures: Vec<&Event> = list.iter().copied().filter(|e| !matches!(e.kind, Kind::SshAccepted { .. })).collect();
        let attempts = failed.max(invalid);
        if attempts >= threshold {
            many.push((attempts, source, failures));
        } else if attempts > 0 {
            few.push((attempts, source, failures));
        }
    }
    many.sort_by(|a, b| b.0.cmp(&a.0));
    let hidden = many.len().saturating_sub(20);
    for (attempts, source, list) in many.iter().take(20) {
        col.push(
            Finding::new(Severity::Medium, MODULE, "AUTH-SSH-BRUTEFORCE", format!("Many failed SSH logins from {source}"))
                .evidence(describe_events(list, *attempts))
                .description("Somebody is guessing passwords against SSH. This is common for machines reachable from the internet and harmless as long as no guess succeeds. Protect yourself with key-only login (PasswordAuthentication no), fail2ban or a firewall.")
                .verify(journal(source))
                .verify("sshd -T | grep -Ei 'passwordauthentication|permitrootlogin|maxauthtries'"),
        );
    }
    if hidden > 0 {
        col.note(format!("auth_logs: {hidden} more addresses with many failed SSH logins are not listed"));
    }
    if !few.is_empty() {
        let lines: Vec<String> = few.iter().take(30).map(|(n, source, list)| format!("{source}: {n} attempt(s), last {} ({})", list.last().map(|e| e.time.as_str()).unwrap_or("?"), list.last().map(|e| e.user.as_str()).unwrap_or("?"))).collect();
        col.push(
            Finding::new(Severity::Low, MODULE, "AUTH-SSH-FAILED", "Failed SSH logins")
                .evidence(lines.join("\n"))
                .description("A few wrong passwords or user names over SSH – often a typing mistake or a passing scanner.")
                .verify("sudo journalctl -t sshd -t sshd-session --since=-30days | grep -E 'Failed|Invalid user'"),
        );
    }
    let mut unknown: BTreeMap<&str, usize> = BTreeMap::new();
    for e in events.iter().filter(|e| e.kind == Kind::SshInvalidUser) {
        *unknown.entry(e.user.as_str()).or_default() += 1;
    }
    if !unknown.is_empty() {
        let total: usize = unknown.values().sum();
        let mut names: Vec<(&&str, &usize)> = unknown.iter().collect();
        names.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let lines: Vec<String> = names.iter().take(30).map(|(u, n)| format!("{}: {n}", if u.is_empty() { "(empty)" } else { u })).collect();
        col.push(
            Finding::new(level(total, threshold), MODULE, "AUTH-SSH-INVALID-USER", "SSH logins with user names that do not exist")
                .evidence(format!("{total} attempt(s), {} different name(s):\n{}", unknown.len(), clip(&lines.join("\n"), 900)))
                .description("Attempts with made-up user names (admin, test, oracle …) are typical of automated scanners trying to break in.")
                .verify("sudo journalctl -t sshd -t sshd-session --since=-30days | grep 'Invalid user'"),
        );
    }

    // New accounts and group memberships.
    for e in events {
        match &e.kind {
            Kind::Created { what: "user" } => col.push(
                Finding::new(Severity::Low, MODULE, "AUTH-NEW-USER", format!("A user account was created: {}", e.user))
                    .evidence(clip(&e.line, 300))
                    .description("Packages create system accounts when they are installed. If you did not add this account, find out who did.")
                    .verify(format!("getent passwd {}", shq(&e.user)))
                    .verify("sudo journalctl -t useradd --since=-30days"),
            ),
            Kind::GroupAdded { group } if crate::modules::persistence::extra::PRIVILEGED_GROUPS.contains(&group.as_str()) => col.push(
                Finding::new(Severity::Medium, MODULE, "AUTH-GROUP-ADD", format!("{} was added to the powerful group {group}", e.user))
                    .evidence(clip(&e.line, 300))
                    .description("Members of this group have root or near-root power. Make sure this was intended.")
                    .verify(format!("id {}", shq(&e.user)))
                    .verify("sudo journalctl -t usermod -t gpasswd --since=-30days"),
            ),
            _ => {}
        }
    }

    // Local events, grouped per rule and user.
    let mut groups: BTreeMap<(&str, String), (usize, Vec<&Event>)> = BTreeMap::new();
    for e in events {
        let (rule, who, n) = match &e.kind {
            Kind::SudoWrongPassword { attempts } => ("AUTH-SUDO-FAILED", e.user.clone(), *attempts),
            Kind::SudoDenied => ("AUTH-SUDO-DENIED", e.user.clone(), 1),
            Kind::SuFailed { target } => ("AUTH-SU-FAILED", format!("{} → {target}", e.user), 1),
            Kind::LocalFailed { service } => ("AUTH-LOCAL-FAILED", format!("{} ({service})", if e.user.is_empty() { "unknown user" } else { &e.user }), 1),
            _ => continue,
        };
        let g = groups.entry((rule, who)).or_default();
        g.0 += n;
        g.1.push(e);
    }
    for ((rule, who), (count, list)) in groups {
        let (severity, title, text, check) = match rule {
            "AUTH-SUDO-FAILED" => (level(count, threshold), format!("Wrong sudo password: {who}"), "Wrong passwords for sudo. Usually typing mistakes; many of them can mean someone with access to the account is guessing.", "sudo journalctl -t sudo --since=-30days | grep 'incorrect password'"),
            "AUTH-SUDO-DENIED" => (Severity::Medium, format!("sudo refused: {who}"), "This account tried to run something as root without being allowed to. Make sure you know why.", "sudo journalctl -t sudo --since=-30days | grep -E 'NOT in sudoers|not allowed'"),
            "AUTH-SU-FAILED" => (level(count, threshold), format!("Failed su: {who}"), "A wrong password when switching user with su.", "sudo journalctl -t su --since=-30days"),
            _ => (level(count, threshold), format!("Failed logins on this computer: {who}"), "Wrong passwords at the console, desktop login, screen lock or a password dialog. Usually typing mistakes; many in a row, or at times you were away, deserve a look.", "sudo journalctl --since=-30days SYSLOG_FACILITY=10 | grep 'authentication failure'"),
        };
        col.push(Finding::new(severity, MODULE, rule, title).evidence(describe_events(&list, count)).description(text).verify(check));
    }
}
