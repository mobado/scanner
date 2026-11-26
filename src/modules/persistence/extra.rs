//! More persistence places: udev rules, queued at jobs, added certificate authorities, TLS and
//! SSH host keys, and the accounts and privileged groups (for the baseline).

use super::{record, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_command, clip, max_severity, mode_string, reasons, shq, CmdIssue};
use crate::modules::{Collector, ScanCtx};
use crate::procinfo::Account;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::MetadataExt;

/// Groups that give (nearly) root power.
pub const PRIVILEGED_GROUPS: [&str; 10] = ["root", "sudo", "wheel", "adm", "shadow", "disk", "docker", "lxd", "libvirt", "kmem"];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountEntry {
    pub name: String,
    pub uid: u32,
    pub shell: String,
    /// Has a usable password (None when /etc/shadow could not be read).
    pub password: Option<bool>,
    /// Privileged groups the account belongs to.
    pub groups: Vec<String>,
}

pub fn is_login_shell(shell: &str) -> bool {
    let base = shell.rsplit('/').next().unwrap_or("");
    !matches!(base, "nologin" | "false" | "true" | "sync" | "halt" | "shutdown" | "")
}

pub fn collect_accounts(ctx: &ScanCtx, accounts: &[Account]) -> Vec<AccountEntry> {
    let shadow = ctx.sys.read_string("/etc/shadow").ok();
    let groups = ctx.sys.read_string("/etc/group").unwrap_or_default();
    let mut out: Vec<AccountEntry> = accounts
        .iter()
        .map(|a| {
            let password = shadow.as_ref().and_then(|s| {
                s.lines().find_map(|l| {
                    let mut f = l.split(':');
                    (f.next() == Some(a.name.as_str())).then(|| {
                        let p = f.next().unwrap_or("");
                        !(p.starts_with('!') || p.starts_with('*'))
                    })
                })
            });
            let member_of: Vec<String> = groups
                .lines()
                .filter_map(|l| {
                    let f: Vec<&str> = l.split(':').collect();
                    if f.len() < 4 || !PRIVILEGED_GROUPS.contains(&f[0]) {
                        return None;
                    }
                    let primary = f[2].parse::<u32>().ok() == Some(a.gid);
                    (primary || f[3].split(',').any(|m| m.trim() == a.name)).then(|| f[0].to_string())
                })
                .collect();
            AccountEntry { name: a.name.clone(), uid: a.uid, shell: a.shell.clone(), password, groups: member_of }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub fn check_udev(ctx: &ScanCtx, col: &mut Collector) {
    for dir in ["/etc/udev/rules.d", "/usr/local/lib/udev/rules.d", "/run/udev/rules.d"] {
        for name in ctx.sys.dir_names(dir) {
            if !name.ends_with(".rules") {
                continue;
            }
            let path = format!("{dir}/{name}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            for (i, line) in text.lines().enumerate() {
                let t = line.trim();
                if t.starts_with('#') {
                    continue;
                }
                for key in ["RUN+=\"", "RUN=\"", "PROGRAM=\"", "PROGRAM==\"", "IMPORT{program}=\""] {
                    let Some(at) = t.find(key) else { continue };
                    let command = t[at + key.len()..].split('"').next().unwrap_or("");
                    let issues = analyze_command(command, ctx.cfg);
                    let program = command.split_whitespace().next().unwrap_or("");
                    let odd = program.starts_with('/') && !["/usr/", "/lib/", "/bin/", "/sbin/", "/etc/udev/"].iter().any(|d| program.starts_with(d));
                    let severity = match max_severity(&issues) {
                        Some(s) if s >= Severity::High => Some(s),
                        _ if odd => Some(Severity::Medium),
                        _ => None,
                    };
                    if let Some(sev) = severity {
                        col.push(
                            Finding::new(sev, MODULE, "PERS-UDEV", format!("udev rule runs a suspicious command: {name}"))
                                .evidence(format!("{path}:{}: {}", i + 1, clip(t, 300)))
                                .description(format!(
                                    "udev runs this as root when a device appears (also at every boot).{}",
                                    if issues.is_empty() { " The program is outside the system folders.".to_string() } else { format!(" Suspicious: {}.", reasons(&issues)) }
                                ))
                                .verify(format!("cat {}", shq(&path)))
                                .verify(format!("dpkg -S {}", shq(&path))),
                        );
                    }
                }
            }
        }
    }
}

pub fn check_at_jobs(ctx: &ScanCtx, col: &mut Collector) {
    for name in ctx.sys.dir_names("/var/spool/cron/atjobs") {
        if name.starts_with('.') {
            continue;
        }
        let path = format!("/var/spool/cron/atjobs/{name}");
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        let mut issues: Vec<CmdIssue> = Vec::new();
        let mut lines = Vec::new();
        for line in text.lines().map(|l| l.trim()) {
            // the job file starts with the saved environment
            if line.is_empty() || ["#", "export ", "cd ", "umask ", "}"].iter().any(|p| line.starts_with(p)) || line.contains("; export ") {
                continue;
            }
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
        if let Some(sev) = max_severity(&issues) {
            col.push(
                Finding::new(sev, MODULE, "PERS-AT-CMD", format!("Suspicious at job: {name}"))
                    .evidence(format!("{path}\n{}", clip(&lines.join("\n"), 600)))
                    .description(format!("A queued job will run this later. Suspicious: {}.", reasons(&issues)))
                    .verify("atq")
                    .verify(format!("cat {}", shq(&path))),
            );
        }
    }
}

pub fn check_keys_and_certificates(ctx: &ScanCtx, col: &mut Collector) {
    for name in ctx.sys.dir_names("/usr/local/share/ca-certificates") {
        let path = format!("/usr/local/share/ca-certificates/{name}");
        if std::fs::metadata(ctx.sys.path(&path)).map(|m| m.is_file()).unwrap_or(false) {
            record(ctx, col, &path);
            col.push(
                Finding::new(Severity::Low, MODULE, "PERS-CA-ADDED", format!("Added certificate authority: {name}"))
                    .evidence(path.clone())
                    .description("A locally added certificate authority is trusted for every HTTPS connection. Companies add their own; an attacker's would let them read encrypted traffic.")
                    .verify(format!("openssl x509 -in {} -noout -subject -issuer -dates", shq(&path))),
            );
        }
    }
    let mut keys: Vec<(String, u32)> = Vec::new();
    for name in ctx.sys.dir_names("/etc/ssh") {
        if name.starts_with("ssh_host_") {
            let path = format!("/etc/ssh/{name}");
            if name.ends_with(".pub") {
                record(ctx, col, &path);
            } else {
                keys.push((path, 0o077));
            }
        }
    }
    for name in ctx.sys.dir_names("/etc/ssl/private") {
        let path = format!("/etc/ssl/private/{name}");
        record(ctx, col, &path);
        // the ssl-cert group may read these
        keys.push((path, 0o007));
    }
    for (path, mask) in keys {
        let Ok(m) = std::fs::metadata(ctx.sys.path(&path)) else { continue };
        if m.is_file() && m.mode() & mask != 0 {
            col.push(
                Finding::new(Severity::High, MODULE, "PERS-KEY-PERMS", format!("Private key readable by others: {path}"))
                    .evidence(format!("{path} mode {} owner {}:{}", mode_string(m.mode()), m.uid(), m.gid()))
                    .description("Whoever can read a private key can impersonate this server.")
                    .verify(format!("stat {}", shq(&path))),
            );
        }
    }
}
