//! PAM, shell files, desktop autostart, accounts and sudo.

use super::{check_perms, issue_finding, record, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_command, clip, max_severity, mode_string, reasons, shq, split_quoted, writable_by_others, CmdIssue};
use crate::modules::{Collector, ScanCtx};
use crate::procinfo::Account;
use std::collections::{BTreeSet, HashSet};
use std::os::unix::fs::MetadataExt;

// ---------------------------------------------------------------- PAM

/// (type, control, module, arguments) from a PAM line. Handles controls like `[success=1 default=ignore]`.
pub fn parse_pam_line(line: &str) -> Option<(String, String, String, Vec<String>)> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') || t.starts_with('@') {
        return None;
    }
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth = 0i32;
    for c in t.chars() {
        match c {
            '[' => {
                depth += 1;
                cur.push(c)
            }
            ']' => {
                depth -= 1;
                cur.push(c)
            }
            c if c.is_whitespace() && depth <= 0 => {
                if !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
            }
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    if tokens.len() < 3 {
        return None;
    }
    let ty = tokens[0].trim_start_matches('-').to_lowercase();
    Some((ty, tokens[1].clone(), tokens[2].clone(), tokens[3..].to_vec()))
}

pub const PAM_DIRS: [&str; 4] = [
    "/usr/lib/x86_64-linux-gnu/security",
    "/lib/x86_64-linux-gnu/security",
    "/usr/lib/security",
    "/lib/security",
];

pub fn check_pam(ctx: &ScanCtx, col: &mut Collector) {
    let mut files: Vec<String> = ctx.sys.dir_names("/etc/pam.d").into_iter().map(|n| format!("/etc/pam.d/{n}")).collect();
    files.push("/etc/pam.conf".into());
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        check_perms(ctx, col, &path, "PERS-PAM-PERMS", "PAM file");
        for (lineno, line) in text.lines().enumerate() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            let line_txt = if path == "/etc/pam.conf" {
                // pam.conf has the service name first
                line.trim().split_once(char::is_whitespace).map(|(_, r)| r).unwrap_or("")
            } else {
                line
            };
            let Some((ty, control, module, args)) = parse_pam_line(line_txt) else { continue };
            if control == "include" || control == "substack" {
                continue; // the module is the name of another PAM file here
            }
            let modname = crate::procinfo::basename(&module).trim_end_matches(".so").to_string();
            let ev = format!("{path}:{}: {}", lineno + 1, line.trim());
            let verify = vec![format!("cat {}", shq(&path)), "dpkg -V libpam-modules libpam-runtime".to_string()];
            let ctl = control.to_lowercase();
            let lets_through = ctl == "sufficient" || ctl.contains("success=done") || ctl.contains("default=done");
            if modname == "pam_permit" && (ty == "auth" || ty == "account") && lets_through {
                col.push(
                    Finding::new(Severity::Critical, MODULE, "PERS-PAM-PERMIT", format!("pam_permit.so lets logins through in {path}"))
                        .evidence(ev.clone())
                        .description("pam_permit always succeeds. As 'sufficient' in auth/account you can log in without the right password – a classic PAM backdoor. (Debian's default 'required pam_permit.so' after pam_deny is normal.)")
                        .verify_all(verify.clone()),
                );
            }
            if modname == "pam_exec" {
                let cmd = args.iter().filter(|a| !a.contains('=') || a.starts_with('/')).cloned().collect::<Vec<_>>().join(" ");
                let issues = analyze_command(&cmd, ctx.cfg);
                let sev = max_severity(&issues).unwrap_or(Severity::Medium).max(Severity::Medium);
                col.push(
                    Finding::new(sev, MODULE, "PERS-PAM-EXEC", format!("pam_exec runs a program in {path}"))
                        .evidence(ev.clone())
                        .description(format!(
                            "pam_exec runs an external program at login – sometimes used to steal passwords (expose_authtok).{}",
                            if issues.is_empty() { String::new() } else { format!(" Suspicious: {}.", reasons(&issues)) }
                        ))
                        .verify_all(verify.clone()),
                );
            }
            if module.starts_with('/') && !PAM_DIRS.iter().any(|d| module.starts_with(d)) {
                col.push(
                    Finding::new(Severity::High, MODULE, "PERS-PAM-PATH", format!("PAM module from an unusual path: {module}"))
                        .evidence(ev.clone())
                        .description("PAM modules are loaded into the login with root privileges. A module outside the normal directories is very suspicious.")
                        .verify_all(verify.clone())
                        .verify(format!("dpkg -S {}", shq(&module))),
                );
            } else if !ctx.cfg.allowed_pam_modules.contains(&modname) {
                col.push(
                    Finding::new(Severity::Medium, MODULE, "PERS-PAM-UNKNOWN", format!("Unknown PAM module {modname} in {path}"))
                        .evidence(ev.clone())
                        .description("The module is not in the list of known PAM modules. Check which package it comes from.")
                        .verify_all(verify.clone())
                        .verify(format!("dpkg -S {modname}.so")),
                );
            }
        }
    }
    // The module files themselves are hashed into the baseline so replaced modules are detected
    let mut seen = HashSet::new();
    for dir in PAM_DIRS {
        let Ok(canon) = std::fs::canonicalize(ctx.sys.path(dir)) else { continue };
        if !seen.insert(canon) {
            continue;
        }
        for name in ctx.sys.dir_names(dir) {
            if !name.ends_with(".so") {
                continue;
            }
            let p = format!("{dir}/{name}");
            record(ctx, col, &p);
            if let Ok(m) = std::fs::metadata(ctx.sys.path(&p)) {
                if writable_by_others(&m) || (ctx.sys.is_live() && m.uid() != 0) {
                    col.push(
                        Finding::new(Severity::Critical, MODULE, "PERS-PAM-PERMS", format!("PAM module can be changed by others than root: {p}"))
                            .evidence(format!("{p} mode {} owner {}:{}", mode_string(m.mode()), m.uid(), m.gid()))
                            .description("Whoever can overwrite a PAM module controls every login.")
                            .verify(format!("stat {}", shq(&p))),
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------- shell files and autostart

pub fn check_shell_files(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)]) {
    let mut files: Vec<String> = ["/etc/profile", "/etc/bash.bashrc", "/etc/environment", "/etc/zsh/zshrc", "/etc/zsh/zprofile", "/etc/zsh/zshenv"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    for n in ctx.sys.dir_names("/etc/profile.d") {
        files.push(format!("/etc/profile.d/{n}"));
    }
    for (_, _, home) in homes {
        for f in [".bashrc", ".profile", ".bash_profile", ".bash_login", ".bash_logout", ".zshrc", ".zprofile", ".zshenv", ".xprofile", ".xsessionrc"] {
            files.push(format!("{home}/{f}"));
        }
    }
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        let mut issues: Vec<CmdIssue> = Vec::new();
        let mut lines = Vec::new();
        for line in text.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let mut found: Vec<CmdIssue> = analyze_command(line, ctx.cfg).into_iter().filter(|i| i.severity >= Severity::High).collect();
            let words = split_quoted(line);
            if words.first().map(|w| w == "alias").unwrap_or(false) {
                let target = words.get(1).map(|s| s.as_str()).unwrap_or("");
                if ["sudo=", "su=", "ssh=", "passwd="].iter().any(|p| target.starts_with(p)) {
                    found.push(CmdIssue { severity: Severity::High, reason: format!("alias that replaces {}", target.split('=').next().unwrap_or("")) });
                }
            }
            if path == "/etc/environment" && line.contains("LD_PRELOAD") {
                found.push(CmdIssue { severity: Severity::Critical, reason: "LD_PRELOAD i /etc/environment".into() });
            }
            if !found.is_empty() {
                lines.push(line.to_string());
            }
            for i in found {
                if !issues.contains(&i) {
                    issues.push(i);
                }
            }
        }
        if let Some(f) = issue_finding("PERS-SHELLRC", format!("Suspicious content in {path}"), &issues, format!("{path}\n{}", clip(&lines.join("\n"), 800)), "The file runs every time a shell or a login starts.") {
            col.push(f.verify(format!("cat {}", shq(&path))).verify(format!("dpkg -S {} 2>/dev/null || echo 'not from any package'", shq(&path))));
        }
    }

    // XDG-autostart (skrivbord)
    let mut dirs: Vec<(String, bool)> = vec![("/etc/xdg/autostart".into(), false)];
    for (_, _, home) in homes {
        dirs.push((format!("{home}/.config/autostart"), true));
    }
    for (dir, user_dir) in dirs {
        for name in ctx.sys.dir_names(&dir) {
            if !name.ends_with(".desktop") {
                continue;
            }
            let path = format!("{dir}/{name}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            let exec: Vec<String> = text.lines().filter_map(|l| l.trim().strip_prefix("Exec=")).map(|s| s.to_string()).collect();
            let issues: Vec<CmdIssue> = exec.iter().flat_map(|e| analyze_command(e, ctx.cfg)).collect();
            if let Some(f) = issue_finding("PERS-AUTOSTART", format!("Suspicious autostart entry: {path}"), &issues, format!("{path}\nExec={}", exec.join(" | ")), "The program starts automatically when a user logs in to the desktop.") {
                col.push(f.verify(format!("cat {}", shq(&path))));
            } else if user_dir {
                col.push(
                    Finding::new(Severity::Low, MODULE, "PERS-AUTOSTART", format!("Autostart entry in a home directory: {name}"))
                        .evidence(format!("{path}\nExec={}", exec.join(" | ")))
                        .description("The program starts when the user logs in to the desktop. Usually normal programs, but check that it is known.")
                        .verify(format!("cat {}", shq(&path))),
                );
            }
        }
    }
}

// ---------------------------------------------------------------- accounts and sudo

pub fn check_accounts(ctx: &ScanCtx, col: &mut Collector, accounts: &[Account]) {
    for p in ["/etc/passwd", "/etc/group", "/etc/sudoers"] {
        record(ctx, col, p);
    }
    let login_shells = ["/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh", "/bin/zsh", "/usr/bin/zsh", "/bin/dash", "/usr/bin/dash", "/bin/ksh", "/usr/bin/fish"];
    for a in accounts {
        if a.uid == 0 && a.name != "root" {
            col.push(
                Finding::new(Severity::Critical, MODULE, "PERS-UID0", format!("Extra account with UID 0: {}", a.name))
                    .evidence(format!("/etc/passwd: {}:x:{}:{}:…:{}:{}", a.name, a.uid, a.gid, a.home, a.shell))
                    .description("Every account with UID 0 is root. An extra root account is a common backdoor.")
                    .verify("awk -F: '$3 == 0' /etc/passwd"),
            );
        } else if a.uid > 0 && a.uid < 1000 && login_shells.contains(&a.shell.as_str()) && a.name != "postgres" {
            col.push(
                Finding::new(Severity::Low, MODULE, "PERS-SYSACCT-SHELL", format!("System account with a login shell: {}", a.name))
                    .evidence(format!("{}: UID {} shell {}", a.name, a.uid, a.shell))
                    .description("System accounts normally have /usr/sbin/nologin. A real shell makes it possible to log in as the account if it gets a password or a key.")
                    .verify(format!("getent passwd {}", shq(&a.name)))
                    .verify(format!("passwd -S {}", shq(&a.name))),
            );
        }
    }
    if let Ok(shadow) = ctx.sys.read_string("/etc/shadow") {
        for line in shadow.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() > 1 && f[1].is_empty() {
                col.push(
                    Finding::new(Severity::High, MODULE, "PERS-EMPTY-PASSWORD", format!("Account without a password: {}", f[0]))
                        .evidence(format!("/etc/shadow: {}::…", f[0]))
                        .description("The account has an empty password field and can in some cases log in without a password.")
                        .verify(format!("passwd -S {}", shq(f[0]))),
                );
            }
        }
    }
    let mut sudo_files = vec!["/etc/sudoers".to_string()];
    sudo_files.extend(ctx.sys.dir_names("/etc/sudoers.d").into_iter().map(|n| format!("/etc/sudoers.d/{n}")));
    let mut seen = BTreeSet::new();
    for path in sudo_files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        for line in text.lines().map(|l| l.trim()).filter(|l| !l.starts_with('#') && !l.is_empty()) {
            if line.contains("NOPASSWD") && seen.insert(line.to_string()) {
                let all = line.split("NOPASSWD:").nth(1).map(|r| r.trim() == "ALL").unwrap_or(false);
                col.push(
                    Finding::new(if all { Severity::Medium } else { Severity::Low }, MODULE, "PERS-SUDO-NOPASSWD", format!("sudo without a password in {path}"))
                        .evidence(format!("{path}: {line}"))
                        .description("The rule gives root privileges without a password. Attackers add such lines to keep root.")
                        .verify("sudo -l -U <user>")
                        .verify(format!("cat {}", shq(&path))),
                );
            }
        }
    }
}
