//! SSH: sshd_config (with Include) and authorized_keys.

use super::{record, check_perms, MODULE};
use crate::modules::common::{analyze_command, base64_decode, clip, max_severity, mode_string, reasons, shq, writable_by_others};
use crate::modules::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Clone, PartialEq)]
pub struct SshdSetting {
    pub key: String,
    pub value: String,
    pub file: String,
    pub in_match: bool,
}

/// Read sshd_config with Include in the right order. sshd uses the first value.
pub fn read_sshd_config(ctx: &ScanCtx, col: &mut Collector) -> Vec<SshdSetting> {
    let mut out = Vec::new();
    let mut visited = HashSet::new();
    read_sshd_file(ctx, col, "/etc/ssh/sshd_config", &mut out, &mut visited, 0, false);
    out
}

fn expand_include(ctx: &ScanCtx, pattern: &str) -> Vec<String> {
    let abs = if pattern.starts_with('/') { pattern.to_string() } else { format!("/etc/ssh/{pattern}") };
    match abs.rsplit_once('/') {
        Some((dir, file)) if file.contains('*') => {
            let (pre, suf) = file.split_once('*').unwrap_or((file, ""));
            ctx.sys
                .dir_names(dir)
                .into_iter()
                .filter(|n| n.starts_with(pre) && n.ends_with(suf))
                .map(|n| format!("{dir}/{n}"))
                .collect()
        }
        _ => vec![abs],
    }
}

fn read_sshd_file(
    ctx: &ScanCtx,
    col: &mut Collector,
    path: &str,
    out: &mut Vec<SshdSetting>,
    visited: &mut HashSet<String>,
    depth: u32,
    mut in_match: bool,
) {
    if depth > 8 || !visited.insert(path.to_string()) {
        return;
    }
    let text = match ctx.sys.read_string(path) {
        Ok(t) => t,
        Err(e) => {
            if path == "/etc/ssh/sshd_config" && !e.is_not_found() {
                col.note(e.to_string());
            }
            return;
        }
    };
    record(ctx, col, path);
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let (k, v) = match t.split_once(|c: char| c.is_whitespace() || c == '=') {
            Some((k, v)) => (k.to_lowercase(), v.trim().trim_start_matches('=').trim().to_string()),
            None => continue,
        };
        if k == "match" {
            in_match = !v.eq_ignore_ascii_case("all");
            continue;
        }
        if k == "include" {
            for pat in v.split_whitespace() {
                for f in expand_include(ctx, pat) {
                    read_sshd_file(ctx, col, &f, out, visited, depth + 1, in_match);
                }
            }
            continue;
        }
        out.push(SshdSetting { key: k, value: v, file: path.to_string(), in_match });
    }
}

pub fn sshd_effective<'a>(settings: &'a [SshdSetting], key: &str) -> Option<&'a SshdSetting> {
    settings.iter().find(|s| s.key == key && !s.in_match)
}

/// Reviews sshd_config and returns the AuthorizedKeysFile patterns.
pub fn check_sshd_config(ctx: &ScanCtx, col: &mut Collector) -> Vec<String> {
    let settings = read_sshd_config(ctx, col);
    check_perms(ctx, col, "/etc/ssh/sshd_config", "PERS-SSHD-PERMS", "sshd_config");
    let mk = |sev, rule: &str, title: String, s: &SshdSetting, desc: &str| {
        Finding::new(sev, MODULE, rule, title)
            .evidence(format!(
                "{}: {} {}{}",
                s.file,
                s.key,
                s.value,
                if s.in_match { " (inside a Match block)" } else { "" }
            ))
            .description(desc.to_string())
            .verify("sshd -T | grep -Ei 'permitrootlogin|authorizedkeys|passwordauth|permitempty|subsystem'")
            .verify(format!("grep -n -i {} {}", shq(&s.key), shq(&s.file)))
    };
    // sshd uses the first occurrence – only report the effective one (or Match blocks)
    let mut seen_keys = HashSet::new();
    for s in &settings {
        if !s.in_match && !seen_keys.insert(s.key.clone()) {
            continue;
        }
        let v = s.value.to_lowercase();
        match s.key.as_str() {
            "permitrootlogin" if v == "yes" => col.push(mk(Severity::High, "PERS-SSHD-ROOTLOGIN", "sshd allows root login with a password (PermitRootLogin yes)".into(), s, "Debian 13 defaults to prohibit-password. 'yes' allows password guessing directly against root.")),
            "permitemptypasswords" if v == "yes" => col.push(mk(Severity::Critical, "PERS-SSHD-EMPTYPW", "sshd allows empty passwords".into(), s, "Accounts without a password can log in over the network.")),
            "authorizedkeysfile" => {
                let default_like = s.value.split_whitespace().all(|p| {
                    matches!(p, ".ssh/authorized_keys" | ".ssh/authorized_keys2" | "%h/.ssh/authorized_keys" | "%h/.ssh/authorized_keys2")
                });
                if !default_like {
                    col.push(mk(Severity::High, "PERS-SSHD-AKF", format!("Changed AuthorizedKeysFile: {}", s.value), s, "The key file has been moved from its default location. Attackers do this to put their keys where nobody looks."));
                }
            }
            "authorizedkeyscommand" if v != "none" => col.push(mk(Severity::Medium, "PERS-SSHD-AKC", format!("AuthorizedKeysCommand is used: {}", s.value), s, "An external program decides which keys are accepted. Check that the program is known and protected.")),
            "passwordauthentication" if v == "yes" => col.push(mk(Severity::Low, "PERS-SSHD-PASSWORD", "Password login is explicitly enabled in sshd".into(), s, "Password login makes the server vulnerable to password guessing. Consider key-only login.")),
            "permituserenvironment" if v != "no" => col.push(mk(Severity::Medium, "PERS-SSHD-USERENV", "PermitUserEnvironment is enabled".into(), s, "Users can set environment variables (e.g. LD_PRELOAD) through ~/.ssh/environment.")),
            "gatewayports" if v == "yes" => col.push(mk(Severity::Medium, "PERS-SSHD-GATEWAY", "GatewayPorts yes".into(), s, "Forwarded ports become reachable from other computers – can be used as a tunnel into the network.")),
            "forcecommand" if !s.in_match => col.push(mk(Severity::Medium, "PERS-SSHD-FORCECMD", format!("ForceCommand for every login: {}", s.value), s, "A command runs at every SSH login.")),
            "subsystem" => {
                let ok = ["/usr/lib/openssh/sftp-server", "internal-sftp", "/usr/libexec/openssh/sftp-server", "/usr/libexec/sftp-server"];
                let prog = s.value.split_whitespace().nth(1).unwrap_or("");
                if !ok.contains(&prog) {
                    col.push(mk(Severity::High, "PERS-SSHD-SUBSYSTEM", format!("Unusual SSH subsystem: {}", s.value), s, "The subsystem program runs on connection. An unknown program here can be a backdoor."));
                }
            }
            _ => {}
        }
    }
    let rc = "/etc/ssh/sshrc";
    if ctx.sys.exists(rc) {
        record(ctx, col, rc);
        col.push(
            Finding::new(Severity::Medium, MODULE, "PERS-SSH-RC", format!("{rc} exists (runs at every SSH login)"))
                .evidence(clip(&ctx.sys.read_string(rc).unwrap_or_default(), 600))
                .description("sshrc runs for every user at login and is rarely used on Debian.")
                .verify(format!("cat {rc}")),
        );
    }
    sshd_effective(&settings, "authorizedkeysfile")
        .map(|s| s.value.split_whitespace().map(|x| x.to_string()).collect())
        .unwrap_or_else(|| vec![".ssh/authorized_keys".into(), ".ssh/authorized_keys2".into()])
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthKey {
    pub options: Vec<String>,
    pub key_type: String,
    pub key_b64: String,
    pub comment: String,
}

impl AuthKey {
    pub fn option(&self, name: &str) -> Option<&str> {
        self.options.iter().find_map(|o| {
            let (k, v) = o.split_once('=').unwrap_or((o.as_str(), ""));
            k.eq_ignore_ascii_case(name).then_some(v.trim_matches('"'))
        })
    }

    pub fn has_option(&self, name: &str) -> bool {
        self.options
            .iter()
            .any(|o| o.split('=').next().map(|k| k.eq_ignore_ascii_case(name)).unwrap_or(false))
    }

    /// Size in bits for RSA keys (reads the modulus from the key blob).
    pub fn rsa_bits(&self) -> Option<u32> {
        if self.key_type != "ssh-rsa" {
            return None;
        }
        let blob = base64_decode(&self.key_b64)?;
        let mut pos = 0usize;
        let mut parts: Vec<&[u8]> = Vec::new();
        for _ in 0..3 {
            let len_bytes: [u8; 4] = blob.get(pos..pos + 4)?.try_into().ok()?;
            let len = u32::from_be_bytes(len_bytes) as usize;
            parts.push(blob.get(pos + 4..pos + 4 + len)?);
            pos += 4 + len;
        }
        let n: Vec<u8> = parts[2].iter().copied().skip_while(|b| *b == 0).collect();
        let first = *n.first()?;
        Some((n.len() as u32 - 1) * 8 + (8 - first.leading_zeros()))
    }

    /// OpenSSH fingerprint (SHA256:...), same as `ssh-keygen -lf`.
    pub fn fingerprint(&self) -> Option<String> {
        use sha2::{Digest, Sha256};
        let blob = base64_decode(&self.key_b64)?;
        Some(format!("SHA256:{}", base64_encode_nopad(&Sha256::digest(&blob))))
    }
}

fn base64_encode_nopad(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = (u32::from(chunk[0]) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for i in 0..=chunk.len() {
            out.push(T[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fn is_key_type(t: &str) -> bool {
    t.starts_with("ssh-") || t.starts_with("ecdsa-sha2-") || t.starts_with("sk-ssh-") || t.starts_with("sk-ecdsa-")
}

/// Parse an authorized_keys line: [options] type base64 [comment].
pub fn parse_authorized_key(line: &str) -> Option<AuthKey> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    let (opts_str, rest) = if t.split_whitespace().next().map(is_key_type).unwrap_or(false) {
        ("", t)
    } else {
        let mut in_q = false;
        let mut end = t.len();
        for (i, c) in t.char_indices() {
            if c == '"' {
                in_q = !in_q;
            } else if c.is_whitespace() && !in_q {
                end = i;
                break;
            }
        }
        (&t[..end], t[end..].trim_start())
    };
    let mut parts = rest.splitn(3, char::is_whitespace);
    let key_type = parts.next()?.to_string();
    if !is_key_type(&key_type) {
        return None;
    }
    let key_b64 = parts.next()?.to_string();
    let comment = parts.next().unwrap_or("").trim().to_string();
    let mut options = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in opts_str.chars() {
        match c {
            '"' => {
                in_q = !in_q;
                cur.push(c);
            }
            ',' if !in_q => options.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    if !cur.is_empty() {
        options.push(cur);
    }
    Some(AuthKey { options, key_type, key_b64, comment })
}

pub fn check_authorized_keys(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)], akf: &[String]) {
    let mut seen = HashSet::new();
    // present even when empty, so that a first key shows up against the baseline
    col.inventory.ssh_keys.get_or_insert_with(Vec::new);
    for (user, uid, home) in homes {
        for pat in akf {
            if pat.eq_ignore_ascii_case("none") {
                continue;
            }
            let expanded = pat.replace("%%", "\u{0}").replace("%h", home).replace("%u", user).replace('\u{0}', "%");
            let path = if expanded.starts_with('/') { expanded } else { format!("{home}/{expanded}") };
            if !seen.insert(path.clone()) {
                continue;
            }
            let text = match ctx.sys.read_string(&path) {
                Ok(t) => t,
                Err(e) => {
                    if e.is_permission_denied() {
                        col.note(format!("{path} could not be read (needs root)"));
                    }
                    continue;
                }
            };
            record(ctx, col, &path);
            check_key_file_perms(ctx, col, &path, *uid);
            let mut inventory = Vec::new();
            for (lineno, line) in text.lines().enumerate() {
                let Some(k) = parse_authorized_key(line) else { continue };
                let fp = k.fingerprint().unwrap_or_else(|| "?".into());
                let bits = k.rsa_bits();
                col.inventory.ssh_keys.get_or_insert_with(Vec::new).push(format!("{path} {} {fp} {}", k.key_type, k.comment));
                inventory.push(format!(
                    "{} {}{} \"{}\"{}",
                    k.key_type,
                    bits.map(|b| format!("{b} bits ")).unwrap_or_default(),
                    fp,
                    k.comment,
                    if k.options.is_empty() { String::new() } else { format!(" [{}]", k.options.join(",")) }
                ));
                let ev = format!("{path}:{} ({user})\n{}", lineno + 1, clip(line.trim(), 400));
                let verify = vec![
                    format!("ssh-keygen -lf {}", shq(&path)),
                    format!("sed -n '{}p' {}", lineno + 1, shq(&path)),
                ];

                if let Some(cmd) = k.option("command") {
                    let issues = analyze_command(cmd, ctx.cfg);
                    let sev = max_severity(&issues).unwrap_or(Severity::High).max(Severity::High);
                    col.push(
                        Finding::new(sev, MODULE, "PERS-SSH-COMMAND", format!("SSH key with command= for {user}"))
                            .evidence(ev.clone())
                            .description(format!(
                                "The key runs a forced command at login: {cmd}. Legitimate for e.g. backups, but attackers use it to start backdoors quietly.{}",
                                if issues.is_empty() { String::new() } else { format!(" Suspicious: {}.", reasons(&issues)) }
                            ))
                            .verify_all(verify.clone()),
                    );
                }
                if k.has_option("environment") {
                    col.push(
                        Finding::new(Severity::High, MODULE, "PERS-SSH-ENV", format!("SSH key with environment= for {user}"))
                            .evidence(ev.clone())
                            .description("The key sets environment variables at login (e.g. LD_PRELOAD).")
                            .verify_all(verify.clone()),
                    );
                }
                if k.has_option("permitopen") || k.has_option("permitlisten") || k.has_option("tunnel") {
                    col.push(
                        Finding::new(Severity::Medium, MODULE, "PERS-SSH-TUNNEL", format!("SSH key that allows tunnels for {user}"))
                            .evidence(ev.clone())
                            .description("The key is limited to port or tunnel forwarding – can be used as a hidden way into the network.")
                            .verify_all(verify.clone()),
                    );
                }
                if k.key_type == "ssh-dss" || bits.map(|b| b < 2048).unwrap_or(false) {
                    col.push(
                        Finding::new(Severity::Medium, MODULE, "PERS-SSH-WEAK", format!("Weak SSH key for {user}"))
                            .evidence(ev.clone())
                            .description("DSA keys and RSA keys under 2048 bits are obsolete and not accepted by OpenSSH in Debian 13 – unusual on a freshly installed system.")
                            .verify_all(verify.clone()),
                    );
                }
                if k.comment.is_empty() {
                    col.push(
                        Finding::new(Severity::Low, MODULE, "PERS-SSH-NOCOMMENT", format!("SSH key without a comment for {user}"))
                            .evidence(ev.clone())
                            .description("The key has no comment, so you cannot see whose it is. Attackers often add keys without a comment.")
                            .verify_all(verify.clone()),
                    );
                } else if !ctx.cfg.allowed_ssh_key_comments.is_empty() && !ctx.cfg.allowed_ssh_key_comments.contains(&k.comment) {
                    col.push(
                        Finding::new(if *uid == 0 { Severity::High } else { Severity::Medium }, MODULE, "PERS-SSH-UNKNOWN-KEY", format!("Unknown SSH key for {user}: \"{}\"", k.comment))
                            .evidence(ev.clone())
                            .description("The key's comment is not in allowed_ssh_key_comments.")
                            .verify_all(verify.clone()),
                    );
                }
            }
            if !inventory.is_empty() && ctx.cfg.allowed_ssh_key_comments.is_empty() {
                col.push(
                    Finding::new(if *uid == 0 { Severity::Medium } else { Severity::Low }, MODULE, "PERS-SSH-KEYS", format!("{} SSH key(s) allow login as {user}", inventory.len()))
                        .evidence(format!("{path}\n{}", inventory.join("\n")))
                        .description("Overview of keys that can log in. Fill allowed_ssh_key_comments with known comments and only unknown keys will be reported.")
                        .verify(format!("ssh-keygen -lf {}", shq(&path))),
                );
            }
        }
        let rc = format!("{home}/.ssh/rc");
        if ctx.sys.exists(&rc) {
            record(ctx, col, &rc);
            col.push(
                Finding::new(Severity::Medium, MODULE, "PERS-SSH-RC", format!("{rc} exists (runs at every SSH login)"))
                    .evidence(clip(&ctx.sys.read_string(&rc).unwrap_or_default(), 600))
                    .description("~/.ssh/rc runs at every login for the user and is a known persistence method.")
                    .verify(format!("cat {}", shq(&rc))),
            );
        }
    }
}

fn check_key_file_perms(ctx: &ScanCtx, col: &mut Collector, path: &str, uid: u32) {
    if let Ok(m) = std::fs::metadata(ctx.sys.path(path)) {
        let wrong_owner = uid != u32::MAX && m.uid() != uid && m.uid() != 0;
        if writable_by_others(&m) || wrong_owner {
            col.push(
                Finding::new(Severity::High, MODULE, "PERS-SSH-PERMS", format!("Unsafe permissions on {path}"))
                    .evidence(format!("{path} mode {} owner {}:{}", mode_string(m.mode()), m.uid(), m.gid()))
                    .description("If others can write to authorized_keys they can add their own keys and log in as the user.")
                    .verify(format!("stat {}", shq(path))),
            );
        }
    }
}
