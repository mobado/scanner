//! Shared rules: assessment of command lines (systemd, cron, rc.local,
//! shell files), file permissions and a small base64 decoder.

use crate::config::Config;
use crate::finding::Severity;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// A suspicious trait in a command.
#[derive(Debug, Clone, PartialEq)]
pub struct CmdIssue {
    pub severity: Severity,
    pub reason: String,
}

/// Highest severity in a list, if any.
pub fn max_severity(issues: &[CmdIssue]) -> Option<Severity> {
    issues.iter().map(|i| i.severity).max()
}

pub fn reasons(issues: &[CmdIssue]) -> String {
    issues
        .iter()
        .map(|i| i.reason.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

fn is_b64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
}

/// Assess a command or a script line. Empty list = nothing suspicious.
pub fn analyze_command(cmd: &str, cfg: &Config) -> Vec<CmdIssue> {
    let mut out = Vec::new();
    let lower = cmd.to_lowercase();
    let mut add = |sev: Severity, reason: &str| {
        if !out.iter().any(|i: &CmdIssue| i.reason == reason) {
            out.push(CmdIssue {
                severity: sev,
                reason: reason.to_string(),
            });
        }
    };

    // Executables in temporary directories
    for d in &cfg.temp_dirs {
        let needle = format!("{d}/");
        if let Some(pos) = cmd.find(&needle) {
            let after = &cmd[pos + needle.len()..];
            let hidden = after.starts_with('.');
            if d.contains("shm") || hidden {
                add(
                    Severity::Critical,
                    &format!("runs from {d}{}", if hidden { " (hidden file)" } else { "" }),
                );
            } else {
                add(Severity::High, &format!("points to temporary directory {d}"));
            }
        }
    }
    if cmd.contains("/home/") {
        add(Severity::High, "points to a home directory (/home)");
    }

    // Decoding and obfuscation
    if lower.contains("base64 -d")
        || lower.contains("base64 --decode")
        || lower.contains("b64decode")
        || lower.contains("frombase64")
        || lower.contains("base64 -di")
    {
        add(Severity::Critical, "decodes base64 at run time");
    }
    let long_blob = cmd
        .split(|c: char| !is_b64_char(c))
        .any(|tok| tok.len() >= 60 && tok.chars().any(|c| c.is_ascii_digit()) && tok.chars().any(|c| c.is_ascii_uppercase()));
    if long_blob {
        add(Severity::High, "contains a long base64-like string");
    }
    if cmd.matches("\\x").count() >= 8 {
        add(Severity::High, "contains hex-encoded characters (\\x..)");
    }
    if lower.contains("eval ") || lower.contains("eval(") || lower.contains("exec(") {
        add(Severity::Medium, "uses eval/exec");
    }

    // Reverse shells and downloads
    if cmd.contains("/dev/tcp/") || cmd.contains("/dev/udp/") {
        add(Severity::Critical, "uses /dev/tcp or /dev/udp (bash networking, typical reverse shell)");
    }
    // quotes around words must not hide them: sh -c 'curl ... | sh'
    let tokens: Vec<&str> = cmd.split_whitespace().map(|t| t.trim_matches(|c| c == '\'' || c == '"')).collect();
    let has_tool = |names: &[&str]| {
        tokens
            .iter()
            .any(|t| names.contains(&crate::procinfo::basename(t)))
    };
    if has_tool(&["nc", "ncat", "netcat", "nc.traditional", "nc.openbsd"])
        && (tokens.contains(&"-e") || tokens.contains(&"-c") || lower.contains("-e /bin") || tokens.contains(&"--exec"))
    {
        add(Severity::Critical, "netcat with -e/-c (starts a shell over the network)");
    }
    if has_tool(&["socat"]) && (lower.contains("exec:") || lower.contains("system:")) {
        add(Severity::Critical, "socat with exec:/system: (shell over the network)");
    }
    if lower.contains("mkfifo") || lower.contains("mknod") && lower.contains(" p") {
        add(Severity::High, "creates a named pipe (common in reverse shells)");
    }
    let downloads = has_tool(&["curl", "wget", "fetch", "tftp", "lwp-download"]);
    let pipes_to_shell = ["| sh", "|sh", "| bash", "|bash", "| python", "|python", "| perl", "|perl", "| /bin/sh", "| /bin/bash"]
        .iter()
        .any(|p| lower.contains(p));
    if downloads && pipes_to_shell {
        add(Severity::Critical, "downloads and runs code directly (curl/wget | sh)");
    } else if pipes_to_shell {
        add(Severity::High, "pipes data straight into a shell");
    } else if downloads {
        add(Severity::Medium, "downloads files (curl/wget)");
    }
    let inline_interp = [
        ("python", "-c"),
        ("python3", "-c"),
        ("perl", "-e"),
        ("ruby", "-e"),
        ("php", "-r"),
    ];
    for (interp, flag) in inline_interp {
        if tokens.iter().any(|t| {
            let b = crate::procinfo::basename(t);
            b == interp || (b.starts_with(interp) && b[interp.len()..].chars().all(|c| c.is_ascii_digit() || c == '.'))
        }) && tokens.contains(&flag)
        {
            if lower.contains("socket") || lower.contains("pty") || lower.contains("subprocess") || lower.contains("connect") {
                add(Severity::Critical, &format!("{interp} {flag} with socket/pty (reverse shell pattern)"));
            } else {
                add(Severity::Medium, &format!("runs inline {interp} code ({flag})"));
            }
        }
    }
    if lower.contains("chmod +s") || lower.contains("chmod u+s") || lower.contains("chmod 4755") || lower.contains("chmod 4777") || lower.contains("chmod 6755") {
        add(Severity::High, "sets the SUID bit");
    }
    if cmd.contains("LD_PRELOAD") {
        add(Severity::High, "sets LD_PRELOAD");
    }
    if lower.contains("/etc/shadow") {
        add(Severity::High, "touches /etc/shadow");
    }
    if lower.contains("authorized_keys") && (lower.contains(">>") || lower.contains("echo")) {
        add(Severity::Critical, "adds SSH keys");
    }
    if lower.contains("iptables -f") || lower.contains("ufw disable") || lower.contains("setenforce 0") {
        add(Severity::High, "disables firewall/protection");
    }
    if lower.contains("history -c") || lower.contains("unset histfile") || lower.contains("histfile=/dev/null") {
        add(Severity::High, "hides shell history");
    }
    for name in &cfg.known_malware_names {
        if lower.contains(name.as_str()) {
            add(Severity::Critical, &format!("mentions known malware '{name}'"));
        }
    }
    if lower.contains("stratum+tcp") || lower.contains("--donate-level") {
        add(Severity::Critical, "kryptominer-parametrar");
    }
    out
}

/// Permission problem on a file that controls the system.
pub fn writable_by_others(meta: &std::fs::Metadata) -> bool {
    meta.mode() & 0o022 != 0
}

pub fn mode_string(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

/// Short description of owner and permissions.
pub fn perm_summary(path: &Path) -> Option<String> {
    let m = std::fs::symlink_metadata(path).ok()?;
    Some(format!("mode {} owner {}:{}", mode_string(m.mode()), m.uid(), m.gid()))
}

/// Small standard base64 decoder (to read the SSH key length).
pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<u8> = input.bytes().filter(|b| *b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in clean {
        buf = (buf << 6) | val(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// Split a line into words, respecting quotes ("a b" becomes one word).
pub fn split_quoted(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    for c in line.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => cur.push(c),
            None if c == '"' || c == '\'' => quote = Some(c),
            None if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            None => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Shorten long evidence.
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max).collect();
        format!("{cut}…")
    }
}

/// Quote a path for a shell command.
pub fn shq(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "/._-+:@%".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}
