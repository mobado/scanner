//! Shared rules: assessment of command lines (systemd, cron, rc.local,
//! shell files), file permissions and a small base64 decoder.

use crate::config::Config;
use crate::finding::Severity;
use chrono::{Datelike, NaiveDateTime};
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

const HOME_REASON: &str = "points to a home directory (/home)";

/// The words of a command that name something that gets run: the first one of every command,
/// and what a shell, interpreter or wrapper is given.
pub fn program_words(cmd: &str) -> Vec<String> {
    const WRAPPERS: [&str; 15] = [
        "sh", "bash", "dash", "zsh", "env", "nohup", "setsid", "exec", "nice", "ionice", "python", "python3", "perl", "source", ".",
    ];
    let mut out = Vec::new();
    let mut expect = true;
    for word in split_quoted(cmd) {
        if matches!(word.as_str(), "&&" | "||" | ";" | "|" | "&") {
            expect = true;
            continue;
        }
        // options and NAME=value settings come between a wrapper and its program
        if !expect || word.starts_with('-') || (word.contains('=') && !word.starts_with('/')) {
            continue;
        }
        // sh -c "program arguments"
        if word.contains(char::is_whitespace) && !word.starts_with('/') {
            out.extend(program_words(&word));
            expect = false;
            continue;
        }
        let word = word.trim_end_matches(';').to_string();
        expect = WRAPPERS.contains(&crate::procinfo::basename(&word));
        out.push(word);
    }
    out
}

/// Is a program in a home folder kept in a place where programs do not belong?
pub fn risky_home_place(path: &str, cfg: &Config) -> Option<&'static str> {
    let rest = match path.strip_prefix("/home/") {
        Some(r) => r.split_once('/')?.1,
        None => path.strip_prefix("/root/")?,
    };
    if cfg.download_dirs.iter().any(|d| rest.starts_with(&format!("{d}/"))) {
        Some("the download folder")
    } else if rest.starts_with(".local/share/Trash/") {
        Some("the wastebasket")
    } else if rest.starts_with(".cache/") {
        Some("a cache folder")
    } else if crate::procinfo::basename(rest).starts_with('.') {
        Some("a hidden file")
    } else {
        None
    }
}

/// Like [`analyze_command`], for what a user starts from their own files (autostart, user
/// services, own cron jobs, shell files): pointing into a home folder is normal there, but
/// running something from the download folder, a cache or a hidden file is not.
pub fn analyze_user_command(cmd: &str, cfg: &Config) -> Vec<CmdIssue> {
    let mut out = analyze_command(cmd, cfg);
    out.retain(|i| i.reason != HOME_REASON);
    for word in program_words(cmd) {
        let path = ["%h/", "~/", "$HOME/", "${HOME}/"]
            .iter()
            .find_map(|p| word.strip_prefix(p))
            .map(|rest| format!("/home/user/{rest}"))
            .unwrap_or(word);
        if let Some(place) = risky_home_place(&path, cfg) {
            let reason = format!("runs a program from {place}");
            if !out.iter().any(|i| i.reason == reason) {
                out.push(CmdIssue { severity: Severity::Medium, reason });
            }
        }
    }
    out
}

/// Is this a program inside a mounted AppImage (its own file system under /tmp)?
pub fn is_appimage_mount(sys: &crate::sys::SysRoot, exe: &str) -> bool {
    exe.starts_with("/tmp/.mount_")
        && sys.read_string("/proc/mounts").unwrap_or_default().lines().any(|line| {
            let mut f = line.split_whitespace().skip(1);
            match (f.next(), f.next()) {
                (Some(point), Some(kind)) => kind.starts_with("fuse") && point.starts_with("/tmp/.mount_") && exe.starts_with(&format!("{point}/")),
                _ => false,
            }
        })
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
        // desktops keep sockets and settings under /run; only a program started from there counts
        if (d == "/run/user" || d == "/run/lock") && !program_words(cmd).iter().any(|w| w.starts_with(&needle)) {
            continue;
        }
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
        add(Severity::High, HOME_REASON);
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

/// The time of a log line: ISO ("2026-11-25T10:00:00+01:00", journal or rsyslog) or the old
/// syslog form "Nov 25 10:00:00", whose year is taken from `reference` (the year before when
/// that would put the line in the future).
pub fn log_line_time(line: &str, reference: NaiveDateTime) -> Option<NaiveDateTime> {
    let mut words = line.split_whitespace();
    let first = words.next()?;
    if first.starts_with(|c: char| c.is_ascii_digit()) {
        return chrono::DateTime::parse_from_str(first, "%Y-%m-%dT%H:%M:%S%.f%z").ok().map(|t| t.naive_local());
    }
    let stamp = format!("{first} {} {}", words.next()?, words.next()?);
    let with_year = |year: i32| NaiveDateTime::parse_from_str(&format!("{year} {stamp}"), "%Y %b %d %H:%M:%S").ok();
    match with_year(reference.year()) {
        Some(t) if t <= reference + chrono::Duration::days(1) => Some(t),
        _ => with_year(reference.year() - 1),
    }
}

/// Keep only the log lines from the last `days` days. On the running system "now" is the end
/// of that window; for a mounted disk or test folder it is the newest line in the log. Lines
/// without a readable time are kept.
pub fn recent_lines<'a>(lines: Vec<&'a str>, days: u32, live: bool) -> Vec<&'a str> {
    let now = chrono::Local::now().naive_local();
    let reference = if live { now } else { lines.iter().filter_map(|l| log_line_time(l, now)).max().unwrap_or(now) };
    let oldest = reference - chrono::Duration::days(i64::from(days.max(1)));
    lines.into_iter().filter(|l| log_line_time(l, reference).map(|t| t >= oldest).unwrap_or(true)).collect()
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
