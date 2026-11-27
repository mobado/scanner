//! Shell command histories: commands an intruder typically types. Only the lines that match
//! are shown; nothing else from a history is stored or reported.

use super::MODULE;
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_command, clip, cut_short, shq, MINER_REASON};
use crate::modules::{Collector, ScanCtx};

const FILES: [&str; 4] = [".bash_history", ".zsh_history", ".sh_history", ".local/share/fish/fish_history"];
/// Only the end of a very large history is read.
const READ_LIMIT: usize = 4 * 1024 * 1024;
const SHOWN: usize = 15;

/// The command part of a history line (zsh writes ": time:0;command", fish "- cmd: command").
fn command_of(line: &str) -> Option<&str> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with("when:") || line.starts_with("paths:") {
        return None;
    }
    if let Some(cmd) = line.strip_prefix("- cmd: ") {
        return Some(cmd);
    }
    if line.starts_with(": ") {
        return line.split_once(';').map(|(_, c)| c);
    }
    Some(line)
}

/// Commands that only look for text should not match what they search for.
const SEARCHES: [&str; 9] = ["grep", "egrep", "fgrep", "rg", "ag", "man", "apt", "apt-cache", "history"];

/// Why a typed command is suspicious, if it is.
pub fn judge_command(ctx: &ScanCtx, command: &str) -> Option<(Severity, String)> {
    let lower = command.to_lowercase();
    let first = lower.split_whitespace().find(|w| *w != "sudo").unwrap_or("");
    if SEARCHES.contains(&crate::procinfo::basename(first)) && !lower.contains('|') {
        return None;
    }
    let words: Vec<&str> = lower.split_whitespace().collect();
    let high = |r: &str| Some((Severity::High, r.to_string()));
    let medium = |r: &str| Some((Severity::Medium, r.to_string()));

    if lower.contains("histfile=/dev/null") || lower.contains("unset histfile") || lower.contains("histsize=0") {
        return high("switches off the command history");
    }
    if (lower.contains(">") || lower.contains("tee ")) && lower.contains("/etc/ld.so.preload") {
        return high("writes to /etc/ld.so.preload (rootkit technique)");
    }
    if ["useradd", "usermod"].iter().any(|c| words.contains(c)) && words.windows(2).any(|w| w == ["-u", "0"]) {
        return high("creates or changes an account to UID 0 (a second root)");
    }
    if (words.contains(&"rm") || words.contains(&"shred") || words.contains(&"truncate")) && ["/var/log/auth", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/var/log/journal"].iter().any(|p| lower.contains(p)) {
        return high("deletes login records or logs");
    }
    // Reuse the command rules, but only the ones that are rare in honest use
    for issue in analyze_command(command, ctx.cfg) {
        let r = issue.reason.as_str();
        if r.starts_with("netcat with") || r.starts_with("socat with") || r.starts_with("uses /dev/tcp") || r.ends_with("(reverse shell pattern)") || r == MINER_REASON {
            return high(r);
        }
        if r.starts_with("downloads and runs code") {
            // from a bare IP address it is far less likely to be a normal installer
            let bare_ip = words.iter().any(|w| {
                let w = w.trim_matches(|c| c == '"' || c == '\'');
                let host = w.split_once("://").map(|(_, r)| r).unwrap_or(w).split(['/', ':']).next().unwrap_or("");
                host.parse::<std::net::Ipv4Addr>().is_ok()
            });
            return if bare_ip { high("downloads code from an IP address and runs it") } else { Some((Severity::Low, r.to_string())) };
        }
        if r == "adds SSH keys" {
            return medium(r);
        }
    }
    if lower.contains("chmod +s") || lower.contains("chmod u+s") || lower.contains("chmod 4755") || lower.contains("chmod 4777") {
        return medium("sets the SUID bit");
    }
    if lower.contains("history -c") {
        return medium("clears the command history");
    }
    if words.contains(&"chattr") && words.contains(&"+i") {
        return medium("locks a file so it cannot be changed or deleted");
    }
    if let Some(name) = ctx.cfg.known_malware_names.iter().find(|n| words.iter().any(|w| crate::procinfo::basename(w) == n.as_str() && (w.starts_with('/') || w.starts_with("./") || *w == first))) {
        return high(&format!("starts known malware '{name}'"));
    }
    None
}

pub fn check_histories(ctx: &ScanCtx, col: &mut Collector, homes: &[(String, u32, String)]) {
    for (user, _, home) in homes {
        for name in FILES {
            let path = format!("{home}/{name}");
            let Ok(bytes) = ctx.sys.read_bytes(&path) else { continue };
            if bytes.len() > READ_LIMIT {
                cut_short(&format!("the older part of {path} (bytes)"), READ_LIMIT);
            }
            let text = String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(READ_LIMIT)..]);
            let mut hits: Vec<(Severity, String)> = Vec::new();
            for line in text.lines() {
                let Some(command) = command_of(line) else { continue };
                let Some((severity, why)) = judge_command(ctx, command) else { continue };
                let shown = format!("{}  ← {why}", clip(command, 200));
                if !hits.iter().any(|(_, l)| *l == shown) {
                    hits.push((severity, shown));
                }
            }
            let Some(worst) = hits.iter().map(|(s, _)| *s).max() else { continue };
            let total = hits.len();
            // worst first, newest first among equals
            hits.reverse();
            hits.sort_by(|a, b| b.0.cmp(&a.0));
            let lines: Vec<String> = hits.into_iter().take(SHOWN).map(|(_, l)| l).collect();
            col.push(
                Finding::new(worst, MODULE, "PERS-HISTORY", format!("{total} suspicious command(s) in {user}'s shell history: {path}"))
                    .evidence(format!("{path}\n{}", lines.join("\n")))
                    .description("These commands were typed in a shell. If you or an installer you trust ran them, that is fine; if you do not recognise them, someone else has used the account.")
                    .verify(format!("less {}", shq(&path)))
                    .verify("last -F | head -20"),
            );
        }
    }
}
