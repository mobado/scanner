//! integrity: signs that logs were cleared or logging stopped, damaged login records, and a
//! clock that can't be trusted (which breaks the timeline of an investigation).

use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::modules::common::shq;
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, SystemTime};

pub const MODULE: &str = "integrity";

/// Size of one record in wtmp/btmp (struct utmp on x86_64 and arm64).
const UTMP_RECORD: usize = 384;

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    check_silenced_logs(ctx, col);
    check_empty_logs(ctx, col);
    check_wtmp(ctx, col);
    check_time_order(ctx, col);
    super::bootchain::run(ctx, col);
    if ctx.sys.is_live() {
        check_journal(ctx, col);
        check_clock(col);
    }
}

fn check_silenced_logs(ctx: &ScanCtx, col: &mut Collector) {
    let mut paths: Vec<(String, Severity)> = ["/var/log/auth.log", "/var/log/syslog", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog", "/var/log/dpkg.log", "/var/log/journal"]
        .iter()
        .map(|p| (p.to_string(), Severity::High))
        .collect();
    let mut homes = vec!["/root".to_string()];
    homes.extend(ctx.sys.dir_names("/home").into_iter().map(|n| format!("/home/{n}")));
    for h in &homes {
        for f in [".bash_history", ".zsh_history"] {
            paths.push((format!("{h}/{f}"), Severity::Medium));
        }
    }
    for (path, sev) in paths {
        if let Some(target) = ctx.sys.read_link(&path) {
            if target == "/dev/null" {
                col.push(
                    Finding::new(sev, MODULE, "INT-LOG-DEVNULL", format!("Log or history thrown away: {path}"))
                        .evidence(format!("{path} -> /dev/null"))
                        .description("The file points to /dev/null, so nothing is saved. Intruders do this to hide what they did (some people do it for privacy).")
                        .verify(format!("ls -l {}", shq(&path))),
                );
            }
        }
    }
}

fn age(ctx: &ScanCtx, path: &str) -> Option<(u64, Duration)> {
    let m = std::fs::metadata(ctx.sys.path(path)).ok()?;
    let age = SystemTime::now().duration_since(m.modified().ok()?).unwrap_or_default();
    Some((m.len(), age))
}

fn check_empty_logs(ctx: &ScanCtx, col: &mut Collector) {
    for log in ["/var/log/auth.log", "/var/log/syslog", "/var/log/wtmp"] {
        let Some((len, since)) = age(ctx, log) else { continue };
        let older = age(ctx, &format!("{log}.1")).map(|(l, _)| l > 0).unwrap_or(false);
        // right after rotation a new log is briefly empty
        if len == 0 && older && since > Duration::from_secs(2 * 86_400) {
            col.push(
                Finding::new(Severity::Medium, MODULE, "INT-LOG-EMPTY", format!("Log is empty and has stayed so: {log}"))
                    .evidence(format!("{log} is 0 bytes (last changed {} days ago), {log}.1 has content", since.as_secs() / 86_400))
                    .description("The log was emptied or logging stopped. Check that rsyslog runs and whether someone truncated it.")
                    .verify(format!("ls -l --time-style=full-iso {log}*"))
                    .verify("systemctl status rsyslog systemd-journald"),
            );
        }
    }
}

/// (damaged size, number of completely empty records)
pub fn utmp_damage(data: &[u8]) -> (bool, usize) {
    let torn = data.len() % UTMP_RECORD != 0;
    let zero = data.chunks_exact(UTMP_RECORD).filter(|r| r.iter().all(|b| *b == 0)).count();
    (torn, zero)
}

/// The last `max` bytes of a file (rounded to start on a multiple of `align`), and its size.
/// Logs on a server under attack can be gigabytes, so they are never read whole.
fn read_tail(ctx: &ScanCtx, path: &str, max: u64, align: u64) -> Option<(Vec<u8>, u64)> {
    let mut f = std::fs::File::open(ctx.sys.path(path)).ok()?;
    let len = f.metadata().ok()?.len();
    let mut start = len.saturating_sub(max);
    start -= start % align.max(1);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut data = Vec::new();
    f.take(max + align).read_to_end(&mut data).ok()?;
    Some((data, len))
}

fn check_wtmp(ctx: &ScanCtx, col: &mut Collector) {
    for path in ["/var/log/wtmp", "/var/log/btmp"] {
        let Some((data, len)) = read_tail(ctx, path, 16 * 1024 * 1024, UTMP_RECORD as u64) else { continue };
        let (torn, zero) = utmp_damage(&data);
        if torn || zero > 0 {
            col.push(
                Finding::new(if torn { Severity::Medium } else { Severity::Low }, MODULE, "INT-WTMP", format!("Damaged login records in {path}"))
                    .evidence(format!("{path}: {len} bytes{}, {zero} empty record(s)", if torn { " (not a whole number of records)" } else { "" }))
                    .description("Login history with holes can mean entries were erased to hide a login; a crash or power cut also does it.")
                    .verify("last -x -f /var/log/wtmp | head -40"),
            );
        }
    }
}

/// Login and administrator events logged within ten minutes of the given times.
pub fn logins_near(lines: &[&str], times: &[chrono::DateTime<chrono::FixedOffset>]) -> Vec<String> {
    const SIGNS: [&str; 7] = ["sshd", "sudo", "su[", "pkexec", "polkitd", "authentication failure", "session opened"];
    lines
        .iter()
        .filter(|l| SIGNS.iter().any(|s| l.contains(s)))
        .filter(|l| {
            let stamp = l.split_whitespace().next().and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok());
            stamp.map(|t| times.iter().any(|j| (t - *j).num_seconds().abs() <= 600)).unwrap_or(false)
        })
        .take(8)
        .map(|l| crate::modules::common::clip(l, 180))
        .collect()
}

/// Backward jumps of more than an hour in an ISO-stamped log.
pub fn backward_jumps(text: &str) -> Vec<String> {
    let mut last: Option<(chrono::DateTime<chrono::FixedOffset>, &str)> = None;
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(stamp) = line.split_whitespace().next() else { continue };
        let Ok(t) = chrono::DateTime::parse_from_rfc3339(stamp) else { continue };
        if let Some((prev, prev_line)) = last {
            if (prev - t).num_seconds() > 3600 && out.len() < 5 {
                out.push(format!("{}\n  then: {}", crate::modules::common::clip(prev_line, 140), crate::modules::common::clip(line, 140)));
            }
        }
        last = Some((t, line));
    }
    out
}

fn check_time_order(ctx: &ScanCtx, col: &mut Collector) {
    for log in ["/var/log/auth.log", "/var/log/syslog"] {
        let Some((data, _)) = read_tail(ctx, log, 16 * 1024 * 1024, 1) else { continue };
        let text = String::from_utf8_lossy(&data);
        let recent = crate::modules::common::recent_lines(text.lines().collect(), ctx.cfg.log_days, ctx.sys.is_live());
        let jumps = backward_jumps(&recent.join("\n"));
        if !jumps.is_empty() {
            // the times on both sides of each jump, to show what happened around them
            let times: Vec<_> = jumps.iter().flat_map(|j| j.split_whitespace().filter_map(|w| chrono::DateTime::parse_from_rfc3339(w).ok())).collect();
            let mut evidence = jumps.join("\n");
            let near = logins_near(&recent, &times);
            if !near.is_empty() {
                evidence.push_str(&format!("\nlogins and administrator actions within 10 minutes:\n{}", near.join("\n")));
            }
            col.push(
                Finding::new(Severity::Medium, MODULE, "INT-TIME-BACKWARDS", format!("Time jumps backwards in {log}"))
                    .evidence(evidence)
                    .description("Later lines carry an earlier time. The clock was set back (or lines were inserted), so the order of events can't be trusted around these points.")
                    .verify(format!("grep -n . {log} | head -50"))
                    .verify("journalctl -u systemd-timesyncd --since=-28days"),
            );
        }
    }
}

fn check_journal(ctx: &ScanCtx, col: &mut Collector) {
    if !ctx.sys.exists("/var/log/journal") {
        col.push(
            Finding::new(Severity::Low, MODULE, "INT-JOURNAL-VOLATILE", "The system journal is not saved across reboots")
                .evidence("/var/log/journal does not exist")
                .description("Logs disappear at every restart, so there is little to investigate afterwards. Create it with: mkdir -p /var/log/journal && systemctl restart systemd-journald (as root).")
                .verify("journalctl --list-boots"),
        );
        return;
    }
    if !ctx.privileged {
        col.note("integrity: the journal is only verified as root");
        return;
    }
    // Verifying reads every journal file and can take minutes on a large journal, so it only
    // runs in the full (deep) scan and stops after a time limit.
    let limit = ctx.cfg.journal_verify_secs;
    if !ctx.deep_pid_scan || limit == 0 {
        col.note("integrity: the journal is verified only in the full scan (it can take a minute)");
        return;
    }
    let Some(journalctl) = crate::external_tools::find_binary("journalctl") else { return };
    match crate::external_tools::run_capture(&journalctl, &["--verify", "-q"], limit) {
        Ok(o) => {
            if o.timed_out {
                col.note(format!("integrity: verifying the journal was stopped after {limit} s (journal_verify_secs); run 'sudo journalctl --verify' to check all of it"));
            }
            let failed: Vec<&str> = o.stderr.lines().chain(o.stdout.lines()).filter(|l| l.starts_with("FAIL")).take(10).collect();
            if !failed.is_empty() {
                col.push(
                    Finding::new(Severity::Medium, MODULE, "INT-JOURNAL-CORRUPT", "The system journal fails verification")
                        .evidence(failed.join("\n"))
                        .description("Journal files are damaged. A crash can cause this; so can someone editing logs.")
                        .verify("sudo journalctl --verify"),
                );
            }
        }
        Err(e) => col.note(format!("integrity: journalctl --verify could not run: {e}")),
    }
}

fn check_clock(col: &mut Collector) {
    let Some(timedatectl) = crate::external_tools::find_binary("timedatectl") else { return };
    let Ok(o) = crate::external_tools::run_capture(&timedatectl, &["show", "-p", "NTP", "-p", "NTPSynchronized"], 20) else { return };
    let value = |k: &str| o.stdout.lines().find_map(|l| l.strip_prefix(k).and_then(|v| v.strip_prefix('=')).map(|v| v.trim().to_string()));
    if value("NTPSynchronized").as_deref() == Some("no") {
        let off = value("NTP").as_deref() == Some("no");
        col.push(
            Finding::new(if off { Severity::Medium } else { Severity::Low }, MODULE, "INT-CLOCK", if off { "Automatic time setting is switched off" } else { "The clock is not synchronised right now" })
                .evidence(o.stdout.trim().to_string())
                .description("A wrong clock makes logs misleading and can break certificate checks. Switch on with: timedatectl set-ntp true (as root).")
                .verify("timedatectl status")
                .verify("timedatectl timesync-status"),
        );
    }
}
