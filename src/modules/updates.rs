//! updates: pending package updates (security updates first) and "reboot required".
//!
//! Runs `apt-get -s upgrade` (a simulation: nothing is installed or downloaded) and
//! reads the answer. It only knows what the package lists say, so it also reports
//! how old the lists are.

use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use std::time::{Duration, SystemTime};

pub const MODULE: &str = "updates";

#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    pub name: String,
    pub old: Option<String>,
    pub new: String,
    pub origin: String,
    pub security: bool,
}

/// Parse `apt-get -s upgrade`:
/// `Inst libssl3t64 [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])`
pub fn parse_apt_simulation(out: &str) -> Vec<Pending> {
    let mut v = Vec::new();
    for line in out.lines() {
        let Some(rest) = line.strip_prefix("Inst ") else { continue };
        let name = rest.split_whitespace().next().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        let old = rest
            .find('[')
            .and_then(|a| rest[a + 1..].find(']').map(|b| rest[a + 1..a + 1 + b].to_string()))
            .filter(|_| rest.find('[') < rest.find('('));
        let inside = rest.find('(').and_then(|a| rest[a + 1..].find(')').map(|b| &rest[a + 1..a + 1 + b])).unwrap_or("");
        let mut parts = inside.split_whitespace();
        let new = parts.next().unwrap_or("?").to_string();
        let origin = parts.next().unwrap_or("").to_string();
        let security = origin.to_lowercase().contains("security");
        v.push(Pending { name, old, new, origin, security });
    }
    v
}

fn fmt_pending(p: &Pending) -> String {
    format!(
        "{} {} → {}{}",
        p.name,
        p.old.as_deref().unwrap_or("(new)"),
        p.new,
        if p.security { "  [security]" } else { "" }
    )
}

fn age_days(ctx: &ScanCtx, abs: &str) -> Option<u64> {
    let m = std::fs::metadata(ctx.sys.path(abs)).ok()?.modified().ok()?;
    SystemTime::now().duration_since(m).ok().map(|d| d.as_secs() / 86_400)
}

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    if !ctx.sys.is_live() {
        col.note("updates: skipped (only checked on the live system)");
        return;
    }
    check_reboot_required(ctx, col);

    let Some(apt) = crate::external_tools::find_binary("apt-get") else {
        col.note("updates: apt-get was not found – pending updates were not checked");
        return;
    };
    let out = match crate::external_tools::run_capture(&apt, &["-s", "-o", "Debug::NoLocking=true", "upgrade"], 90) {
        Ok(o) => o,
        Err(e) => {
            col.note(format!("updates: apt-get could not run: {e}"));
            return;
        }
    };
    if out.status != Some(0) {
        col.note(format!("updates: apt-get -s upgrade failed: {}", out.stderr.lines().next().unwrap_or("").trim()));
        return;
    }
    let pending = parse_apt_simulation(&out.stdout);
    let security: Vec<&Pending> = pending.iter().filter(|p| p.security).collect();
    let evidence = |list: &[&Pending]| {
        let mut lines: Vec<String> = list.iter().take(40).map(|p| fmt_pending(p)).collect();
        if list.len() > 40 {
            lines.push(format!("… and {} more", list.len() - 40));
        }
        lines.join("\n")
    };
    let verify = [
        "apt list --upgradable 2>/dev/null",
        "sudo apt update",
        "sudo apt upgrade",
        "apt-get -s upgrade | grep -i security",
    ];

    if !security.is_empty() {
        let all: Vec<&Pending> = pending.iter().collect();
        col.push(
            Finding::new(
                Severity::Medium,
                MODULE,
                "UPD-SECURITY",
                format!("{} security update(s) are available ({} updates in total)", security.len(), pending.len()),
            )
            .evidence(evidence(&security) + &if pending.len() > security.len() { format!("\n— plus {} other update(s): see apt list --upgradable", all.len() - security.len()) } else { String::new() })
            .description("Installed packages have newer versions that fix security problems. Until they are installed, known vulnerabilities stay open. Install them with: sudo apt update && sudo apt upgrade (then reboot if a kernel or libc update was included).")
            .verify_all(verify),
        );
    } else if !pending.is_empty() {
        let all: Vec<&Pending> = pending.iter().collect();
        col.push(
            Finding::new(Severity::Low, MODULE, "UPD-AVAILABLE", format!("{} update(s) are available (none marked as security)", pending.len()))
                .evidence(evidence(&all))
                .description("Newer package versions exist. Keeping the system up to date is the best protection: sudo apt update && sudo apt upgrade.")
                .verify_all(verify),
        );
    }

    // How fresh is the information above?
    let stamp = age_days(ctx, "/var/lib/apt/periodic/update-success-stamp").or_else(|| age_days(ctx, "/var/lib/apt/lists"));
    if let Some(days) = stamp.filter(|d| *d >= 7) {
        col.push(
            Finding::new(Severity::Low, MODULE, "UPD-STALE-LISTS", format!("The package lists are {days} days old"))
                .evidence(format!("/var/lib/apt/periodic/update-success-stamp is {days} days old"))
                .description("apt only knows about updates from the last 'apt update', so there may be more updates than shown. Refresh with: sudo apt update.")
                .verify("ls -l --time-style=long-iso /var/lib/apt/periodic/update-success-stamp")
                .verify("sudo apt update"),
        );
    }
    let _ = Duration::from_secs(0);
}

fn check_reboot_required(ctx: &ScanCtx, col: &mut Collector) {
    let flag = ["/run/reboot-required", "/var/run/reboot-required"].into_iter().find(|p| ctx.sys.exists(p));
    let Some(flag) = flag else { return };
    let pkgs = ctx.sys.read_string("/run/reboot-required.pkgs").unwrap_or_default();
    let list: Vec<&str> = pkgs.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
    let important = list.iter().any(|p| p.starts_with("linux-image") || p.starts_with("libc6") || p.starts_with("systemd"));
    col.push(
        Finding::new(
            if important { Severity::Medium } else { Severity::Low },
            MODULE,
            "UPD-REBOOT",
            "A reboot is needed to finish installed updates",
        )
        .evidence(format!("{flag} exists{}", if list.is_empty() { String::new() } else { format!("\npackages: {}", list.join(", ")) }))
        .description("Updates that were already installed (for example a new kernel) only take effect after a reboot, until then the old, possibly vulnerable version is still running.")
        .verify("cat /run/reboot-required.pkgs")
        .verify("uname -r; ls /boot/vmlinuz-*"),
    );
}
