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

/// Is the security source there, and do the Debian sources point at this release?
fn check_debian_sources(ctx: &ScanCtx, col: &mut Collector) {
    let (sources, _) = super::persistence::apt::read_sources(ctx);
    let debian: Vec<_> = sources
        .iter()
        .filter(|s| super::persistence::apt::host_of(&s.uri).map(|h| h == "debian.org" || h.ends_with(".debian.org")).unwrap_or(false))
        .collect();
    let release = ctx
        .sys
        .read_string("/etc/os-release")
        .ok()
        .and_then(|t| t.lines().find_map(|l| l.strip_prefix("VERSION_CODENAME=").map(|v| v.trim_matches('"').to_string())));
    // mirrors under other names also carry "<release>-security"
    let secured = sources.iter().any(|s| s.suites.split_whitespace().any(|w| w.ends_with("-security") || w.ends_with("/updates")) || s.uri.contains("security.debian.org"));
    if !debian.is_empty() && !secured {
        col.push(
            Finding::new(Severity::Medium, MODULE, "UPD-NO-SECURITY-REPO", "The Debian security updates are not enabled")
                .evidence(debian.iter().map(|s| format!("{} {} {}", s.origin, s.uri, s.suites)).collect::<Vec<_>>().join("\n"))
                .description("No software source provides security updates, so known holes stay open. Add the security source (deb http://security.debian.org/debian-security <release>-security main) or restore it in /etc/apt/sources.list.d.")
                .verify("apt-cache policy | grep -i security")
                .verify("grep -rn security /etc/apt/sources.list /etc/apt/sources.list.d/"),
        );
    }
    const RELEASES: [&str; 8] = ["stretch", "buster", "bullseye", "bookworm", "trixie", "forky", "duke", "sid"];
    let Some(release) = release else { return };
    let Some(current) = RELEASES.iter().position(|r| *r == release) else { return };
    let old: Vec<String> = debian
        .iter()
        .filter(|s| s.suites.split_whitespace().any(|w| RELEASES.iter().position(|r| w.split(['-', '/']).next() == Some(*r)).map(|i| i < current).unwrap_or(false)))
        .map(|s| format!("{} {} {}", s.origin, s.uri, s.suites))
        .collect();
    if !old.is_empty() {
        col.push(
            Finding::new(Severity::Low, MODULE, "UPD-OLD-REPO", format!("Software sources for an older Debian than {release}"))
                .evidence(old.join("\n"))
                .description("Packages from an older release can hold the system back or mix versions. Remove the source if it is left over from an upgrade.")
                .verify("grep -rn . /etc/apt/sources.list /etc/apt/sources.list.d/"),
        );
    }
}

/// Is this package installed according to dpkg's status file?
fn installed(status: &str, package: &str) -> bool {
    status
        .split("\n\n")
        .any(|block| block.lines().any(|l| l == format!("Package: {package}")) && block.lines().any(|l| l == "Status: install ok installed"))
}

/// Processor microcode and firmware updates on real (not virtual) machines.
fn check_firmware(ctx: &ScanCtx, col: &mut Collector) {
    let (Ok(cpu), Ok(status)) = (ctx.sys.read_string("/proc/cpuinfo"), ctx.sys.read_string("/var/lib/dpkg/status")) else { return };
    if cpu.lines().any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "hypervisor")) {
        return;
    }
    let package = if cpu.contains("GenuineIntel") {
        "intel-microcode"
    } else if cpu.contains("AuthenticAMD") {
        "amd64-microcode"
    } else {
        return;
    };
    if !installed(&status, package) {
        col.push(
            Finding::new(Severity::Medium, MODULE, "UPD-MICROCODE", format!("Processor microcode updates are missing: {package}"))
                .evidence(format!("{package} is not installed"))
                .description("The processor gets fixes for security flaws through this package (in Debian's non-free-firmware section). Install it and reboot.")
                .verify(format!("apt-cache policy {package}"))
                .verify("grep -r . /sys/devices/system/cpu/vulnerabilities/"),
        );
    }
    if !ctx.sys.exists("/sys/firmware/efi") {
        return;
    }
    let metadata = ctx.sys.dir_names("/var/lib/fwupd/metadata").into_iter().filter_map(|d| age_days(ctx, &format!("/var/lib/fwupd/metadata/{d}"))).min();
    let problem = if !installed(&status, "fwupd") {
        Some("fwupd is not installed, so firmware (BIOS, SSD, dock) updates are not offered".to_string())
    } else {
        metadata.filter(|days| *days > 90).map(|days| format!("the list of firmware updates is {days} days old"))
    };
    if let Some(problem) = problem {
        col.push(
            Finding::new(Severity::Low, MODULE, "UPD-FIRMWARE", "Firmware updates are not being checked")
                .evidence(problem)
                .description("Firmware flaws are fixed by the maker, often through fwupd. Install it (sudo apt install fwupd) and run fwupdmgr refresh and fwupdmgr get-updates now and then.")
                .verify("fwupdmgr get-updates"),
        );
    }
}

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    check_debian_sources(ctx, col);
    check_firmware(ctx, col);
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
