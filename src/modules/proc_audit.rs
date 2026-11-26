//! proc_audit: running processes and suspicious run paths.

use super::common::{clip, is_appimage_mount, risky_home_place, shq};
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::procinfo::ProcInfo;
use std::collections::BTreeMap;

pub const MODULE: &str = "proc_audit";

fn evidence(p: &ProcInfo) -> String {
    format!(
        "PID {} PPID {} UID {} exe={} cwd={}\ncmdline=\"{}\"",
        p.pid,
        p.ppid,
        p.uid,
        p.exe.as_deref().unwrap_or("?"),
        p.cwd.as_deref().unwrap_or("?"),
        clip(&p.cmdline_str(), 300)
    )
}

fn verify(p: &ProcInfo) -> Vec<String> {
    vec![
        format!("ls -l /proc/{}/exe /proc/{}/cwd", p.pid, p.pid),
        format!("tr '\\0' ' ' < /proc/{}/cmdline; echo", p.pid),
        format!("cat /proc/{}/maps | awk '{{print $6}}' | sort -u", p.pid),
        format!("pstree -asp {}", p.pid),
        format!("sha256sum /proc/{}/exe", p.pid),
    ]
}

const STANDARD_PREFIXES: [&str; 8] = ["/usr/", "/opt/", "/snap/", "/lib/", "/bin/", "/sbin/", "/nix/", "/var/lib/flatpak/"];

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    let cfg = ctx.cfg;
    col.inventory.process_count = ctx.processes.len();
    let own = crate::procinfo::own_exe(ctx.sys);
    let first_finding = col.findings.len();
    let uptime: Option<f64> = ctx.sys.read_string("/proc/uptime").ok().and_then(|t| t.split_whitespace().next().and_then(|v| v.parse().ok()));
    // library path entry → processes that use it
    let mut library_paths: BTreeMap<String, Vec<&ProcInfo>> = BTreeMap::new();

    for p in ctx.processes {
        if p.is_kernel_thread() || p.state == 'Z' || (own.is_some() && p.exe_path() == own.as_deref()) {
            continue;
        }

        // Known malware names
        let names = p.candidate_names();
        if let Some(bad) = names
            .iter()
            .find(|n| cfg.known_malware_names.iter().any(|m| m.eq_ignore_ascii_case(n)))
        {
            col.push(
                Finding::new(Severity::Critical, MODULE, "PROC-MALWARE-NAME", format!("Process with a known malware name: {bad}"))
                    .evidence(evidence(p))
                    .description("The name matches known malware (e.g. crypto miners such as xmrig or kinsing).")
                    .verify_all(verify(p)),
            );
        }

        let Some(exe) = p.exe_path() else { continue };

        for dir in p.ld_library_path.as_deref().unwrap_or("").split(':').filter(|d| !d.is_empty()) {
            // AppImages run from their own mount point in /tmp
            let temp = cfg.is_temp_path(dir) && !dir.starts_with("/tmp/.mount_");
            if temp || dir.starts_with('.') {
                library_paths.entry(dir.to_string()).or_default().push(p);
            }
        }

        if let Some((percent, alive)) = uptime.and_then(|up| average_cpu(ctx, p.pid, up)) {
            // compilers installed by rustup live in the home folder but are installed programs
            let system = STANDARD_PREFIXES.iter().any(|d| exe.starts_with(d)) || exe.contains("/.rustup/toolchains/") || is_appimage_mount(ctx.sys, exe);
            // browsers, compilers, players and indexers are busy by nature (only the installed ones)
            let heavy = system && names.iter().any(|n| cfg.cpu_heavy_programs.contains(n));
            // an installed program has to stay busy much longer than an unknown one
            let needed = if system { f64::from(cfg.high_cpu_minutes) * 60.0 } else { CPU_MIN_SECONDS };
            if !heavy && cfg.high_cpu_percent > 0 && alive >= needed && percent >= f64::from(cfg.high_cpu_percent) {
                col.push(
                    Finding::new(if system { Severity::Low } else { Severity::Medium }, MODULE, "PROC-HIGH-CPU", format!("Process using a lot of CPU: {}", p.display_name()))
                        .evidence(format!("{}\naverage CPU since it started: {percent:.0} % (100 % = one core)", evidence(p)))
                        .description("The process has kept the processor busy for a long time. Games, video encoding and compilers do that; so do crypto miners, which is why unknown programs outside the system folders are worth a look.")
                        .verify_all(verify(p))
                        .verify(format!("ps -o pid,user,%cpu,etime,cmd -p {}", p.pid)),
                );
            }
        }

        if exe.starts_with("/memfd:") {
            col.push(
                Finding::new(Severity::Critical, MODULE, "PROC-MEMFD", format!("Fileless process running from memory: {}", p.display_name()))
                    .evidence(evidence(p))
                    .description("The binary was loaded from a memfd (an anonymous memory area) and does not exist on disk. Fileless malware uses this to avoid file scanning.")
                    .verify_all(verify(p))
                    .verify(format!("cp /proc/{}/exe /root/pid{}-memfd.bin   # keep a copy for analysis", p.pid, p.pid)),
            );
            continue;
        }

        if let Some(place) = risky_home_place(exe, cfg) {
            // programs unpack helpers into caches; downloads and hidden files are less expected
            let severity = if place == "a cache folder" { Severity::Low } else { Severity::Medium };
            col.push(
                Finding::new(severity, MODULE, "PROC-HOME-EXE", format!("Process running from {place}: {exe}"))
                    .evidence(evidence(p))
                    .description("The program was started from a place where programs are not normally installed. Something you downloaded and ran yourself looks like this; so does malware that arrived as a download.")
                    .verify_all(verify(p))
                    .verify(format!("ls -l --time-style=full-iso {}", shq(exe))),
            );
        }

        if is_appimage_mount(ctx.sys, exe) {
            col.push(
                Finding::new(Severity::Low, MODULE, "PROC-APPIMAGE", format!("Program running from an AppImage: {}", p.display_name()))
                    .evidence(evidence(p))
                    .description("AppImages mount themselves under /tmp while they run. That is how they work; check that you started this one.")
                    .verify_all(verify(p))
                    .verify("grep mount_ /proc/mounts"),
            );
        } else if cfg.is_temp_path(exe) {
            let hidden = exe.rsplit('/').next().map(|n| n.starts_with('.')).unwrap_or(false);
            col.push(
                Finding::new(
                    if hidden || exe.contains("/shm/") { Severity::Critical } else { Severity::High },
                    MODULE,
                    "PROC-TMP-EXE",
                    format!("Process running from a temporary directory: {exe}"),
                )
                .evidence(evidence(p))
                .description("Programs in /tmp, /var/tmp, /dev/shm or /run are unusual in production and a common foothold for attackers (hidden names starting with a dot are extra suspicious).")
                .verify_all(verify(p)),
            );
        }

        if p.exe_deleted() {
            let pkg_dir = STANDARD_PREFIXES.iter().any(|d| exe.starts_with(d));
            let sev = if pkg_dir { Severity::Low } else { Severity::High };
            col.push(
                Finding::new(sev, MODULE, "PROC-DELETED", format!("The process binary has been deleted: {exe}"))
                    .evidence(evidence(p))
                    .description(if pkg_dir {
                        "The binary was replaced on disk while the process runs – usually a package upgrade. Restart the service (needrestart / checkrestart shows which)."
                    } else {
                        "The binary was removed from disk while the process runs. Malware often deletes itself after starting to avoid being found."
                    })
                    .verify_all(verify(p))
                    .verify("needrestart -r l   # if needrestart is installed"),
            );
        }

        let preload = p.ld_preload.as_ref().filter(|pre| {
            // skip known harmless libraries (Firefox sandbox, Flatpak etc.)
            !pre.split([':', ' '])
                .filter(|l| !l.is_empty())
                .all(|l| cfg.allowed_ld_preload.iter().any(|a| l.contains(a.as_str())))
        });
        if let Some(pre) = preload {
            let libs: Vec<&str> = pre.split([':', ' ']).filter(|l| !l.is_empty()).collect();
            let risky = libs.iter().any(|l| cfg.is_temp_path(l) || l.starts_with("/home/") || l.starts_with("/dev/shm"));
            let sev = if risky { Severity::Critical } else if p.uid == 0 { Severity::High } else { Severity::Medium };
            col.push(
                Finding::new(sev, MODULE, "PROC-LD-PRELOAD", format!("Process runs with LD_PRELOAD: {}", p.display_name()))
                    .evidence(format!("{}\nLD_PRELOAD={}", evidence(p), pre))
                    .description("LD_PRELOAD loads a library before all others and is used by user-mode rootkits to hide files and processes.")
                    .verify(format!("tr '\\0' '\\n' < /proc/{}/environ | grep LD_PRELOAD", p.pid))
                    .verify(format!("ls -l {}", shq(pre))),
            );
        }

        if let Some(cwd) = &p.cwd {
            if cwd.starts_with("/dev/shm") {
                col.push(
                    Finding::new(Severity::Medium, MODULE, "PROC-SHM-CWD", format!("Process working in /dev/shm: {}", p.display_name()))
                        .evidence(evidence(p))
                        .description("The working directory is in shared memory, which is unusual for normal programs.")
                        .verify_all(verify(p)),
                );
            }
        }

        if p.uid == 0 && !cfg.is_temp_path(exe) && !STANDARD_PREFIXES.iter().any(|d| exe.starts_with(d)) {
            let sev = if exe.starts_with("/home/") || exe.starts_with("/root/") { Severity::Medium } else { Severity::Low };
            col.push(
                Finding::new(sev, MODULE, "PROC-ROOT-ODD-PATH", format!("Root process from an unusual path: {exe}"))
                    .evidence(evidence(p))
                    .description("The process runs as root from a place outside /usr, /opt and similar package directories. Check that the program is known.")
                    .verify_all(verify(p))
                    .verify(format!("dpkg -S {}", shq(exe))),
            );
        }
    }
    for (dir, users) in library_paths {
        let temp = cfg.is_temp_path(&dir);
        let list: Vec<String> = users.iter().take(8).map(|p| format!("PID {} {}", p.pid, p.display_name())).collect();
        col.push(
            Finding::new(if temp { Severity::High } else { Severity::Low }, MODULE, "PROC-LD-LIBRARY-PATH", format!("LD_LIBRARY_PATH points to {}: {dir}", if temp { "a temporary folder" } else { "a relative folder" }))
                .evidence(format!("LD_LIBRARY_PATH contains {dir}\n{} process(es): {}", users.len(), list.join(", ")))
                .description("LD_LIBRARY_PATH makes programs load libraries from this folder first. In a folder where others can write, a malicious library is loaded instead of the real one.")
                .verify(format!("tr '\\0' '\\n' < /proc/{}/environ | grep LD_LIBRARY_PATH", users.first().map(|p| p.pid).unwrap_or(1)))
                .verify(format!("ls -la {}", shq(&dir))),
        );
    }
    group_restart_needed(col, first_finding);
}

/// Processes younger than this are not judged by their CPU use.
const CPU_MIN_SECONDS: f64 = 600.0;

/// Average CPU use of a process since it started, in percent of one core, and its age in
/// seconds. `None` for young processes.
fn average_cpu(ctx: &ScanCtx, pid: u32, uptime: f64) -> Option<(f64, f64)> {
    let stat = ctx.sys.read_string(format!("/proc/{pid}/stat")).ok()?;
    let rest: Vec<&str> = stat[stat.rfind(')')? + 1..].split_whitespace().collect();
    let ticks = |i: usize| rest.get(i).and_then(|v| v.parse::<f64>().ok());
    // fields 14, 15 and 22 of stat; Linux reports them in 1/100 seconds
    let (user, system, started) = (ticks(11)?, ticks(12)?, ticks(19)?);
    let alive = uptime - started / 100.0;
    (alive >= CPU_MIN_SECONDS).then(|| ((user + system) / 100.0 / alive * 100.0, alive))
}

/// After updates many running programs have a replaced binary. Several of those (Low, from
/// package directories) become one finding that says what to restart.
fn group_restart_needed(col: &mut Collector, from: usize) {
    let tail: Vec<Finding> = col.findings.split_off(from);
    let (stale, mut keep): (Vec<Finding>, Vec<Finding>) = tail.into_iter().partition(|f| f.rule == "PROC-DELETED" && f.severity == Severity::Low);
    if stale.len() < 2 {
        keep.extend(stale);
        col.findings.extend(keep);
        return;
    }
    let mut names: Vec<String> = stale
        .iter()
        .map(|f| f.title.rsplit('/').next().unwrap_or("?").trim().to_string())
        .collect();
    names.sort();
    names.dedup();
    let evidence: Vec<String> = stale.iter().map(|f| f.evidence.lines().next().unwrap_or("").to_string()).collect();
    keep.push(
        Finding::new(
            Severity::Low,
            MODULE,
            "PROC-DELETED",
            format!("{} running programs were updated on disk and need a restart: {}", stale.len(), names.join(", ")),
        )
        .evidence(evidence.join("\n"))
        .description("The programs on disk were replaced by a package update while the old versions keep running, so the old (possibly vulnerable) code is still in use. Restart them, or log out and in again, or reboot. Binaries deleted outside the package folders (/usr, /opt) are reported separately and are more suspicious.")
        .verify("needrestart -r l")
        .verify("ls -l /proc/*/exe 2>/dev/null | grep deleted"),
    );
    col.findings.extend(keep);
}
