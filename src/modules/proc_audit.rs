//! proc_audit: running processes and suspicious run paths.

use super::common::{clip, shq};
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::procinfo::ProcInfo;

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

        if cfg.is_temp_path(exe) {
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
    group_restart_needed(col, first_finding);
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
