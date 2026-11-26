//! Newer ways to stay out of sight (part of `proc_audit`): io_uring in unknown programs, and
//! processes in their own user, network or mount namespace that no known sandbox explains.

use super::common::{clip, shq};
use super::proc_audit::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::procinfo::ProcInfo;
use std::collections::{BTreeMap, HashMap};

/// Programs that isolate themselves or others as part of their job (matched as prefixes for
/// families like `systemd-` and `containerd-`).
const SANDBOXES: [&str; 40] = [
    "systemd", "bwrap", "flatpak", "xdg-", "chrome", "chromium", "brave", "firefox", "thunderbird", "msedge", "vivaldi",
    "opera", "electron", "code", "codium", "slack", "discord", "Discord", "signal-desktop", "spotify", "steam", "pressure-vessel",
    "docker", "containerd", "podman", "conmon", "runc", "crun", "snap", "lxc", "lxd", "incus", "libvirt", "qemu", "waydroid",
    "firejail", "evince", "glycin", "tracker", "localsearch",
];

fn is_sandbox(p: &ProcInfo) -> bool {
    let exe = p.exe_path().unwrap_or("");
    // a copy in a home or temporary folder is not the sandbox its name claims
    let installed = exe.is_empty() || ["/usr/", "/opt/", "/snap/", "/app/", "/var/lib/flatpak/", "/lib/"].iter().any(|d| exe.starts_with(d)) || exe.contains("/.local/share/Steam/");
    installed && p.candidate_names().iter().any(|n| SANDBOXES.iter().any(|s| n.starts_with(s)))
}

/// The sandbox of an installed Chromium or Electron app, whatever the app is called: its helper
/// processes are started with "--type=zygote", "--type=renderer" and the like.
fn is_chromium_sandbox(p: &ProcInfo) -> bool {
    let exe = p.exe_path().unwrap_or("");
    let installed = ["/usr/", "/opt/", "/snap/", "/app/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
    let by_hand = p.candidate_names().iter().any(|n| n == "unshare" || n == "nsenter");
    // Chromium rewrites its command line, so the options may be one long word
    installed && !by_hand && p.cmdline_str().contains(" --type=")
}

/// A packaged user service that systemd started with isolation settings.
fn is_sandboxed_user_service(p: &ProcInfo, parent: Option<&ProcInfo>, cgroup: &str) -> bool {
    let exe = p.exe_path().unwrap_or("");
    let installed = exe.starts_with("/usr/") && !exe.starts_with("/usr/local/");
    let from_systemd = parent.map(|q| q.candidate_names().iter().any(|n| n == "systemd")).unwrap_or(false);
    let by_hand = p.candidate_names().iter().any(|n| n == "unshare" || n == "nsenter");
    installed && from_systemd && !by_hand && cgroup.contains("/user@") && cgroup.trim().ends_with(".service")
}

fn is_odd_place(ctx: &ScanCtx, exe: &str) -> bool {
    (ctx.cfg.is_temp_path(exe) && !exe.starts_with("/tmp/.mount_")) || exe.starts_with("/home/") || exe.starts_with("/root/") || exe.starts_with("/memfd:")
}

pub(crate) fn check_io_uring(ctx: &ScanCtx, col: &mut Collector) {
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread()) {
        let exe = p.exe_path().unwrap_or("");
        let installed = ["/usr/", "/lib/", "/bin/", "/sbin/", "/snap/", "/app/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
        if installed || exe.is_empty() {
            continue;
        }
        let uses = ctx.sys.dir_names(format!("/proc/{}/fd", p.pid)).iter().any(|fd| ctx.sys.read_link(format!("/proc/{}/fd/{fd}", p.pid)).map(|t| t.contains("[io_uring]")).unwrap_or(false));
        if !uses {
            continue;
        }
        let severity = if ctx.cfg.is_temp_path(exe) || exe.starts_with("/memfd:") { Severity::High } else if exe.starts_with("/opt/") { Severity::Low } else { Severity::Medium };
        col.push(
            Finding::new(severity, MODULE, "PROC-IO-URING", format!("A program outside the system folders uses io_uring: {}", p.display_name()))
                .evidence(format!("PID {} UID {} exe={}\ncmdline=\"{}\"\nholds anon_inode:[io_uring]", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 300)))
                .description("io_uring does file and network work without the usual system calls, so monitoring tools may not see it. Databases and modern runtimes use it; some new rootkits do too. Check that you know this program.")
                .verify(format!("ls -l /proc/{}/fd | grep io_uring", p.pid))
                .verify(format!("sha256sum /proc/{}/exe", p.pid))
                .verify(format!("ls -l {}", shq(exe))),
        );
    }
}

/// Does systemd, a container engine or an app sandbox manage this control group?
pub fn managed_cgroup(cgroup: &str) -> bool {
    ["/system.slice/", "/machine.slice/", "docker", "libpod", "/lxc", "snap.", "app-flatpak-", "kubepods", "/init.scope"].iter().any(|m| cgroup.contains(m))
}

pub(crate) fn check_namespaces(ctx: &ScanCtx, col: &mut Collector) {
    let space = |who: &str, kind: &str| ctx.sys.read_link(format!("/proc/{who}/ns/{kind}"));
    // the first process shows the host's namespaces; without root, our own do
    let host: Vec<(&str, String)> = ["user", "net", "mnt"].iter().filter_map(|k| Some((*k, space("1", k).or_else(|| space("self", k))?))).collect();
    if host.is_empty() {
        return;
    }
    let by_pid: HashMap<u32, &ProcInfo> = ctx.processes.iter().map(|p| (p.pid, p)).collect();
    // the namespaces that differ → processes
    let mut odd: BTreeMap<String, Vec<&ProcInfo>> = BTreeMap::new();
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread() && p.pid != 1) {
        let differing: Vec<(&str, String)> = host
            .iter()
            .filter_map(|(kind, base)| space(&p.pid.to_string(), kind).filter(|v| v != base).map(|v| (*kind, v)))
            .collect();
        if differing.is_empty() {
            continue;
        }
        let exe = p.exe_path().unwrap_or("");
        // services and desktops make private mounts all the time
        let only_mounts = differing.iter().all(|(k, _)| *k == "mnt");
        if only_mounts && !is_odd_place(ctx, exe) {
            continue;
        }
        let mut chain = Some(p);
        let mut explained = false;
        for _ in 0..8 {
            let Some(current) = chain else { break };
            // systemd (the system's and each user's) is above every program, so as an ancestor
            // it explains nothing
            let manager = current.pid != p.pid && current.candidate_names().iter().any(|n| n == "systemd");
            if current.pid != 1 && !manager && (is_sandbox(current) || is_chromium_sandbox(current)) {
                explained = true;
                break;
            }
            chain = by_pid.get(&current.ppid).copied();
        }
        let cgroup = ctx.sys.read_string(format!("/proc/{}/cgroup", p.pid)).unwrap_or_default();
        if explained || managed_cgroup(&cgroup) || is_sandboxed_user_service(p, by_pid.get(&p.ppid).copied(), &cgroup) {
            continue;
        }
        let key = differing.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>().join(" ");
        odd.entry(key).or_default().push(p);
    }
    for (spaces, processes) in odd.into_iter().take(10) {
        let strange = processes.iter().any(|p| is_odd_place(ctx, p.exe_path().unwrap_or("")));
        let first = processes[0];
        let lines: Vec<String> = processes.iter().take(6).map(|p| format!("PID {} UID {} exe={} cmdline=\"{}\"", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 160))).collect();
        col.push(
            Finding::new(if strange { Severity::High } else { Severity::Medium }, MODULE, "PROC-NAMESPACE", format!("Programs run in an isolated space of their own: {}", first.display_name()))
                .evidence(format!("{spaces}\n{}{}", lines.join("\n"), if processes.len() > 6 { format!("\n… and {} more", processes.len() - 6) } else { String::new() }))
                .description("These processes have their own user, network or mount namespace, and no known sandbox, container or service explains it. Any user may create such a space on Debian (unshare) to mount things or run a network that others do not see.")
                .verify(format!("ls -l /proc/{}/ns", first.pid))
                .verify("lsns")
                .verify(format!("pstree -asp {}", first.pid)),
        );
    }
}
