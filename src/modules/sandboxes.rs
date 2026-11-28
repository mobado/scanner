//! Newer ways to stay out of sight (part of `proc_audit`): io_uring in unknown programs, and
//! processes in their own user, network or mount namespace that no known sandbox explains.

use super::common::{clip, is_steam_path, shq};
use super::proc_audit::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::procinfo::ProcInfo;
use std::collections::{BTreeMap, BTreeSet, HashMap};

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
    let installed = ["/usr/", "/opt/", "/snap/", "/app/", "/var/lib/flatpak/", "/lib/"].iter().any(|d| exe.starts_with(d));
    // only the program file's name counts, and never an interpreter's
    installed && p.program_name().is_some_and(|n| SANDBOXES.iter().any(|s| n.starts_with(s)))
}

// ---------------------------------------------------------------- Steam
// Steam lives in a folder the user can write to, so nothing there is trusted outright: what
// belongs to a running Steam client is reported quietly (Low), never hidden.

/// The parts of the Steam Linux Runtime that start the client inside a container.
const STEAM_RUNTIME: [&str; 4] = ["srt-bwrap", "pv-bwrap", "pv-adverb", "pressure-vessel-wrap"];

/// Steam's main program: "steam" in a Steam folder.
fn is_steam_main(p: &ProcInfo) -> bool {
    p.exe_path().is_some_and(|e| is_steam_path(e) && crate::procinfo::basename(e) == "steam")
}

/// The process ids a running Steam client starts from: its main program, and the parts of the
/// runtime container that started it.
pub(crate) fn steam_roots(processes: &[ProcInfo]) -> BTreeSet<u32> {
    let by_pid: HashMap<u32, &ProcInfo> = processes.iter().map(|p| (p.pid, p)).collect();
    let mut roots = BTreeSet::new();
    for main in processes.iter().filter(|p| is_steam_main(p)) {
        roots.insert(main.pid);
        let mut chain = by_pid.get(&main.ppid).copied();
        for _ in 0..8 {
            let Some(parent) = chain else { break };
            if parent.is_program(&STEAM_RUNTIME) {
                roots.insert(parent.pid);
            }
            chain = by_pid.get(&parent.ppid).copied();
        }
    }
    roots
}

/// Was the process started by a running Steam client (or is it one of its roots)?
fn from_steam(p: &ProcInfo, by_pid: &HashMap<u32, &ProcInfo>, roots: &BTreeSet<u32>) -> bool {
    let mut chain = Some(p);
    for _ in 0..12 {
        let Some(current) = chain else { break };
        if roots.contains(&current.pid) {
            return true;
        }
        chain = by_pid.get(&current.ppid).copied();
    }
    false
}

/// Steam's client or its browser, in a Steam folder and started from Steam's main program.
pub(crate) fn is_steam_client(p: &ProcInfo, processes: &[ProcInfo]) -> bool {
    let by_pid: HashMap<u32, &ProcInfo> = processes.iter().map(|q| (q.pid, q)).collect();
    p.uid != 0 && p.exe_path().is_some_and(is_steam_path) && p.is_program(&["steam", "steamwebhelper"]) && from_steam(p, &by_pid, &steam_roots(processes))
}

/// Files that lie beside the program in every Chromium, Electron and CEF app.
const CHROMIUM_FILES: [&str; 5] = ["resources.pak", "chrome_100_percent.pak", "icudtl.dat", "v8_context_snapshot.bin", "snapshot_blob.bin"];

/// The sandbox of an installed Chromium or Electron app, whatever the app is called: its helper
/// processes are started with "--type=zygote", "--type=renderer" and the like. Any program can
/// be given such an option, so its folder also has to hold Chromium's files (Qt keeps those
/// elsewhere and names its helper).
fn is_chromium_sandbox(ctx: &ScanCtx, p: &ProcInfo) -> bool {
    let exe = p.exe_path().unwrap_or("");
    let installed = ["/usr/", "/opt/", "/snap/", "/app/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
    let by_hand = p.candidate_names().iter().any(|n| n == "unshare" || n == "nsenter");
    let folder = exe.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    let chromium = p.is_program(&["QtWebEngineProcess"]) || p.program_name().is_some() && CHROMIUM_FILES.iter().any(|f| ctx.sys.exists(format!("{folder}/{f}")));
    // Chromium rewrites its command line, so the options may be one long word
    installed && !by_hand && chromium && p.cmdline_str().contains(" --type=")
}

/// A packaged user service that systemd started with isolation settings.
fn is_sandboxed_user_service(p: &ProcInfo, parent: Option<&ProcInfo>, cgroup: &str) -> bool {
    let exe = p.exe_path().unwrap_or("");
    let installed = exe.starts_with("/usr/") && !exe.starts_with("/usr/local/");
    let from_systemd = parent.is_some_and(|q| q.is_program(&["systemd"]) && q.exe_path().is_some_and(|e| e.starts_with("/usr/") || e.starts_with("/lib/")));
    let by_hand = p.candidate_names().iter().any(|n| n == "unshare" || n == "nsenter");
    // anyone can start a service of their own, so an interpreter in one explains nothing
    installed && p.program_name().is_some() && from_systemd && !by_hand && cgroup.contains("/user@") && cgroup.trim().ends_with(".service")
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
            if current.pid != 1 && !manager && (is_sandbox(current) || is_chromium_sandbox(ctx, current)) {
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
    let steam = steam_roots(ctx.processes);
    for (spaces, processes) in odd.into_iter().take(10) {
        let strange = processes.iter().any(|p| is_odd_place(ctx, p.exe_path().unwrap_or("")));
        // Steam and its games run in containers of Steam's own runtime
        let of_steam = processes.iter().all(|p| p.uid != 0 && from_steam(p, &by_pid, &steam));
        let severity = if of_steam { Severity::Low } else if strange { Severity::High } else { Severity::Medium };
        let first = processes[0];
        let lines: Vec<String> = processes.iter().take(6).map(|p| format!("PID {} UID {} exe={} cmdline=\"{}\"", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 160))).collect();
        let title = if of_steam { "Steam runs programs in a space of their own" } else { "Programs run in an isolated space of their own" };
        col.push(
            Finding::new(severity, MODULE, "PROC-NAMESPACE", format!("{title}: {}", first.display_name()))
                .evidence(format!("{spaces}\n{}{}", lines.join("\n"), if processes.len() > 6 { format!("\n… and {} more", processes.len() - 6) } else { String::new() }))
                .description(if of_steam {
                    "These were started by your Steam client, which runs itself and its games in containers. Steam's folder can be written by any program of yours, so they are listed: check that the paths are Steam's."
                } else {
                    "These processes have their own user, network or mount namespace, and no known sandbox, container or service explains it. Any user may create such a space on Debian (unshare) to mount things or run a network that others do not see."
                })
                .verify(format!("ls -l /proc/{}/ns", first.pid))
                .verify("lsns")
                .verify(format!("pstree -asp {}", first.pid)),
        );
    }
}
