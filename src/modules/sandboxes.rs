//! Newer ways to stay out of sight (part of `proc_audit`): io_uring in unknown programs,
//! programs that pose as installed ones inside a mount namespace, and processes in their own
//! user, network or mount namespace that no known sandbox explains.

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

// ---------------------------------------------------------------- posing programs

/// Is the program named like one that earns exceptions somewhere: it may read passwords, hold
/// keys, answer for the wallet or read the keyboard?
fn earns_exceptions(name: &str) -> bool {
    let lists: [&[&str]; 5] = [
        &super::secrets::BROWSERS,
        &super::secrets::KEYRINGS,
        &super::persistence::keys::KEY_PROGRAMS,
        &super::desktop_session::input::INPUT_READERS,
        &super::desktop_session::session::UINPUT_USERS,
    ];
    lists.iter().any(|list| list.contains(&name)) || super::wallet::OWNERS.iter().any(|(_, usual)| usual.contains(&name))
}

/// Is the program one that shows another's path: not the installed file, in a namespace made
/// without root, at a path where this computer has a program or by a name that earns exceptions?
/// A Flatpak of the person's own shows paths of its own, so it only counts by such a name.
fn poses(p: &ProcInfo) -> bool {
    let (Some(claimed), Some(mounts)) = (p.claimed(), &p.mounts) else { return false };
    p.forged() && (earns_exceptions(crate::procinfo::basename(claimed)) || mounts.installed_here && !mounts.own_flatpak)
}

/// Programs whose file is not the one their path names, one finding for each namespace and path.
pub(crate) fn check_fake_programs(ctx: &ScanCtx, col: &mut Collector) {
    let by_pid: HashMap<u32, &ProcInfo> = ctx.processes.iter().map(|p| (p.pid, p)).collect();
    let steam = steam_roots(ctx.processes);
    let mut found: BTreeMap<(&str, &str), Vec<&ProcInfo>> = BTreeMap::new();
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread() && poses(p)) {
        let (Some(claimed), Some(mounts)) = (p.claimed(), &p.mounts) else { continue };
        found.entry((claimed, mounts.namespace.as_str())).or_default().push(p);
    }
    for ((claimed, namespace), processes) in found {
        let first = processes[0];
        let sensitive = earns_exceptions(crate::procinfo::basename(claimed));
        let own_flatpak = first.mounts.as_ref().is_some_and(|m| m.own_flatpak);
        // containers and Steam's runtime bring their own copies of ordinary programs
        let of_steam = processes.iter().all(|p| p.uid != 0 && from_steam(p, &by_pid, &steam));
        // only a container root runs counts: a person's own is theirs to fill, and to name
        let contained = processes.iter().all(|p| {
            let cgroup = ctx.sys.read_string(format!("/proc/{}/cgroup", p.pid)).unwrap_or_default();
            roots_cgroup(&cgroup) && ["libpod", "docker", "/lxc", "/machine.slice/"].iter().any(|m| cgroup.contains(m))
        });
        let (severity, title) = if own_flatpak {
            (Severity::Medium, format!("A Flatpak installed for one person runs its own {claimed}"))
        } else if !sensitive && (of_steam || contained) {
            (Severity::Low, format!("A container or Steam runs its own program as {claimed}"))
        } else {
            (Severity::High, format!("A program file pretends to be {claimed}"))
        };
        let lines: Vec<String> = processes
            .iter()
            .take(6)
            .map(|p| format!("PID {} UID {} exe={} cmdline=\"{}\"", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 160)))
            .collect();
        col.push(
            Finding::new(severity, MODULE, "PROC-FAKE-PROGRAM", title)
                .evidence(format!(
                    "shows its program as {claimed}, but the file that runs is another one\nmount namespace {namespace}\n{}{}",
                    lines.join("\n"),
                    if processes.len() > 6 { format!("\n… and {} more", processes.len() - 6) } else { String::new() }
                ))
                .description("These processes have a mount namespace of their own in which another file lies at that path, so they look like that program to anyone who reads the path. Any program of yours can arrange this without root, with bwrap or unshare, to be mistaken for a browser, a key program or a system tool. The scanner compares the real files and gives such a program no exception. Containers (podman, docker), Steam and Flatpak bring files of their own: if you did not start such a thing, treat this as hostile.")
                .verify(format!("stat -L -c '%d:%i %U %n' /proc/{}/exe {}", first.pid, shq(claimed)))
                .verify(format!("sha256sum /proc/{}/exe", first.pid))
                .verify(format!("pstree -asp {}", first.pid)),
        );
    }
}

// ---------------------------------------------------------------- Steam
// Steam lives in a folder the user can write to, so nothing there is trusted outright: what
// belongs to a running Steam client is reported quietly (Low), never hidden.

/// The parts of the Steam Linux Runtime that start the client inside a container.
const STEAM_RUNTIME: [&str; 4] = ["srt-bwrap", "pv-bwrap", "pv-adverb", "pressure-vessel-wrap"];

/// Steam's main program: "steam" in a Steam folder.
fn is_steam_main(p: &ProcInfo) -> bool {
    p.claimed().is_none() && p.exe_path().is_some_and(|e| is_steam_path(e) && crate::procinfo::basename(e) == "steam")
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

/// An installed program that the person's systemd started, as it starts packaged services with
/// isolation settings. Anyone can have it start one, so this only makes the finding quieter.
fn is_started_by_user_systemd(p: &ProcInfo, parent: Option<&ProcInfo>) -> bool {
    let exe = p.exe_path().unwrap_or("");
    let installed = exe.starts_with("/usr/") && !exe.starts_with("/usr/local/");
    let from_systemd = parent.is_some_and(|q| q.is_program(&["systemd"]) && q.exe_path().is_some_and(|e| e.starts_with("/usr/") || e.starts_with("/lib/")));
    let by_hand = p.candidate_names().iter().any(|n| n == "unshare" || n == "nsenter");
    // an interpreter in a service explains nothing at all
    installed && p.program_name().is_some() && from_systemd && !by_hand
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

/// Could only root have chosen this control group's name? Under their own `user@….service` a
/// person creates and names groups as they like (`systemd-run --user --unit=docker-x`), and the
/// job runners' groups hold whatever people schedule.
fn roots_cgroup(cgroup: &str) -> bool {
    !["/user@", "/cron.service", "/atd.service"].iter().any(|theirs| cgroup.contains(theirs))
}

/// Does root's systemd or a container engine manage this control group?
pub fn managed_cgroup(cgroup: &str) -> bool {
    roots_cgroup(cgroup) && ["/system.slice/", "/machine.slice/", "docker", "libpod", "/lxc", "snap.", "kubepods", "/init.scope"].iter().any(|m| cgroup.contains(m))
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
    // processes only listed quietly: what the person's systemd started
    let mut services: BTreeSet<u32> = BTreeSet::new();
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
        let strange = is_odd_place(ctx, exe) || poses(p);
        let only_mounts = differing.iter().all(|(k, _)| *k == "mnt");
        if only_mounts && !strange {
            continue;
        }
        let mut ancestors = Vec::new();
        let mut chain = Some(p);
        for _ in 0..8 {
            let Some(current) = chain else { break };
            ancestors.push(current);
            chain = by_pid.get(&current.ppid).copied();
        }
        // anyone can start bubblewrap: it explains that there is a namespace, not what runs in
        // it, so a program from an odd place or one posing as another is still looked at
        let in_bubblewrap = strange && ancestors.iter().any(|a| a.pid != p.pid && a.is_program(&["bwrap"]));
        // systemd (the system's and each user's) is above every program, so as an ancestor it
        // explains nothing
        let explained = ancestors.iter().any(|current| {
            let manager = current.pid != p.pid && current.candidate_names().iter().any(|n| n == "systemd");
            current.pid != 1 && !manager && (is_sandbox(current) || is_chromium_sandbox(ctx, current))
        });
        let cgroup = ctx.sys.read_string(format!("/proc/{}/cgroup", p.pid)).unwrap_or_default();
        if !in_bubblewrap && (explained || managed_cgroup(&cgroup)) {
            continue;
        }
        if !strange && is_started_by_user_systemd(p, by_pid.get(&p.ppid).copied()) {
            services.insert(p.pid);
        }
        let key = differing.iter().map(|(_, v)| v.clone()).collect::<Vec<_>>().join(" ");
        odd.entry(key).or_default().push(p);
    }
    let steam = steam_roots(ctx.processes);
    let mut judged: Vec<(Severity, bool, String, Vec<&ProcInfo>)> = odd
        .into_iter()
        .map(|(spaces, processes)| {
            let strange = processes.iter().any(|p| is_odd_place(ctx, p.exe_path().unwrap_or("")) || poses(p));
            // Steam and its games run in containers of Steam's own runtime
            let of_steam = processes.iter().all(|p| p.uid != 0 && from_steam(p, &by_pid, &steam));
            // programs that are files of a Flatpak installed for the whole system
            let of_flatpak = processes.iter().all(|p| p.mounts.as_ref().is_some_and(|m| m.system_flatpak));
            let of_services = processes.iter().all(|p| services.contains(&p.pid));
            let severity = if of_steam || of_flatpak || of_services { Severity::Low } else if strange { Severity::High } else { Severity::Medium };
            (severity, of_steam, spaces, processes)
        })
        .collect();
    // the worst first: many harmless-looking spaces must not push one out of the list
    judged.sort_by(|a, b| b.0.cmp(&a.0));
    if judged.len() > 10 {
        col.note(format!("Programs in spaces of their own: {} more spaces were found than the 10 listed", judged.len() - 10));
    }
    for (severity, of_steam, spaces, processes) in judged.into_iter().take(10) {
        let first = processes[0];
        let lines: Vec<String> = processes.iter().take(6).map(|p| format!("PID {} UID {} exe={} cmdline=\"{}\"", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 160))).collect();
        let title = if of_steam { "Steam runs programs in a space of their own" } else { "Programs run in an isolated space of their own" };
        col.push(
            Finding::new(severity, MODULE, "PROC-NAMESPACE", format!("{title}: {}", first.display_name()))
                .evidence(format!("{spaces}\n{}{}", lines.join("\n"), if processes.len() > 6 { format!("\n… and {} more", processes.len() - 6) } else { String::new() }))
                .description(if of_steam {
                    "These were started by your Steam client, which runs itself and its games in containers. Steam's folder can be written by any program of yours, so they are listed: check that the paths are Steam's."
                } else {
                    "These processes have their own user, network or mount namespace, and no known sandbox, container or service explains what runs in it. Any user may create such a space on Debian (unshare, bwrap) to mount things or run a network that others do not see."
                })
                .verify(format!("ls -l /proc/{}/ns", first.pid))
                .verify("lsns")
                .verify(format!("pstree -asp {}", first.pid)),
        );
    }
}
