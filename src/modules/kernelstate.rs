//! Kernel state beyond modules (part of `kernel`): eBPF programs, why the kernel is marked as
//! "tainted", Secure Boot and lockdown, and the firmware's boot entries. Everything is read
//! from /proc, /sys and, when installed, `bpftool` (list commands only).

use super::kernel::{parse_modules, MODULE};
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, shq};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------- eBPF

/// Program types that can watch or change system calls and network traffic.
const WATCHING: [(u64, &str); 11] = [
    (2, "kprobe"), (3, "sched_cls"), (4, "sched_act"), (5, "tracepoint"), (6, "xdp"), (7, "perf_event"),
    (17, "raw_tracepoint"), (24, "raw_tracepoint_writable"), (26, "tracing"), (29, "lsm"), (31, "syscall"),
];

/// Programs that load eBPF as part of their normal work.
const KNOWN_LOADERS: [&str; 17] = [
    "systemd", "systemd-network", "NetworkManager", "tailscaled", "dockerd", "containerd", "cilium-agent", "falco",
    "tetragon", "osqueryd", "firewalld", "snapd", "bpftrace", "bpftool", "below", "scx_loader", "gamemoded",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BpfProgram {
    pub id: u64,
    pub kind: String,
    pub name: String,
    /// Names of the processes that hold it (empty when only pinned or attached).
    pub holders: Vec<String>,
}

impl BpfProgram {
    /// systemd's own filters, loaded for services.
    fn is_systemd_filter(&self) -> bool {
        (self.name.starts_with("sd_") || self.name.starts_with("restrict_")) && self.holders.iter().all(|h| h == "systemd")
    }

    fn is_expected(&self) -> bool {
        !self.holders.is_empty() && self.holders.iter().all(|h| KNOWN_LOADERS.contains(&h.as_str()))
    }
}

/// The watching programs in the output of `bpftool -j prog show`.
pub fn parse_bpftool(json: &str) -> Vec<BpfProgram> {
    let Ok(Value::Array(list)) = serde_json::from_str::<Value>(json) else { return Vec::new() };
    list.iter()
        .filter_map(|p| {
            let kind = p.get("type")?.as_str()?.to_string();
            if !WATCHING.iter().any(|(_, k)| *k == kind) {
                return None;
            }
            let holders = p.get("pids").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.get("comm")?.as_str().map(String::from)).collect()).unwrap_or_default();
            Some(BpfProgram { id: p.get("id")?.as_u64()?, kind, name: p.get("name").and_then(Value::as_str).unwrap_or("").to_string(), holders })
        })
        .collect()
}

/// The watching programs that processes hold open, from /proc/<pid>/fdinfo.
fn programs_from_proc(ctx: &ScanCtx) -> Vec<BpfProgram> {
    let mut found: BTreeMap<u64, BpfProgram> = BTreeMap::new();
    for p in ctx.processes {
        for fd in ctx.sys.dir_names(format!("/proc/{}/fd", p.pid)) {
            if ctx.sys.read_link(format!("/proc/{}/fd/{fd}", p.pid)).as_deref() != Some("anon_inode:bpf-prog") {
                continue;
            }
            let Ok(info) = ctx.sys.read_string(format!("/proc/{}/fdinfo/{fd}", p.pid)) else { continue };
            let field = |key: &str| info.lines().find_map(|l| l.strip_prefix(key)?.trim_start_matches(':').trim().parse::<u64>().ok());
            let (Some(kind), Some(id)) = (field("prog_type"), field("prog_id")) else { continue };
            let Some((_, kind)) = WATCHING.iter().find(|(n, _)| *n == kind) else { continue };
            let entry = found.entry(id).or_insert_with(|| BpfProgram { id, kind: kind.to_string(), name: String::new(), holders: Vec::new() });
            if !entry.holders.contains(&p.comm) {
                entry.holders.push(p.comm.clone());
            }
        }
    }
    found.into_values().collect()
}

pub fn judge_bpf(programs: &[BpfProgram], network: &[String], col: &mut Collector) {
    let listed: Vec<&BpfProgram> = programs.iter().filter(|p| !p.is_systemd_filter()).collect();
    if listed.is_empty() && network.is_empty() {
        return;
    }
    let unexpected = listed.iter().filter(|p| !p.is_expected()).count();
    let mut lines: Vec<String> = listed
        .iter()
        .map(|p| format!("id {} {} {} held by {}{}", p.id, p.kind, p.name, if p.holders.is_empty() { "no process".to_string() } else { p.holders.join(", ") }, if p.is_expected() { "" } else { "  ← unfamiliar" }))
        .collect();
    lines.sort_by_key(|l| !l.ends_with("unfamiliar"));
    lines.truncate(25);
    lines.extend(network.iter().take(10).map(|n| format!("attached to the network: {n}")));
    col.push(
        Finding::new(if unexpected > 0 { Severity::Medium } else { Severity::Low }, MODULE, "KERN-EBPF", "eBPF programs that can watch system calls or network traffic")
            .evidence(clip(&lines.join("\n"), 1800))
            .description("eBPF programs run inside the kernel. Monitoring tools, VPNs and containers use them; modern rootkits do too, to hide files and traffic without a kernel module. Check the unfamiliar ones.")
            .verify("bpftool prog show   # package bpftool")
            .verify("bpftool net show"),
    );
}

fn check_ebpf(ctx: &ScanCtx, col: &mut Collector) {
    let mut programs = Vec::new();
    let mut network = Vec::new();
    let bpftool = (ctx.sys.is_live() && ctx.privileged).then(|| crate::external_tools::find_binary("bpftool")).flatten();
    match &bpftool {
        Some(tool) => {
            let run = |args: &[&str]| crate::external_tools::run_capture(tool, args, 30).ok().filter(|o| o.status == Some(0)).map(|o| o.stdout);
            match run(&["-j", "prog", "show"]) {
                Some(json) => programs = parse_bpftool(&json),
                None => col.note("bpftool could not list the eBPF programs"),
            }
            if let Some(Value::Array(list)) = run(&["-j", "net", "show"]).and_then(|j| serde_json::from_str(&j).ok()) {
                for part in &list {
                    for key in ["xdp", "tc", "flow_dissector", "netfilter"] {
                        for a in part.get(key).and_then(Value::as_array).into_iter().flatten() {
                            network.push(format!("{key} {a}"));
                        }
                    }
                }
            }
        }
        None => {
            programs = programs_from_proc(ctx);
            if ctx.sys.is_live() {
                col.note("eBPF: only programs that a process holds open were checked (run as root with the bpftool package for all of them)");
            }
        }
    }
    judge_bpf(&programs, &network, col);
    // objects "pinned" here stay loaded without any process
    let mut pinned = Vec::new();
    for entry in walkdir::WalkDir::new(ctx.sys.path("/sys/fs/bpf")).max_depth(4).into_iter().filter_map(|e| e.ok()).filter(|e| !e.file_type().is_dir()).take(100) {
        pinned.push(ctx.sys.display(entry.path()));
    }
    if !pinned.is_empty() {
        pinned.sort();
        col.push(
            Finding::new(Severity::Low, MODULE, "KERN-EBPF-PINNED", "Pinned eBPF objects")
                .evidence(clip(&pinned.join("\n"), 900))
                .description("Pinned eBPF programs and maps stay in the kernel after their program exits. Check that you know which software put them there.")
                .verify("ls -laR /sys/fs/bpf"),
        );
    }
}

// ---------------------------------------------------------------- taint

/// (bit, letter, meaning) of /proc/sys/kernel/tainted.
const TAINT: [(u32, char, &str); 19] = [
    (0, 'P', "a proprietary module was loaded"), (1, 'F', "a module was loaded by force"), (2, 'S', "the processor runs outside its specification"),
    (3, 'R', "a module was removed by force"), (4, 'M', "the processor reported a hardware error"), (5, 'B', "a bad memory page was found"),
    (6, 'U', "a program asked for the mark"), (7, 'D', "the kernel crashed (oops)"), (8, 'A', "a firmware table was replaced"),
    (9, 'W', "the kernel issued a warning"), (10, 'C', "an unfinished (staging) driver was loaded"), (11, 'I', "a firmware bug is worked around"),
    (12, 'O', "a module built outside the kernel was loaded"), (13, 'E', "an unsigned module was loaded"), (14, 'L', "the processor was stuck for a while"),
    (15, 'K', "the kernel was patched while running"), (16, 'X', "a distribution-specific mark"), (17, 'T', "built with randomised structures"),
    (18, 'N', "a test was run in the kernel"),
];

/// The meanings of a taint number: (letter, meaning).
pub fn decode_taint(value: u64) -> Vec<(char, &'static str)> {
    TAINT.iter().filter(|(bit, _, _)| value & (1u64 << bit) != 0).map(|(_, letter, text)| (*letter, *text)).collect()
}

fn check_taint(ctx: &ScanCtx, col: &mut Collector) {
    let Some(value) = ctx.sys.read_string("/proc/sys/kernel/tainted").ok().and_then(|v| v.trim().parse::<u64>().ok()) else { return };
    let marks = decode_taint(value);
    if marks.is_empty() {
        return;
    }
    let loaded: BTreeSet<char> = ctx.sys.read_string("/proc/modules").map(|t| parse_modules(&t).values().flat_map(|v| v.chars().collect::<Vec<_>>()).collect()).unwrap_or_default();
    // a module mark that no loaded module carries: the module is gone again
    let gone: Vec<char> = marks.iter().map(|m| m.0).filter(|l| "PFOE".contains(*l) && !loaded.contains(l)).collect();
    let forced_removal = marks.iter().any(|m| m.0 == 'R');
    let severity = if forced_removal { Severity::High } else if !gone.is_empty() { Severity::Medium } else { Severity::Low };
    let mut lines: Vec<String> = marks.iter().map(|(l, t)| format!("{l}: {t}{}", if gone.contains(l) { " – no module loaded now carries this mark" } else { "" })).collect();
    lines.insert(0, format!("/proc/sys/kernel/tainted = {value}"));
    col.push(
        Finding::new(severity, MODULE, "KERN-TAINTED", "The kernel is marked as tainted")
            .evidence(lines.join("\n"))
            .description("The kernel remembers until the next reboot that something unusual happened. Vendor drivers (graphics, VirtualBox) and warnings are common; a module that was loaded and then removed, or removed by force, is what a rootkit installer leaves behind.")
            .verify("cat /proc/sys/kernel/tainted")
            .verify("journalctl -k | grep -iE 'taint|module verification'"),
    );
}

// ---------------------------------------------------------------- Secure Boot, lockdown, boot entries

const EFI_DIR: &str = "/sys/firmware/efi/efivars";
const EFI_GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

fn utf16_until_nul(data: &[u8]) -> (String, usize) {
    let mut units = Vec::new();
    let mut used = 0;
    for pair in data.chunks_exact(2) {
        used += 2;
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    (String::from_utf16_lossy(&units), used)
}

/// (description, file path) of an EFI boot entry variable (with the 4 attribute bytes that
/// efivarfs puts first).
pub fn parse_boot_entry(data: &[u8]) -> Option<(String, String)> {
    let option = data.get(4..)?;
    let length = u16::from_le_bytes(option.get(4..6)?.try_into().ok()?) as usize;
    let (description, used) = utf16_until_nul(option.get(6..)?);
    let mut devices = option.get(6 + used..)?;
    devices = &devices[..length.min(devices.len())];
    let mut path = String::new();
    // a list of nodes: type, subtype, length
    while devices.len() >= 4 {
        let size = u16::from_le_bytes([devices[2], devices[3]]) as usize;
        if size < 4 || size > devices.len() || devices[0] == 0x7f {
            break;
        }
        if devices[0] == 4 && devices[1] == 4 {
            path.push_str(&utf16_until_nul(&devices[4..size]).0);
        }
        devices = &devices[size..];
    }
    Some((description, path))
}

fn efi_variable(ctx: &ScanCtx, name: &str) -> Option<Vec<u8>> {
    ctx.sys.read_bytes(format!("{EFI_DIR}/{name}-{EFI_GLOBAL}")).ok()
}

/// "none [integrity] confidentiality" → "integrity"
fn selected(text: &str) -> Option<String> {
    Some(text.split_once('[')?.1.split_once(']')?.0.to_string())
}

fn check_boot(ctx: &ScanCtx, col: &mut Collector) {
    let lockdown = ctx.sys.read_string("/sys/kernel/security/lockdown").ok().and_then(|t| selected(&t));
    if let Some(mode) = &lockdown {
        col.inventory.boot.insert("lockdown".into(), mode.clone());
    }
    let secure = efi_variable(ctx, "SecureBoot").and_then(|d| d.get(4).map(|v| *v == 1));
    if let Some(on) = secure {
        col.inventory.boot.insert("secure_boot".into(), if on { "on" } else { "off" }.into());
        if !on || lockdown.as_deref() == Some("none") {
            let value = |path: &str| ctx.sys.read_string(path).map(|v| v.trim().to_string()).unwrap_or_else(|_| "?".into());
            col.push(
                Finding::new(if on { Severity::Medium } else { Severity::Low }, MODULE, "KERN-SECUREBOOT", if on { "Secure Boot is on but the kernel is not locked down" } else { "Secure Boot is off" })
                    .evidence(format!(
                        "Secure Boot: {}\nlockdown: {}\nunsigned modules refused (sig_enforce): {}\nkernel.modules_disabled: {}",
                        if on { "on" } else { "off" },
                        lockdown.as_deref().unwrap_or("?"),
                        value("/sys/module/module/parameters/sig_enforce"),
                        value("/proc/sys/kernel/modules_disabled")
                    ))
                    .description("Without Secure Boot and lockdown, anyone with root can load unsigned code into the kernel and change what starts at boot. Many people switch it off for drivers or dual boot; if you did not, switch it on again in the firmware setup.")
                    .verify("mokutil --sb-state   # package mokutil")
                    .verify("cat /sys/kernel/security/lockdown"),
            );
        }
    }
    if let Some(order) = efi_variable(ctx, "BootOrder") {
        let list: Vec<String> = order.get(4..).unwrap_or_default().chunks_exact(2).map(|c| format!("{:04X}", u16::from_le_bytes([c[0], c[1]]))).collect();
        col.inventory.boot.insert("boot_order".into(), list.join(","));
    }
    let mut unfamiliar = Vec::new();
    for name in ctx.sys.dir_names(EFI_DIR) {
        let Some(id) = name.strip_suffix(&format!("-{EFI_GLOBAL}")).and_then(|n| n.strip_prefix("Boot")) else { continue };
        if id.len() != 4 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let Some((description, path)) = efi_variable(ctx, &format!("Boot{id}")).and_then(|d| parse_boot_entry(&d)) else { continue };
        col.inventory.boot.insert(format!("boot_entry {id}"), format!("{description} | {path}"));
        let lower = path.to_lowercase();
        let known = ["\\efi\\debian\\", "\\efi\\boot\\", "\\efi\\microsoft\\"].iter().any(|p| lower.starts_with(p));
        if !path.is_empty() && !known {
            unfamiliar.push(format!("Boot{id}: {description} → {path}"));
        }
    }
    if !unfamiliar.is_empty() {
        col.push(
            Finding::new(Severity::Low, MODULE, "KERN-BOOT-ENTRY", "Firmware boot entries that start another loader")
                .evidence(clip(&unfamiliar.join("\n"), 900))
                .description("These entries start something other than Debian's, Windows' or the standard loader. Other operating systems and vendor tools add such entries; the baseline reports when one appears or changes.")
                .verify("efibootmgr -v   # package efibootmgr")
                .verify(format!("ls -l {}", shq(EFI_DIR))),
        );
    }
}

// ---------------------------------------------------------------- AppArmor and SELinux

/// (profiles that enforce, names of profiles that only complain) from
/// /sys/kernel/security/apparmor/profiles ("name (enforce)").
pub fn apparmor_profiles(text: &str) -> (usize, Vec<String>) {
    let mut enforcing = 0;
    let mut complaining = Vec::new();
    for line in text.lines() {
        match line.trim().rsplit_once(" (") {
            Some((_, "enforce)")) => enforcing += 1,
            Some((name, "complain)")) => complaining.push(name.to_string()),
            _ => {}
        }
    }
    (enforcing, complaining)
}

fn check_security_module(ctx: &ScanCtx, col: &mut Collector) {
    if let Ok(enforce) = ctx.sys.read_string("/sys/fs/selinux/enforce") {
        let on = enforce.trim() == "1";
        col.inventory.boot.insert("selinux".into(), if on { "enforcing" } else { "permissive" }.into());
        if !on {
            col.push(
                Finding::new(Severity::Medium, MODULE, "KERN-SELINUX", "SELinux only logs and does not protect")
                    .evidence("/sys/fs/selinux/enforce = 0")
                    .description("In permissive mode SELinux reports violations but allows them. Switch to enforcing if the machine relies on SELinux.")
                    .verify("getenforce; sestatus"),
            );
        }
        return;
    }
    let enabled = ctx.sys.read_string("/sys/module/apparmor/parameters/enabled").map(|v| v.trim() == "Y").ok();
    // a machine without AppArmor's files at all is not a Debian with AppArmor switched off
    if enabled.is_none() && !ctx.sys.exists("/etc/apparmor.d") {
        return;
    }
    let enabled = enabled.unwrap_or(false);
    col.inventory.boot.insert("apparmor".into(), if enabled { "on" } else { "off" }.into());
    if !enabled {
        col.push(
            Finding::new(Severity::Medium, MODULE, "KERN-APPARMOR-OFF", "AppArmor is not active")
                .evidence("/sys/module/apparmor/parameters/enabled is not Y")
                .description("Debian uses AppArmor to confine programs such as the browser's helpers, the print server and many services. It is on by default; find out why it is off (a kernel start option, or removed packages).")
                .verify("cat /sys/module/apparmor/parameters/enabled; cat /proc/cmdline")
                .verify("aa-status   # package apparmor"),
        );
        return;
    }
    let mut weak = Vec::new();
    match ctx.sys.read_string("/sys/kernel/security/apparmor/profiles") {
        Ok(text) => {
            let (enforcing, complaining) = apparmor_profiles(&text);
            if enforcing == 0 {
                weak.push("no profile is enforced".to_string());
            }
            weak.extend(complaining.into_iter().map(|p| format!("only complains: {p}")));
        }
        Err(_) => col.note("AppArmor is active; its profiles can only be listed as root"),
    }
    weak.extend(ctx.sys.dir_names("/etc/apparmor.d/disable").into_iter().map(|p| format!("switched off: {p}")));
    if !weak.is_empty() {
        col.push(
            Finding::new(Severity::Low, MODULE, "KERN-APPARMOR-PROFILES", "AppArmor profiles that do not protect")
                .evidence(clip(&weak.join("\n"), 1200))
                .description("A profile in complain mode only logs, and a disabled one does nothing. Some packages ship profiles that way; one you did not change yourself deserves a look.")
                .verify("aa-status   # package apparmor")
                .verify("ls -l /etc/apparmor.d/disable"),
        );
    }
}

pub(crate) fn run(ctx: &ScanCtx, col: &mut Collector) {
    check_ebpf(ctx, col);
    check_taint(ctx, col);
    check_boot(ctx, col);
    check_security_module(ctx, col);
}
