//! Special rights of running programs (part of `proc_audit`): a program that is not root but
//! holds root-like capabilities, which no look at files would show.

use super::common::{clip, risky_home_place};
use super::proc_audit::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::procinfo::status_field;

/// Capabilities that are close to root: (bit, name).
const DANGEROUS: [(u32, &str); 15] = [
    (0, "chown"), (1, "dac_override"), (2, "dac_read_search"), (3, "fowner"), (6, "setgid"), (7, "setuid"), (12, "net_admin"),
    (13, "net_raw"), (16, "sys_module"), (17, "sys_rawio"), (19, "sys_ptrace"), (21, "sys_admin"), (31, "setfcap"),
    (38, "perfmon"), (39, "bpf"),
];

/// Installed services and tools that hold such rights as part of their job.
const EXPECTED: [&str; 34] = [
    "systemd", "systemd-networkd", "systemd-network", "systemd-resolved", "systemd-resolve", "systemd-timesyncd",
    "systemd-timesyn", "systemd-oomd", "rtkit-daemon", "dnsmasq", "avahi-daemon", "chronyd", "NetworkManager", "ping",
    "dumpcap", "gnome-keyring-daemon", "gnome-keyring-d", "kwin_wayland", "ksysguardd", "ksgrd_network_helper",
    "ksgrd_network_h", "dbus-daemon", "polkitd", "named", "unbound", "squid", "haproxy", "tor", "openvpn", "ntpd", "lldpd",
    "mtr-packet", "fping", "wpa_supplicant",
];

/// The dangerous capabilities in a mask such as `CapEff: 0000000000003400`.
pub fn dangerous_capabilities(mask: u64) -> Vec<&'static str> {
    DANGEROUS.iter().filter(|(bit, _)| mask & (1u64 << bit) != 0).map(|(_, name)| *name).collect()
}

pub(crate) fn check(ctx: &ScanCtx, col: &mut Collector) {
    let user_space = |who: &str| ctx.sys.read_link(format!("/proc/{who}/ns/user"));
    let host = user_space("1").or_else(|| user_space("self"));
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread()) {
        let Ok(status) = ctx.sys.read_string(format!("/proc/{}/status", p.pid)) else { continue };
        // "Uid: real effective …": a set-uid program runs as root and has every right anyway
        let effective: Option<u32> = status_field(&status, "Uid").and_then(|v| v.split_whitespace().nth(1)).and_then(|v| v.parse().ok());
        if effective.map(|u| u == 0).unwrap_or(true) {
            continue;
        }
        let mask = |key: &str| status_field(&status, key).and_then(|v| u64::from_str_radix(v.trim(), 16).ok()).unwrap_or(0);
        // permitted rights count too: the program can switch them on whenever it likes
        let active = mask("CapEff") | mask("CapAmb");
        let held = dangerous_capabilities(active | mask("CapPrm"));
        if held.is_empty() {
            continue;
        }
        // rights inside a namespace of its own (browser sandboxes, containers) end there
        if let (Some(own), Some(host)) = (user_space(&p.pid.to_string()), &host) {
            if &own != host {
                continue;
            }
        }
        let exe = p.exe_path().unwrap_or("");
        let names = p.candidate_names();
        let odd = ctx.cfg.is_temp_path(exe) || risky_home_place(exe, ctx.cfg).is_some() || exe.starts_with("/home/") || exe.starts_with("/memfd:");
        let system = ["/usr/", "/lib/", "/bin/", "/sbin/", "/snap/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
        // rights that a shell passes on to everything it starts
        let shell = names.iter().any(|n| ctx.cfg.is_shell(n) || ctx.cfg.is_interpreter(n));
        // without root, another user's program file can't be read: its name has to do
        if (system || exe.is_empty()) && !shell && names.iter().any(|n| EXPECTED.contains(&n.as_str())) {
            continue;
        }
        let severity = if odd || shell { Severity::High } else if system || exe.is_empty() { Severity::Low } else { Severity::Medium };
        let waiting: Vec<String> = held.iter().filter(|c| !dangerous_capabilities(active).contains(c)).map(|c| format!("cap_{c}")).collect();
        let waiting = if waiting.is_empty() { String::new() } else { format!("\nheld but switched off right now (can be switched on): {}", waiting.join(", ")) };
        col.push(
            Finding::new(severity, MODULE, "PROC-CAPABILITIES", format!("A program without root holds root-like rights: {}", p.display_name()))
                .evidence(format!("PID {} UID {} exe={}\ncmdline=\"{}\"\ncapabilities: {}{waiting}", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 300), held.iter().map(|c| format!("cap_{c}")).collect::<Vec<_>>().join(", ")))
                .description("Capabilities give parts of root's power: reading any file, watching the network, tracing other programs or loading kernel code. Some services need one; an unknown program or a shell holding them is a way to stay in control without being root.")
                .verify(format!("grep Cap /proc/{}/status", p.pid))
                .verify("capsh --decode=<value>   # package libcap2-bin"),
        );
    }
}
