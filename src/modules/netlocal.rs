//! Services a desktop has and a server usually not (part of `net_proc`): paired Bluetooth
//! devices, shared folders, where DNS questions go, and DNS that slips past a VPN.

use super::common::{clip, shq};
use super::net_proc::MODULE;
use super::netwatch::{default_routes, is_public};
use super::persistence::parse_unit;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr};

fn finding(col: &mut Collector, severity: Severity, rule: &str, title: String, evidence: String, description: &str, verify: &str) {
    col.push(Finding::new(severity, MODULE, rule, title).evidence(clip(&evidence, 900)).description(description.to_string()).verify(verify.to_string()));
}

// ---------------------------------------------------------------- Bluetooth

/// Is a paired device a keyboard? From its class of device or its low-energy appearance.
pub fn is_bluetooth_keyboard(info: &str) -> bool {
    let number = |key: &str| {
        parse_unit(info).into_iter().find(|(_, k, _)| k == key).and_then(|(_, _, v)| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
    };
    // major class 5 = peripheral, bit 6 = keyboard; appearance 0x03c1 = keyboard
    number("Class").map(|c| (c >> 8) & 0x1f == 5 && c & 0x40 != 0).unwrap_or(false) || number("Appearance") == Some(0x03c1)
}

fn check_bluetooth(ctx: &ScanCtx, col: &mut Collector) {
    let base = "/var/lib/bluetooth";
    if std::fs::read_dir(ctx.sys.path(base)).is_err() {
        if ctx.sys.exists(base) {
            col.note("Bluetooth: the paired devices can only be read as root");
        }
        return;
    }
    let mut devices = Vec::new();
    let mut keyboards = Vec::new();
    for adapter in ctx.sys.dir_names(base) {
        let settings = ctx.sys.read_string(format!("{base}/{adapter}/settings")).unwrap_or_default();
        if parse_unit(&settings).iter().any(|(_, k, v)| k == "Discoverable" && v == "true") {
            finding(col, Severity::Low, "NET-BLUETOOTH", format!("Bluetooth is visible to everyone nearby: {adapter}"), format!("{base}/{adapter}/settings: Discoverable=true"), "Other devices can find this computer and try to connect. Visibility is only needed while pairing.", "bluetoothctl show");
        }
        for device in ctx.sys.dir_names(format!("{base}/{adapter}")) {
            let Ok(info) = ctx.sys.read_string(format!("{base}/{adapter}/{device}/info")) else { continue };
            let name = parse_unit(&info).into_iter().find(|(g, k, _)| g == "General" && k == "Name").map(|(_, _, v)| v).unwrap_or_default();
            let keyboard = is_bluetooth_keyboard(&info);
            let entry = format!("{device} {name}{}", if keyboard { " [keyboard]" } else { "" });
            if keyboard {
                keyboards.push(entry.clone());
            }
            devices.push(entry);
        }
    }
    if !keyboards.is_empty() {
        finding(col, Severity::Low, "NET-BLUETOOTH", "Paired Bluetooth keyboards".into(), keyboards.join("\n"), "A paired keyboard can type commands. Check that every one of these is yours and remove old ones.", "bluetoothctl devices Paired");
    }
    devices.sort();
    col.inventory.bluetooth = Some(devices);
}

// ---------------------------------------------------------------- shared folders

/// Risky lines of `/etc/exports`.
pub fn risky_exports(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| l.contains("no_root_squash") || l.split_whitespace().skip(1).any(|c| c.starts_with("*(") && c.contains("rw")))
        .map(str::to_string)
        .collect()
}

/// Samba shares that anyone may write to without a password.
pub fn open_shares(text: &str) -> Vec<String> {
    let mut shares: Vec<(String, bool, bool)> = Vec::new();
    for (section, key, value) in parse_unit(text) {
        if shares.last().map(|s| s.0 != section).unwrap_or(true) {
            shares.push((section.clone(), false, false));
        }
        let Some(share) = shares.last_mut() else { continue };
        let on = ["yes", "true", "1"].contains(&value.to_lowercase().as_str());
        match key.to_lowercase().as_str() {
            "guest ok" | "public" => share.1 = on,
            "writable" | "writeable" | "write ok" => share.2 = on,
            "read only" => share.2 = !on,
            _ => {}
        }
    }
    shares.into_iter().filter(|(name, guest, writable)| *guest && *writable && name != "global").map(|s| format!("[{}] guest ok, writable", s.0)).collect()
}

fn check_sharing(ctx: &ScanCtx, col: &mut Collector) {
    if let Ok(text) = ctx.sys.read_string("/etc/exports") {
        let lines = risky_exports(&text);
        if !lines.is_empty() {
            finding(col, Severity::Medium, "NET-SHARE", "NFS shares with wide rights".into(), lines.join("\n"), "no_root_squash lets root on another computer act as root on these files; '*(rw' lets every computer write. Limit them to the machines that need it.", "cat /etc/exports; showmount -e localhost");
        }
    }
    let mut shares = ctx.sys.read_string("/etc/samba/smb.conf").map(|t| open_shares(&t)).unwrap_or_default();
    for name in ctx.sys.dir_names("/var/lib/samba/usershares") {
        let text = ctx.sys.read_string(format!("/var/lib/samba/usershares/{name}")).unwrap_or_default();
        // usershare_acl "Everyone:F" gives full access, guest_ok=y needs no password
        if text.contains("guest_ok=y") && text.contains(":F") {
            shares.push(format!("usershare {name}: guest, full access"));
        }
    }
    if !shares.is_empty() {
        finding(col, Severity::Medium, "NET-SHARE", "Folders shared with guests who may write".into(), shares.join("\n"), "Anyone on the network can add or change files here without a password.", "testparm -s; net usershare list");
    }
}

// ---------------------------------------------------------------- DNS

/// The public DNS servers in a value such as "9.9.9.9 1.2.3.4#name" or "1.2.3.4;5.6.7.8;".
pub fn unknown_servers(value: &str, trusted: &[String]) -> Vec<String> {
    value
        .split([' ', ';', ','])
        .filter_map(|s| {
            let address = s.split(['#', '%']).next()?;
            // "[2001:db8::1]:53" and "192.0.2.1:53" carry a port
            let address = address.strip_prefix('[').and_then(|a| a.split(']').next()).unwrap_or(address);
            let address = match address.split_once(':') {
                Some((host, port)) if host.contains('.') && port.chars().all(|c| c.is_ascii_digit()) => host,
                _ => address,
            };
            let ip: IpAddr = address.parse().ok()?;
            (is_public(&ip) && !trusted.iter().any(|t| t == address)).then(|| address.to_string())
        })
        .collect()
}

fn check_dns_settings(ctx: &ScanCtx, col: &mut Collector) {
    let trusted = &ctx.cfg.trusted_resolvers;
    // servers written into this machine's own settings
    let mut files = vec!["/etc/systemd/resolved.conf".to_string()];
    files.extend(ctx.sys.dir_names("/etc/systemd/resolved.conf.d").into_iter().map(|n| format!("/etc/systemd/resolved.conf.d/{n}")));
    files.extend(ctx.sys.dir_names("/etc/NetworkManager/system-connections").into_iter().map(|n| format!("/etc/NetworkManager/system-connections/{n}")));
    let mut set = Vec::new();
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        for (_, key, value) in parse_unit(&text) {
            if ["DNS", "FallbackDNS", "dns"].contains(&key.as_str()) {
                set.extend(unknown_servers(&value, trusted).into_iter().map(|s| format!("{path}: {key} {s}")));
            }
        }
    }
    if !set.is_empty() {
        finding(col, Severity::Medium, "NET-DNS-CONFIG", "Unknown DNS servers in the network settings".into(), set.join("\n"), "These settings send name lookups to a server that is not one of the well-known ones; it can see and redirect where you go. Add it to trusted_resolvers if it is your provider's or your VPN's.", "resolvectl status; nmcli -f name,ipv4.dns connection show");
    }
    // servers handed out by the network or a VPN right now
    let mut handed = BTreeSet::new();
    for path in ["/run/systemd/resolve/resolv.conf", "/run/NetworkManager/resolv.conf"] {
        let text = ctx.sys.read_string(path).unwrap_or_default();
        for line in text.lines().filter_map(|l| l.trim().strip_prefix("nameserver")) {
            handed.extend(unknown_servers(line.trim(), trusted));
        }
    }
    if !handed.is_empty() {
        finding(col, Severity::Low, "NET-DNS-HANDED", "The network hands out DNS servers that are not well known".into(), handed.into_iter().collect::<Vec<_>>().join("\n"), "The router or VPN decided these. A provider's own servers look like this; on a strange network it can be a trap.", "resolvectl status; nmcli device show");
    }
    // "address=/name/ip" in NetworkManager's dnsmasq answers names with a fixed address
    for name in ctx.sys.dir_names("/etc/NetworkManager/dnsmasq.d") {
        let path = format!("/etc/NetworkManager/dnsmasq.d/{name}");
        let text = ctx.sys.read_string(&path).unwrap_or_default();
        let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| l.starts_with("address=/") && ["debian.org", "github.com", "kernel.org", "pypi.org"].iter().any(|d| l.contains(d))).collect();
        if !lines.is_empty() {
            finding(col, Severity::High, "NET-DNS-CONFIG", "DNS settings redirect update or developer sites".into(), format!("{path}\n{}", lines.join("\n")), "Names of update and developer sites are answered with a fixed address, which can serve fake software.", &format!("cat {}", shq(&path)));
        }
    }
}

/// Networks reached directly through an interface: (interface, network, mask).
fn local_networks(route: &str) -> Vec<(String, u32, u32)> {
    route
        .lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let number = |s: &str| u32::from_str_radix(s, 16).ok().map(|v| u32::from(Ipv4Addr::from(v.to_ne_bytes())));
            let (network, mask) = (number(f.get(1)?)?, number(f.get(7)?)?);
            (mask != 0).then(|| (f[0].to_string(), network, mask))
        })
        .collect()
}

fn is_vpn_interface(name: &str) -> bool {
    ["wg", "tun", "proton", "mullvad", "nordlynx", "ipsec", "ppp"].iter().any(|p| name.starts_with(p))
}

/// DNS servers on the ordinary network while all other traffic goes through a VPN.
pub fn dns_outside_vpn(route: &str, resolv: &str) -> Vec<String> {
    if !default_routes(route).iter().any(|(dev, _, _)| is_vpn_interface(dev)) && !route.lines().skip(1).any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        f.len() > 7 && is_vpn_interface(f[0]) && f[1] == "00000000" && f[7] == "00000000"
    }) {
        return Vec::new();
    }
    let outside: Vec<(String, u32, u32)> = local_networks(route).into_iter().filter(|n| !is_vpn_interface(&n.0)).collect();
    resolv
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver")?.trim().parse::<Ipv4Addr>().ok())
        .filter_map(|ip| outside.iter().find(|(_, net, mask)| u32::from(ip) & mask == *net).map(|n| format!("{ip} is reached through {}", n.0)))
        .collect()
}

fn check_dns_leak(ctx: &ScanCtx, col: &mut Collector) {
    let route = ctx.sys.read_string("/proc/net/route").unwrap_or_default();
    let resolv = ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"].iter().find_map(|p| ctx.sys.read_string(p).ok()).unwrap_or_default();
    let leaks = dns_outside_vpn(&route, &resolv);
    if !leaks.is_empty() {
        finding(col, Severity::Low, "NET-DNS-LEAK", "Name lookups may go around the VPN".into(), leaks.join("\n"), "Traffic goes through the VPN, but a DNS server sits on the local network, so the local network can see which sites you look up. Set the VPN to use its own DNS, and check its kill switch.", "ip route show; resolvectl status");
    }
}

pub(crate) fn run(ctx: &ScanCtx, col: &mut Collector) {
    check_bluetooth(ctx, col);
    check_sharing(ctx, col);
    check_dns_settings(ctx, col);
    check_dns_leak(ctx, col);
}
