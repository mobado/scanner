//! More network checks (part of net_proc): unusual outgoing connections, DNS resolvers and
//! direct DNS traffic, /etc/hosts overrides, ARP spoofing, default routes and sniffing.

use super::net_proc::{Connection, MODULE};
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, shq};
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::MetadataExt;

/// Programs that are expected to talk DNS directly.
const RESOLVERS: [&str; 11] = [
    "systemd-resolved", "dnsmasq", "unbound", "named", "NetworkManager", "tailscaled", "avahi-daemon",
    "dnscrypt-proxy", "kresd", "pdns_recursor", "connmand",
];

/// Is this an address on the internet (not this machine, the local network or a VPN range)?
pub fn is_public(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            !(v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified() || v.is_multicast() || v.is_broadcast()
                || (o[0] == 100 && (64..128).contains(&o[1])))
        }
        IpAddr::V6(v) => {
            if let Some(m) = v.to_ipv4_mapped() {
                return is_public(&IpAddr::V4(m));
            }
            let s = v.segments()[0];
            !(v.is_loopback() || v.is_unspecified() || v.is_multicast() || (s & 0xffc0) == 0xfe80 || (s & 0xfe00) == 0xfc00)
        }
    }
}

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    let resolvers = check_resolv_conf(ctx, col);
    check_outbound(ctx, col, &resolvers);
    check_hosts(ctx, col);
    check_arp_and_routes(ctx, col);
    check_promiscuous(ctx, col);
}

fn describe(c: &Connection) -> String {
    format!(
        "{} {}:{} → {}:{} PID {} ({})",
        c.proto,
        c.local_addr,
        c.local_port,
        c.remote_addr,
        c.remote_port,
        c.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
        clip(c.cmdline.as_deref().unwrap_or("?"), 120)
    )
}

fn check_outbound(ctx: &ScanCtx, col: &mut Collector, resolvers: &BTreeSet<String>) {
    let conns = col.inventory.connections.clone();
    let listening: BTreeSet<u16> = conns.iter().filter(|c| c.listening).map(|c| c.local_port).collect();
    let mut unusual: BTreeMap<String, Vec<&Connection>> = BTreeMap::new();
    let mut dns: BTreeMap<String, Vec<&Connection>> = BTreeMap::new();
    for c in &conns {
        if c.state != "ESTABLISHED" || listening.contains(&c.local_port) {
            continue;
        }
        let Ok(remote) = c.remote_addr.parse::<IpAddr>() else { continue };
        let name = c.process.clone().unwrap_or_else(|| "unknown".into());
        if c.remote_port == 53 {
            if !RESOLVERS.contains(&name.as_str()) && !resolvers.contains(&c.remote_addr) && !remote.is_loopback() {
                dns.entry(name).or_default().push(c);
            }
            continue;
        }
        if !is_public(&remote) || ctx.cfg.common_remote_ports.contains(&c.remote_port) {
            continue;
        }
        if ctx.cfg.is_listen_process_allowed(&name, c.exe.as_deref()) {
            continue;
        }
        unusual.entry(name).or_default().push(c);
    }
    for (name, list) in unusual {
        let odd_place = list.iter().any(|c| !c.exe.as_deref().map(|e| ["/usr/", "/opt/", "/snap/", "/app/"].iter().any(|d| e.starts_with(d))).unwrap_or(false));
        let root = list.iter().any(|c| c.uid == 0);
        let ports: BTreeSet<u16> = list.iter().map(|c| c.remote_port).collect();
        let ports: Vec<String> = ports.iter().take(8).map(|p| p.to_string()).collect();
        col.push(
            Finding::new(if odd_place || root { Severity::Medium } else { Severity::Low }, MODULE, "NET-OUTBOUND-UNUSUAL", format!("Outgoing connections to unusual ports: {name}"))
                .evidence(format!("remote port(s) {}\n{}", ports.join(", "), list.iter().take(12).map(|c| describe(c)).collect::<Vec<_>>().join("\n")))
                .description("The program is connected to computers on the internet on ports that normal web, mail, SSH and time services don't use. Games and chat programs do this; so do botnets and remote-control backdoors. Check the program and the address.")
                .verify(format!("ss -tunap | grep -F -- {}", shq(&name)))
                .verify(format!("getent hosts {}", list.first().map(|c| c.remote_addr.as_str()).unwrap_or(""))),
        );
    }
    for (name, list) in dns {
        col.push(
            Finding::new(Severity::Medium, MODULE, "NET-DNS-DIRECT", format!("Direct DNS traffic that bypasses the system resolver: {name}"))
                .evidence(list.iter().take(12).map(|c| describe(c)).collect::<Vec<_>>().join("\n"))
                .description("A program talks DNS to a server that is not the system's resolver. Some programs do this on purpose, but it is also how DNS tunnelling hides data and commands in DNS queries.")
                .verify(format!("ss -tunap | grep -F -- {}", shq(&name)))
                .verify("resolvectl status 2>/dev/null; cat /etc/resolv.conf"),
        );
    }
}

fn check_resolv_conf(ctx: &ScanCtx, col: &mut Collector) -> BTreeSet<String> {
    let path = "/etc/resolv.conf";
    let Ok(text) = ctx.sys.read_string(path) else { return BTreeSet::new() };
    let servers: BTreeSet<String> = text
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .map(|s| s.trim().split('%').next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if let Some(target) = ctx.sys.read_link(path) {
        if ctx.cfg.is_temp_path(&ctx.sys.resolve_link_target(path, &target)) || target.starts_with("/home/") {
            col.push(
                Finding::new(Severity::High, MODULE, "NET-RESOLVER", "/etc/resolv.conf points to an unusual place")
                    .evidence(format!("{path} -> {target}"))
                    .description("Whoever controls the file decides where every name lookup goes.")
                    .verify("ls -l /etc/resolv.conf"),
            );
        }
    }
    if let Ok(m) = std::fs::metadata(ctx.sys.path(path)) {
        if m.mode() & 0o002 != 0 {
            col.push(
                Finding::new(Severity::High, MODULE, "NET-RESOLVER", "/etc/resolv.conf can be changed by everyone")
                    .evidence(format!("mode {:o}", m.mode() & 0o7777))
                    .description("Any user can redirect all name lookups.")
                    .verify("stat /etc/resolv.conf"),
            );
        }
    }
    let unknown: Vec<&String> = servers
        .iter()
        .filter(|s| s.parse::<IpAddr>().map(|ip| is_public(&ip)).unwrap_or(false) && !ctx.cfg.trusted_resolvers.contains(s))
        .collect();
    if !unknown.is_empty() {
        col.push(
            Finding::new(Severity::Medium, MODULE, "NET-RESOLVER", "Unknown DNS server on the internet")
                .evidence(format!("{path}: {}", unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")))
                .description("The resolver is a public server that is not one of the well-known ones. It can see and change every name lookup. If your provider or VPN gave you this address, add it to trusted_resolvers.")
                .verify("cat /etc/resolv.conf; resolvectl status 2>/dev/null"),
        );
    }
    servers
}

/// Names whose redirection would let an attacker feed fake updates or hide.
const PROTECTED_DOMAINS: [&str; 9] = [
    "debian.org", "github.com", "githubusercontent.com", "kernel.org", "letsencrypt.org", "virustotal.com", "clamav.net", "pypi.org", "docker.io",
];

fn check_hosts(ctx: &ScanCtx, col: &mut Collector) {
    let Ok(text) = ctx.sys.read_string("/etc/hosts") else { return };
    let hits: Vec<String> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| {
            l.split_whitespace().skip(1).any(|n| {
                let n = n.to_lowercase();
                PROTECTED_DOMAINS.iter().any(|d| n == *d || n.ends_with(&format!(".{d}")))
            })
        })
        .map(|l| l.to_string())
        .collect();
    if !hits.is_empty() {
        col.push(
            Finding::new(Severity::High, MODULE, "NET-HOSTS-OVERRIDE", "/etc/hosts redirects update or security sites")
                .evidence(hits.join("\n"))
                .description("Entries in /etc/hosts override DNS. Redirecting Debian, GitHub or security sites can block updates or serve fake ones. Ad-blocking host lists should not contain these.")
                .verify("grep -nE 'debian|github|kernel|virustotal|clamav|pypi|docker' /etc/hosts"),
        );
    }
}

/// Default gateways from /proc/net/route: (interface, gateway, metric).
pub fn default_routes(text: &str) -> Vec<(String, Ipv4Addr, u32)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 8 || f[1] != "00000000" || f[7] != "00000000" {
                return None;
            }
            let gw = u32::from_str_radix(f[2], 16).ok()?;
            if gw == 0 {
                return None;
            }
            Some((f[0].to_string(), Ipv4Addr::from(gw.to_ne_bytes()), f[6].parse().unwrap_or(0)))
        })
        .collect()
}

fn check_arp_and_routes(ctx: &ScanCtx, col: &mut Collector) {
    let routes = ctx.sys.read_string("/proc/net/route").map(|t| default_routes(&t)).unwrap_or_default();
    let mut per_metric: BTreeMap<u32, BTreeSet<String>> = BTreeMap::new();
    for (dev, gw, metric) in &routes {
        per_metric.entry(*metric).or_default().insert(format!("{gw} via {dev}"));
    }
    if let Some((metric, list)) = per_metric.iter().find(|(_, l)| l.len() > 1) {
        col.push(
            Finding::new(Severity::Medium, MODULE, "NET-ROUTE-DEFAULT", "Two default gateways with the same priority")
                .evidence(format!("metric {metric}: {}", list.iter().cloned().collect::<Vec<_>>().join(", ")))
                .description("Traffic is split between two gateways. That happens with some network setups, but an added gateway can also send your traffic through an attacker.")
                .verify("ip route show"),
        );
    }
    let Ok(arp) = ctx.sys.read_string("/proc/net/arp") else { return };
    let mut by_mac: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    for line in arp.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 6 || f[2] == "0x0" || f[3] == "00:00:00:00:00:00" {
            continue;
        }
        by_mac.entry((f[3].to_lowercase(), f[5].to_string())).or_default().insert(f[0].to_string());
    }
    for ((mac, dev), ips) in by_mac {
        if ips.len() < 2 {
            continue;
        }
        let gateway = routes.iter().any(|(_, gw, _)| ips.contains(&gw.to_string()));
        col.push(
            Finding::new(if gateway { Severity::High } else { Severity::Low }, MODULE, "NET-ARP-DUPLICATE", format!("Several addresses share one hardware address on {dev}"))
                .evidence(format!("{mac}: {}{}", ips.iter().cloned().collect::<Vec<_>>().join(", "), if gateway { " (includes the default gateway)" } else { "" }))
                .description(if gateway {
                    "Another address uses the same hardware address as your gateway. That is what ARP spoofing (a man in the middle on the local network) looks like; some routers do it legitimately with several addresses."
                } else {
                    "Often a device or virtual machine with several addresses. Worth knowing on a network you don't control."
                })
                .verify("ip neigh show")
                .verify("arp -an 2>/dev/null"),
        );
    }
}

fn check_promiscuous(ctx: &ScanCtx, col: &mut Collector) {
    for name in ctx.sys.dir_names("/sys/class/net") {
        if ["veth", "docker", "br", "virbr", "vnet", "tap"].iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let base = format!("/sys/class/net/{name}");
        if ctx.sys.exists(format!("{base}/master")) || ctx.sys.exists(format!("{base}/brport")) {
            continue;
        }
        let Ok(flags) = ctx.sys.read_string(format!("{base}/flags")) else { continue };
        let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16).unwrap_or(0);
        if flags & 0x100 != 0 {
            col.push(
                Finding::new(Severity::Medium, MODULE, "NET-PROMISC", format!("Network card {name} is in promiscuous (listening) mode"))
                    .evidence(format!("{base}/flags = {flags:#x}"))
                    .description("The card passes all traffic it sees to a program. Packet sniffers, virtual machine bridges and some tools need this; a hidden sniffer also does.")
                    .verify(format!("ip -d link show {}", shq(&name)))
                    .verify("ss -f link -p 2>/dev/null"),
            );
        }
    }
}
