//! More network checks (part of net_proc): unusual outgoing connections, DNS resolvers and
//! direct DNS traffic, /etc/hosts overrides, ARP spoofing, default routes and sniffing.

use super::net_proc::{Connection, MODULE};
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, is_steam_port, shq};
use crate::modules::sandboxes::is_steam_client;
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
    check_nat(ctx, col);
    check_packet_sockets(ctx, col);
    check_name_broadcasts(col);
    check_route_tables(ctx, col);
    super::firewall::run(ctx, col);
}

/// LLMNR (port 5355) and multicast DNS answered by systemd-resolved: names are asked on the
/// local network, where anyone may answer.
fn check_name_broadcasts(col: &mut Collector) {
    let mut lines: Vec<String> = col
        .inventory
        .connections
        .iter()
        .filter(|c| c.listening && c.proto.starts_with("udp") && (c.local_port == 5355 || c.local_port == 5353 && c.process.as_deref() == Some("systemd-resolve")))
        .map(|c| format!("{} port {} ({}) {}", c.proto, c.local_port, if c.local_port == 5355 { "LLMNR" } else { "mDNS" }, c.process.as_deref().unwrap_or("")))
        .collect();
    lines.sort();
    lines.dedup();
    if !lines.is_empty() {
        col.push(
            Finding::new(Severity::Info, MODULE, "NET-LLMNR", "Names are also looked up by asking the local network (LLMNR)")
                .evidence(lines.join("\n"))
                .description("On a network you do not control, another computer can answer such questions with its own address. Set LLMNR=no (and MulticastDNS=no) in /etc/systemd/resolved.conf if you do not need it.")
                .verify("resolvectl status"),
        );
    }
}

/// Routes outside the ordinary tables, from `ip -j route show table all`: (expected, other).
/// Tailscale's and wg-quick's own tables are expected.
pub fn separate_routes(json: &str) -> (Vec<String>, Vec<String>) {
    let Ok(serde_json::Value::Array(routes)) = serde_json::from_str::<serde_json::Value>(json) else { return (Vec::new(), Vec::new()) };
    let mut tables: BTreeMap<(String, String), (usize, bool)> = BTreeMap::new();
    for r in &routes {
        let get = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("");
        let table = get("table");
        if ["", "main", "local", "default", "254", "255", "253"].contains(&table) || ["local", "broadcast", "unreachable", "anycast"].contains(&get("type")) {
            continue;
        }
        let entry = tables.entry((table.to_string(), get("dev").to_string())).or_default();
        entry.0 += 1;
        entry.1 |= get("dst") == "default";
    }
    let (mut expected, mut other) = (Vec::new(), Vec::new());
    for ((table, device), (count, everything)) in tables {
        let line = format!("table {table} through {device}: {count} route(s){}", if everything { ", including all traffic" } else { "" });
        let tailscale = table == "52" && device.starts_with("tailscale");
        let wireguard = table == "51820" && !device.is_empty();
        if tailscale || wireguard {
            expected.push(format!("{line} ({})", if tailscale { "Tailscale" } else { "WireGuard" }));
        } else {
            other.push(line);
        }
    }
    (expected, other)
}

fn check_route_tables(ctx: &ScanCtx, col: &mut Collector) {
    if !ctx.sys.is_live() {
        return;
    }
    let Some(ip) = crate::external_tools::find_binary("ip") else { return };
    let Ok(out) = crate::external_tools::run_capture(&ip, &["-j", "route", "show", "table", "all"], 20) else { return };
    let (expected, other) = separate_routes(&out.stdout);
    if !expected.is_empty() {
        col.note(format!("VPN routing tables: {}", expected.join("; ")));
    }
    if !other.is_empty() {
        col.push(
            Finding::new(Severity::Low, MODULE, "NET-ROUTE-TABLE", "Some traffic takes separate routing tables")
                .evidence(clip(&other.join("\n"), 900))
                .description("Routing rules can send chosen traffic a different way than the ordinary routes show, for example through a tunnel. VPNs and containers do this; check that you know each one.")
                .verify("ip rule show; ip route show table all"),
        );
    }
}

/// Programs that open raw packet sockets to run the network itself.
const NETWORK_SERVICES: [&str; 11] = [
    "NetworkManager", "wpa_supplicant", "iwd", "dhclient", "dhcpcd", "systemd-networkd", "dnsmasq", "lldpd", "hostapd",
    "avahi-autoipd", "ModemManager",
];

/// (protocol, inode) of the sockets in /proc/net/packet that listen to raw network frames.
pub fn packet_sockets(text: &str) -> Vec<(u16, u64)> {
    text.lines()
        .skip(1)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            Some((u16::from_str_radix(f.get(3)?, 16).ok()?, f.get(8)?.parse().ok()?))
        })
        .collect()
}

/// Raw packet sockets that see all traffic – how tcpdump and other sniffers work.
fn check_packet_sockets(ctx: &ScanCtx, col: &mut Collector) {
    const ALL_PROTOCOLS: u16 = 0x0003;
    let Ok(text) = ctx.sys.read_string("/proc/net/packet") else { return };
    let mut seen = BTreeSet::new();
    let mut unowned = 0;
    for (protocol, inode) in packet_sockets(&text) {
        if protocol != ALL_PROTOCOLS {
            continue;
        }
        let owners: Vec<_> = ctx.processes.iter().filter(|p| p.socket_fds.iter().any(|(_, i)| *i == inode)).collect();
        if owners.is_empty() {
            unowned += 1;
        }
        for p in owners {
            let exe = p.exe_path().unwrap_or("");
            let installed = exe.starts_with("/usr/") && !exe.starts_with("/usr/local/");
            let name = p.display_name();
            if (installed && NETWORK_SERVICES.contains(&name.as_str())) || !seen.insert(p.pid) {
                continue;
            }
            let capture = installed && ["tcpdump", "dumpcap", "tshark", "wireshark"].contains(&name.as_str());
            col.push(
                Finding::new(if capture { Severity::Medium } else { Severity::High }, MODULE, "NET-SNIFFER", format!("Program reads all network traffic: {name}"))
                    .evidence(format!("PID {} UID {} exe={}\ncmdline=\"{}\"\nraw packet socket (all protocols), inode {inode}", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 300)))
                    .description("A raw packet socket sees every frame on the network card, including unencrypted logins. tcpdump and Wireshark do that when you run them; anything else doing it needs an explanation.")
                    .verify("ss -f link -a -p")
                    .verify(format!("ps -o pid,user,lstart,cmd -p {}", p.pid)),
            );
        }
    }
    if unowned > 0 {
        let (severity, why) = if ctx.privileged { (Severity::High, "no process owns it, although the scan runs as root") } else { (Severity::Low, "its owner can only be seen as root") };
        col.push(
            Finding::new(severity, MODULE, "NET-SNIFFER", "Something reads all network traffic")
                .evidence(format!("{unowned} raw packet socket(s) for all protocols; {why}"))
                .description("A raw packet socket sees every frame on the network card. Run the scan as root to learn which program holds it.")
                .verify("ss -f link -a -p")
                .verify("cat /proc/net/packet"),
        );
    }
}

/// Firewall rules in `nft list ruleset` that send traffic somewhere else. Rules that Docker,
/// libvirt and other virtualisation tools manage are left out.
pub fn nat_redirects(ruleset: &str) -> Vec<String> {
    const MANAGED: [&str; 5] = ["docker", "libvirt", "incus", "lxc", "netavark"];
    let managed = |name: &str| MANAGED.iter().any(|m| name.to_lowercase().contains(m));
    let (mut table, mut chain) = (String::new(), String::new());
    let mut out = Vec::new();
    for line in ruleset.lines().map(|l| l.trim()) {
        if let Some(rest) = line.strip_prefix("table ") {
            table = rest.trim_end_matches('{').trim().to_string();
        } else if let Some(rest) = line.strip_prefix("chain ") {
            chain = rest.trim_end_matches('{').trim().to_string();
        } else if !managed(&table) && !managed(&chain) {
            let words: Vec<&str> = line.split_whitespace().collect();
            // "dnat to …", "dnat ip to …" or "redirect to :port" (not "icmp type redirect")
            let redirect = words.iter().position(|w| *w == "redirect").map(|i| i == 0 || words[i - 1] != "type").unwrap_or(false);
            if (words.contains(&"dnat") || redirect) && !line.starts_with("type ") {
                out.push(format!("table {table}, chain {chain}: {line}"));
            }
        }
    }
    out
}

/// Redirect rules in `iptables-legacy-save` (the old firewall, which `nft` does not show).
pub fn iptables_redirects(saved: &str) -> Vec<String> {
    saved
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with("-A ") && (l.contains("-j DNAT") || l.contains("-j REDIRECT")))
        .filter(|l| !l.split_whitespace().nth(1).map(|c| c.starts_with("DOCKER") || c.starts_with("LIBVIRT")).unwrap_or(false))
        .map(|l| format!("iptables-legacy: {l}"))
        .collect()
}

fn check_nat(ctx: &ScanCtx, col: &mut Collector) {
    if !ctx.sys.is_live() || !ctx.privileged {
        return;
    }
    let rules: Vec<String> = super::firewall::legacy_saved(ctx).iter().flat_map(|(_, saved)| iptables_redirects(saved)).collect();
    if !rules.is_empty() {
        col.push(
            Finding::new(Severity::Medium, MODULE, "NET-NAT-REDIRECT", "Old-style iptables rules redirect traffic")
                .evidence(clip(&rules.join("\n"), 1200))
                .description("These rules use the old iptables system, which the usual nftables listing does not show. Debian does not use it by default, so rules there are easy to overlook.")
                .verify("iptables-legacy-save -t nat"),
        );
    }
    let Some(nft) = crate::external_tools::find_binary("nft") else { return };
    let ruleset = match crate::external_tools::run_capture(&nft, &["list", "ruleset"], 30) {
        Ok(o) if o.status == Some(0) => o.stdout,
        Ok(_) => {
            // the read-only timer service deliberately lacks the network administration right
            col.note("The firewall rules could not be read (nft needs network administration rights), so port forwarding was not checked");
            return;
        }
        Err(e) => {
            col.note(format!("nft could not list the firewall rules: {e}"));
            return;
        }
    };
    let rules = nat_redirects(&ruleset);
    if !rules.is_empty() {
        col.push(
            Finding::new(Severity::Low, MODULE, "NET-NAT-REDIRECT", "Firewall rules redirect or forward traffic")
                .evidence(clip(&rules.join("\n"), 1200))
                .description("These rules send incoming or outgoing traffic to another address or port. Port forwarding for your own services does this; an attacker uses it to open a way in or to reroute your connections.")
                .verify("nft list ruleset"),
        );
    }
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
        // the Steam client talking to Steam's game ports; its folder is the user's, so Low
        let steam = list.iter().all(|c| is_steam_port(c.remote_port) && c.pid.is_some_and(|pid| ctx.processes.iter().any(|p| p.pid == pid && is_steam_client(p, ctx.processes))));
        let severity = if !steam && (odd_place || root) { Severity::Medium } else { Severity::Low };
        let ports: Vec<String> = ports.iter().take(8).map(|p| p.to_string()).collect();
        col.push(
            Finding::new(severity, MODULE, "NET-OUTBOUND-UNUSUAL", format!("Outgoing connections to unusual ports: {name}"))
                .evidence(format!("remote port(s) {}\n{}", ports.join(", "), list.iter().take(12).map(|c| describe(c)).collect::<Vec<_>>().join("\n")))
                .description(if steam {
                    "Steam connects to its game servers on these ports."
                } else {
                    "The program is connected to computers on the internet on ports that normal web, mail, SSH and time services don't use. Games and chat programs do this; so do botnets and remote-control backdoors. Check the program and the address."
                })
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
