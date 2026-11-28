//! Ways around the firewall (part of `net_proc`): tunnel interfaces and WireGuard peers that
//! no configuration declares, tunnelling programs and reverse SSH tunnels.

use super::common::{clip, shq};
use super::net_proc::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::procinfo::ProcInfo;

/// Interfaces the kernel creates by itself.
const KERNEL_DEFAULT: [&str; 9] = ["tunl0", "gre0", "gretap0", "erspan0", "sit0", "ip6tnl0", "ip6gre0", "ip_vti0", "ip6_vti0"];

/// Interfaces of well-known software that configures them itself.
const MANAGED: [&str; 11] = ["tailscale", "virbr", "vnet", "docker", "br-", "veth", "zt", "nordlynx", "proton", "mullvad", "CloudflareWARP"];

fn tunnel_kind(ctx: &ScanCtx, name: &str) -> Option<&'static str> {
    let base = format!("/sys/class/net/{name}");
    if ctx.sys.read_string(format!("{base}/uevent")).map(|u| u.contains("DEVTYPE=wireguard")).unwrap_or(false) {
        return Some("WireGuard");
    }
    if ctx.sys.exists(format!("{base}/tun_flags")) {
        return Some("TUN/TAP");
    }
    match ctx.sys.read_string(format!("{base}/type")).ok()?.trim() {
        "768" | "769" => Some("IP-in-IP"),
        "776" => Some("SIT"),
        "778" | "823" => Some("GRE"),
        _ => None,
    }
}

/// All network configuration text: (path, content).
fn network_config(ctx: &ScanCtx) -> Vec<(String, String)> {
    let mut paths = vec!["/etc/network/interfaces".to_string()];
    for dir in [
        "/etc/network/interfaces.d", "/etc/wireguard", "/etc/NetworkManager/system-connections", "/run/NetworkManager/system-connections",
        "/etc/systemd/network", "/run/systemd/network", "/etc/openvpn", "/etc/openvpn/client", "/etc/openvpn/server",
    ] {
        paths.extend(ctx.sys.dir_names(dir).into_iter().map(|n| format!("{dir}/{n}")));
    }
    paths.into_iter().filter_map(|p| ctx.sys.read_string(&p).ok().map(|t| (p, t))).collect()
}

/// Does any configuration declare the interface `name`?
pub fn is_declared(name: &str, kind: &str, configs: &[(String, String)], openvpn_running: bool) -> bool {
    let vpn = kind == "TUN/TAP" && openvpn_running;
    vpn || configs.iter().any(|(path, text)| {
        let wireguard_file = path == &format!("/etc/wireguard/{name}.conf");
        // OpenVPN and NetworkManager VPNs name their interface "tun" + a number
        let numbered = kind == "TUN/TAP"
            && ((path.starts_with("/etc/openvpn") && text.lines().any(|l| ["dev tun", "dev tap"].contains(&l.trim())))
                || (path.contains("system-connections") && text.contains("type=vpn")));
        wireguard_file
            || numbered
            || text.lines().map(str::trim).filter(|l| !l.starts_with('#')).any(|l| {
                l == format!("interface-name={name}") || l == format!("Name={name}") || l == format!("dev {name}")
                    || (path.starts_with("/etc/network/") && l.split_whitespace().any(|w| w == name))
            })
    })
}

/// Peers in `wg show all dump`: (interface, public key, endpoint, allowed addresses).
/// The first line of each interface holds its private key and is skipped.
pub fn wireguard_peers(dump: &str) -> Vec<(String, String, String, String)> {
    dump.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() >= 9).then(|| (f[0].to_string(), f[1].to_string(), f[3].to_string(), f[4].to_string()))
        })
        .collect()
}

fn check_interfaces(ctx: &ScanCtx, col: &mut Collector) {
    let configs = network_config(ctx);
    // a running OpenVPN explains its tunnel: the installed program, or (when its file cannot be
    // read) a process of root's, which only root can start
    let openvpn = ctx.processes.iter().any(|p| p.is_program(&["openvpn"]) && p.exe_path().is_some_and(|e| e.starts_with("/usr/")) || p.uid == 0 && p.comm == "openvpn");
    for name in ctx.sys.dir_names("/sys/class/net") {
        if KERNEL_DEFAULT.contains(&name.as_str()) || MANAGED.iter().any(|m| name.starts_with(m)) {
            continue;
        }
        let Some(kind) = tunnel_kind(ctx, &name) else { continue };
        if is_declared(&name, kind, &configs, openvpn) {
            continue;
        }
        let (severity, note) = if ctx.privileged { (Severity::Medium, "") } else { (Severity::Low, "\nsome configuration files can only be read as root") };
        col.push(
            Finding::new(severity, MODULE, "NET-TUNNEL-IFACE", format!("Tunnel interface that no configuration declares: {name}"))
                .evidence(format!("/sys/class/net/{name}: {kind}{note}"))
                .description("A tunnel carries traffic past the firewall. This one is not in the network, NetworkManager, systemd-networkd, WireGuard or OpenVPN settings. A VPN app of your own can do this; so can a hidden back channel.")
                .verify(format!("ip -d addr show {}", shq(&name)))
                .verify("nmcli connection show 2>/dev/null; networkctl list 2>/dev/null"),
        );
    }
    if !ctx.sys.is_live() || !ctx.privileged {
        return;
    }
    let Some(wg) = crate::external_tools::find_binary("wg") else { return };
    let Ok(out) = crate::external_tools::run_capture(&wg, &["show", "all", "dump"], 20) else { return };
    for (iface, key, endpoint, allowed) in wireguard_peers(&out.stdout) {
        if MANAGED.iter().any(|m| iface.starts_with(m)) || configs.iter().any(|(_, t)| t.contains(&key)) {
            continue;
        }
        col.push(
            Finding::new(Severity::Medium, MODULE, "NET-WG-PEER", format!("WireGuard peer that no configuration file lists: {key}"))
                .evidence(format!("interface {iface}\npeer {key}\nendpoint {endpoint}\nallowed addresses {allowed}"))
                .description("The peer was added while the tunnel was running and is not written down. It can reach this machine until the next restart of the tunnel.")
                .verify("wg show")
                .verify(format!("grep -rl -F -- {} /etc/wireguard /etc/NetworkManager /etc/systemd/network", shq(&key))),
        );
    }
}

/// Does this `ssh` command line open a tunnel from the other end back to here?
pub fn is_reverse_ssh(args: &[String]) -> bool {
    // options that take a value end a group of flags: "-NfR8080:…" is -N -f -R
    const PLAIN: &str = "1246AaCfGgKkMNnqsTtVvXxYy";
    args.iter().skip(1).enumerate().any(|(i, a)| {
        let option = a.strip_prefix('-').filter(|o| !o.starts_with('-')).unwrap_or("");
        let dash_r = option.chars().find(|c| !PLAIN.contains(*c)) == Some('R');
        let next = args.get(i + 2).map(String::as_str).unwrap_or("");
        dash_r || (option == "o" && next.starts_with("RemoteForward")) || option.starts_with("oRemoteForward")
    })
}

fn describe(p: &ProcInfo) -> String {
    format!("PID {} UID {} exe={}\ncmdline=\"{}\"", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 300))
}

fn check_programs(ctx: &ScanCtx, col: &mut Collector) {
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread()) {
        let exe = p.exe_path().unwrap_or("");
        let system = ["/usr/", "/opt/", "/snap/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
        if let Some(name) = p.candidate_names().into_iter().find(|n| ctx.cfg.tunnel_programs.contains(n)) {
            col.push(
                Finding::new(if system { Severity::Medium } else { Severity::High }, MODULE, "NET-TUNNEL-PROGRAM", format!("Tunnelling program is running: {name}"))
                    .evidence(describe(p))
                    .description("This program makes the machine, or a service on it, reachable from outside through another server, without opening a port here. Developers use such tools on purpose; if you did not start it, stop and investigate.")
                    .verify(format!("ps -o pid,user,etime,cmd -p {}", p.pid))
                    .verify(format!("ss -tunap | grep 'pid={},'", p.pid)),
            );
        }
        let ssh = ["ssh", "autossh"].contains(&p.display_name().as_str()) || p.comm == "autossh";
        if ssh && is_reverse_ssh(&p.cmdline) {
            col.push(
                Finding::new(if p.uid == 0 { Severity::High } else { Severity::Medium }, MODULE, "NET-SSH-REVERSE", "Reverse SSH tunnel is open")
                    .evidence(describe(p))
                    .description("ssh -R lets the other computer connect back into this one (or your network) through the encrypted connection, past any firewall. Check that you set it up.")
                    .verify(format!("ps -o pid,user,etime,cmd -p {}", p.pid))
                    .verify(format!("ss -tunap | grep 'pid={},'", p.pid)),
            );
        }
    }
    let accounts = crate::procinfo::read_accounts(ctx.sys);
    let mut configs = vec!["/etc/ssh/ssh_config".to_string()];
    configs.extend(ctx.sys.dir_names("/etc/ssh/ssh_config.d").into_iter().map(|n| format!("/etc/ssh/ssh_config.d/{n}")));
    configs.extend(super::persistence::home_dirs(ctx, &accounts).into_iter().map(|(_, _, h)| format!("{h}/.ssh/config")));
    for path in configs {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        check_agent_forwarding(col, &path, &text);
        let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| l.to_lowercase().starts_with("remoteforward")).collect();
        if !lines.is_empty() {
            col.push(
                Finding::new(Severity::Low, MODULE, "NET-SSH-REVERSE", format!("SSH settings open reverse tunnels: {path}"))
                    .evidence(format!("{path}\n{}", clip(&lines.join("\n"), 600)))
                    .description("Every connection that uses this setting lets the other computer connect back. Check that you added it.")
                    .verify(format!("grep -in remoteforward {}", shq(&path))),
            );
        }
    }
}

/// The hosts for which an SSH client file forwards the key agent ("*" = every server).
pub fn agent_forwarding(text: &str) -> Vec<String> {
    let mut host = "*".to_string();
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        let mut words = line.split(|c: char| c.is_whitespace() || c == '=').filter(|w| !w.is_empty());
        let key = words.next().unwrap_or("").to_ascii_lowercase();
        let value: Vec<&str> = words.collect();
        if key == "host" || key == "match" {
            host = value.join(" ");
        } else if key == "forwardagent" && value.first().map(|v| v.eq_ignore_ascii_case("yes")).unwrap_or(false) {
            out.push(host.clone());
        }
    }
    out
}

fn check_agent_forwarding(col: &mut Collector, path: &str, text: &str) {
    let hosts = agent_forwarding(text);
    if hosts.is_empty() {
        return;
    }
    let everyone = hosts.iter().any(|h| h.split_whitespace().any(|w| w == "*"));
    col.push(
        Finding::new(if everyone { Severity::Medium } else { Severity::Low }, MODULE, "NET-SSH-AGENT", format!("SSH forwards your key agent: {path}"))
            .evidence(format!("{path}\nForwardAgent yes for: {}", clip(&hosts.join(", "), 400)))
            .description("A server you log in to can use your keys while the connection is open. With 'Host *' every server can, including a compromised one. Forward only to hosts you trust, or use ProxyJump.")
            .verify(format!("grep -n -i -B3 forwardagent {}", shq(path))),
    );
}

pub(crate) fn run(ctx: &ScanCtx, col: &mut Collector) {
    check_interfaces(ctx, col);
    check_programs(ctx, col);
}
