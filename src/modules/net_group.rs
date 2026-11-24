//! Merges the one-finding-per-port noise from net_proc: all unknown ports of one program
//! become a single finding, and all NFS-explained ownerless sockets become a single finding.

use super::Collector;
use crate::finding::{Finding, Severity};

/// Short, practical notes for well-known services that show up as "unknown" ports.
fn service_note(name: &str) -> Option<&'static str> {
    match name {
        "rpcbind" | "rpc.statd" => Some(
            " rpcbind and rpc.statd are the helpers for NFSv3 mounts and NFS file locking, so they are expected when you mount NFS shares. If you only use NFSv4 you can switch them off with: systemctl disable --now rpcbind.socket rpcbind.service rpc-statd.service (as root).",
        ),
        "dnsmasq" => Some(" This dnsmasq is probably the one libvirt/virt-manager starts for its virtual network (check the command line in the evidence)."),
        "tailscaled" => Some(" tailscaled is the Tailscale VPN daemon."),
        _ => None,
    }
}

fn pid_of_evidence(evidence: &str) -> Option<&str> {
    evidence.strip_prefix("PID ")?.split_whitespace().next()
}

/// "Unknown listening port tcp/111 (rpcbind)" → "tcp/111"
fn port_in_title(title: &str) -> String {
    title.split("port ").nth(1).and_then(|r| r.split(" (").next()).unwrap_or("?").to_string()
}

/// "Listening socket without a visible owner process: tcp/37393" → "tcp/37393"
fn orphan_port(title: &str) -> String {
    title.rsplit(": ").next().unwrap_or("?").to_string()
}

/// "Unknown listening ports: tcp/111, udp/111 (rpcbind)" → "rpcbind"
pub fn process_in_title(title: &str) -> Option<String> {
    let start = title.rfind('(')?;
    let end = title.rfind(')')?;
    (end > start + 1).then(|| title[start + 1..end].to_string())
}

/// Group the findings added since index `from`.
pub fn group_listener_findings(col: &mut Collector, from: usize) {
    let tail: Vec<Finding> = col.findings.split_off(from);
    let mut keep: Vec<Finding> = Vec::new();
    let mut by_pid: Vec<(String, Vec<Finding>)> = Vec::new();
    let mut orphans: Vec<Finding> = Vec::new();
    for f in tail {
        if f.rule == "NET-LISTEN-UNKNOWN" {
            let pid = pid_of_evidence(&f.evidence).unwrap_or("?").to_string();
            match by_pid.iter_mut().find(|(p, _)| *p == pid) {
                Some((_, v)) => v.push(f),
                None => by_pid.push((pid, vec![f])),
            }
        } else if f.rule == "NET-ORPHAN-LISTEN" && f.severity == Severity::Low && f.evidence.contains("kernel thread") {
            orphans.push(f);
        } else {
            keep.push(f);
        }
    }
    for (pid, mut group) in by_pid {
        let mut first = group.remove(0);
        let name = process_in_title(&first.title).unwrap_or_default();
        let mut ports = vec![port_in_title(&first.title)];
        for g in &group {
            ports.push(port_in_title(&g.title));
            if g.severity > first.severity {
                first.severity = g.severity;
            }
            if let Some(sock) = g.evidence.lines().nth(1) {
                first.evidence.push('\n');
                first.evidence.push_str(sock);
            }
        }
        ports.sort();
        ports.dedup();
        let shown: Vec<String> = ports.iter().take(8).cloned().collect();
        let more = if ports.len() > 8 { format!(" +{} more", ports.len() - 8) } else { String::new() };
        first.title = format!("Unknown listening ports: {}{more} ({name})", shown.join(", "));
        if let Some(note) = service_note(&name) {
            first.description.push_str(note);
        }
        first.verify = vec![
            format!("ss -tulpn | grep 'pid={pid},'"),
            format!("dpkg -S $(readlink -f /proc/{pid}/exe)"),
            format!("systemctl status {pid}"),
        ];
        keep.push(first);
    }
    if !orphans.is_empty() {
        let mut first = orphans.remove(0);
        let mut ports = vec![orphan_port(&first.title)];
        let mut sockets = vec![first.evidence.lines().next().unwrap_or("").to_string()];
        for o in &orphans {
            ports.push(orphan_port(&o.title));
            sockets.push(o.evidence.lines().next().unwrap_or("").to_string());
        }
        ports.sort();
        ports.dedup();
        let mount = first.evidence.lines().nth(1).unwrap_or("").to_string();
        first.title = format!("Listening sockets without an owner process (kernel NFS client): {}", ports.join(", "));
        first.evidence = format!("{}\n{mount}", sockets.join("\n"));
        first.verify = vec!["grep nfs /proc/mounts; rpcinfo -p".into(), "ss -tulpn".into()];
        keep.push(first);
    }
    col.findings.extend(keep);
}
