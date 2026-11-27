//! The firewall (part of `net_proc`): whether anything stops incoming connections at all, and
//! rules that let one address on the internet in. Read from the loaded nftables rules (root),
//! otherwise from the settings of nftables, ufw and firewalld.

use super::common::clip;
use super::net_proc::MODULE;
use super::netwatch::is_public;
use super::persistence::record;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use std::collections::BTreeSet;
use std::net::IpAddr;

/// What a rule set does with incoming traffic.
#[derive(Debug, Default, PartialEq)]
pub struct Ruleset {
    /// Something refuses incoming traffic that no rule allows.
    pub protects: bool,
    /// Rules that accept everything from an address on the internet.
    pub public_allows: Vec<String>,
}

/// A rule without its packet counter.
fn without_counter(rule: &str) -> String {
    let words: Vec<&str> = rule.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        if words[i] == "counter" {
            i += if words.get(i + 1) == Some(&"packets") { 5 } else { 1 };
        } else {
            out.push(words[i]);
            i += 1;
        }
    }
    out.join(" ")
}

/// The addresses a rule takes packets from ("ip saddr 1.2.3.4" or "ip saddr { a, b }").
fn sources(rule: &str) -> Vec<IpAddr> {
    let Some((_, rest)) = rule.split_once("ip saddr ").or_else(|| rule.split_once("ip6 saddr ")) else { return Vec::new() };
    let list = match rest.strip_prefix('{') {
        Some(set) => set.split('}').next().unwrap_or(""),
        None => rest.split_whitespace().next().unwrap_or(""),
    };
    list.split(',').filter_map(|a| a.trim().split(['/', '-']).next()?.parse().ok()).collect()
}

/// Read the output of `nft list ruleset` (or an nftables settings file).
pub fn read_ruleset(text: &str) -> Ruleset {
    let mut out = Ruleset::default();
    let (mut chain, mut incoming) = (String::new(), false);
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if let Some(rest) = line.strip_prefix("chain ") {
            chain = rest.trim_end_matches('{').trim().to_string();
            incoming = chain.to_ascii_lowercase().contains("input");
        } else if line == "}" {
            incoming = false;
        } else if line.starts_with("type ") && line.contains("hook ") {
            incoming = line.contains("hook input");
            out.protects |= incoming && line.contains("policy drop");
        } else if incoming {
            let rule = without_counter(line);
            // "policy drop;" may stand on its own line in a settings file
            out.protects |= rule.starts_with("policy drop") || ["drop", "reject"].contains(&rule.split_whitespace().next().unwrap_or(""));
            let narrowed = ["dport", "sport", "iifname", "iif ", "ct state", "!="].iter().any(|w| rule.contains(w));
            if !narrowed && rule.split_whitespace().any(|w| w == "accept") && sources(&rule).iter().any(is_public) {
                out.public_allows.push(format!("chain {chain}: {rule}"));
            }
        }
    }
    out
}

/// What the settings switch on, without asking the kernel.
fn from_settings(ctx: &ScanCtx) -> Vec<String> {
    let mut on = Vec::new();
    let enabled = |unit: &str| ["sysinit.target.wants", "multi-user.target.wants", "basic.target.wants"].iter().any(|d| ctx.sys.read_link(format!("/etc/systemd/system/{d}/{unit}")).is_some() || ctx.sys.exists(format!("/etc/systemd/system/{d}/{unit}")));
    if ctx.sys.read_string("/etc/ufw/ufw.conf").map(|t| t.lines().any(|l| l.trim().eq_ignore_ascii_case("ENABLED=yes"))).unwrap_or(false) {
        on.push("ufw is switched on".to_string());
    }
    if enabled("nftables.service") && ctx.sys.read_string("/etc/nftables.conf").map(|t| read_ruleset(&t).protects || t.contains("include ")).unwrap_or(false) {
        on.push("nftables loads rules from /etc/nftables.conf".to_string());
    }
    if enabled("firewalld.service") || ctx.processes.iter().any(|p| p.display_name() == "firewalld") {
        on.push("firewalld is switched on".to_string());
    }
    on
}

/// Ports that listen to every network, for the finding's evidence.
fn open_ports(col: &Collector) -> String {
    let ports: BTreeSet<(u16, String)> = col
        .inventory
        .connections
        .iter()
        .filter(|c| c.listening && matches!(c.local_addr.as_str(), "0.0.0.0" | "::" | "[::]" | "*"))
        .map(|c| (c.local_port, format!("{}/{}", c.proto.trim_end_matches('6'), c.local_port)))
        .collect();
    let list: Vec<String> = ports.into_iter().map(|p| p.1).collect::<BTreeSet<_>>().into_iter().collect();
    if list.is_empty() {
        "no port listens to every network right now".to_string()
    } else {
        format!("listening to every network: {}", clip(&list.join(", "), 400))
    }
}

pub(crate) fn run(ctx: &ScanCtx, col: &mut Collector) {
    for path in ["/etc/ufw/ufw.conf", "/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/ufw/before.rules", "/etc/ufw/after.rules", "/etc/nftables.conf"] {
        record(ctx, col, path);
    }
    for dir in ["/etc/firewalld", "/etc/firewalld/zones", "/etc/firewalld/direct"] {
        for name in ctx.sys.dir_names(dir) {
            record(ctx, col, &format!("{dir}/{name}"));
        }
    }
    let live = (ctx.sys.is_live() && ctx.privileged)
        .then(|| crate::external_tools::find_binary("nft"))
        .flatten()
        .and_then(|nft| crate::external_tools::run_capture(&nft, &["list", "ruleset"], 30).ok())
        .filter(|o| o.status == Some(0))
        .map(|o| read_ruleset(&o.stdout));
    if let Some(rules) = &live {
        if !rules.public_allows.is_empty() {
            col.push(
                Finding::new(Severity::Medium, MODULE, "NET-FIREWALL-ALLOW", "The firewall lets everything from certain internet addresses in")
                    .evidence(clip(&rules.public_allows.join("\n"), 900))
                    .description("These rules accept every connection from an address on the internet. A server of your own or a VPN may need one; an intruder adds one to get back in.")
                    .verify("nft list ruleset"),
            );
        }
    }
    let settings = from_settings(ctx);
    let protects = live.as_ref().map(|r| r.protects).unwrap_or(false) || live.is_none() && !settings.is_empty();
    // only a certain answer goes into the baseline
    if ctx.privileged {
        col.inventory.boot.insert("firewall".into(), if protects { "on" } else { "off" }.into());
    }
    if protects {
        return;
    }
    let (severity, how) = if live.is_some() {
        (Severity::Low, "the loaded rules refuse no incoming traffic")
    } else if ctx.privileged {
        (Severity::Low, "ufw, nftables and firewalld are not switched on")
    } else {
        (Severity::Info, "ufw, nftables and firewalld are not switched on (run as root to see the loaded rules)")
    };
    col.push(
        Finding::new(severity, MODULE, "NET-NO-FIREWALL", "No firewall stops incoming connections")
            .evidence(format!("{how}\n{}", open_ports(col)))
            .description("Every program that listens can be reached from the networks this computer joins. A home router protects against the internet, not against others on the same network. A simple choice: sudo apt install ufw && sudo ufw enable.")
            .verify("nft list ruleset")
            .verify("ufw status verbose"),
    );
}
