//! The firewall (part of `net_proc`): whether anything stops incoming connections at all, rules
//! that let an address on the internet in, and every accept rule (for the baseline). Read from the
//! loaded rules (root: nftables and the old iptables-legacy), otherwise from the settings of
//! nftables, ufw and firewalld.

use super::common::clip;
use super::net_proc::MODULE;
use super::netwatch::is_public;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// What a rule set does with incoming traffic.
#[derive(Debug, Default, PartialEq)]
pub struct Ruleset {
    /// Something refuses incoming traffic that no rule allows.
    pub protects: bool,
    /// Incoming rules that accept something from an address on the internet.
    pub public_allows: Vec<String>,
    /// Every accept rule without counters, as "incoming …" or "other …".
    pub accepts: BTreeSet<String>,
}

impl Ruleset {
    pub fn merge(&mut self, other: Ruleset) {
        self.protects |= other.protects;
        self.public_allows.extend(other.public_allows);
        self.accepts.extend(other.accepts);
    }
}

/// One chain of a table, with its rules.
#[derive(Default)]
struct Chain {
    /// The chain the kernel runs for incoming packets, or one named after it.
    incoming: bool,
    rules: Vec<String>,
}

/// A rule without its packet counter, rule number and time left.
fn without_counter(rule: &str) -> String {
    let rule = rule.split(" # handle ").next().unwrap_or(rule);
    let words: Vec<&str> = rule.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < words.len() {
        match words[i] {
            "counter" => i += if words.get(i + 1) == Some(&"packets") { 5 } else { 1 },
            "expires" => i += 2,
            word => {
                out.push(word);
                i += 1;
            }
        }
    }
    out.join(" ")
}

/// The addresses of a list such as "1.2.3.4, 10.0.0.0/8, 192.0.2.1-192.0.2.9".
fn addresses(list: &str) -> impl Iterator<Item = IpAddr> + '_ {
    list.split(',').filter_map(|a| a.split_whitespace().next()?.split(['/', '-']).next()?.parse().ok())
}

/// The addresses an nftables rule takes packets from ("ip saddr 1.2.3.4", "ip saddr { a, b }" or
/// "ip saddr @name" with the set's members).
fn sources(rule: &str, sets: &BTreeMap<String, String>) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for (_, rest) in ["ip saddr ", "ip6 saddr "].iter().filter_map(|key| rule.split_once(key)) {
        let list = if let Some(set) = rest.strip_prefix('{') {
            set.split('}').next().unwrap_or("")
        } else if let Some(name) = rest.strip_prefix('@') {
            sets.get(name.split_whitespace().next().unwrap_or("")).map(String::as_str).unwrap_or("")
        } else {
            rest.split_whitespace().next().unwrap_or("")
        };
        out.extend(addresses(list));
    }
    out
}

/// Chains that incoming packets reach: the incoming ones and those they jump to.
fn reached(chains: &BTreeMap<String, Chain>, targets: impl Fn(&str) -> Vec<String>) -> BTreeSet<String> {
    let mut found: BTreeSet<String> = chains.iter().filter(|(_, c)| c.incoming).map(|(n, _)| n.clone()).collect();
    let mut queue: Vec<String> = found.iter().cloned().collect();
    while let Some(name) = queue.pop() {
        for next in chains.get(&name).into_iter().flat_map(|c| &c.rules).flat_map(|r| targets(r)) {
            if chains.contains_key(&next) && found.insert(next.clone()) {
                queue.push(next);
            }
        }
    }
    found
}

/// A rule that only lets replies to this computer's own connections through.
fn replies_only(rule: &str) -> bool {
    let rule = rule.to_ascii_lowercase();
    ["ct state ", "--ctstate ", "--state "].iter().any(|key| rule.split_once(key).is_some_and(|(_, rest)| {
        let states = if let Some(set) = rest.strip_prefix('{') { set.split('}').next().unwrap_or("") } else { rest.split_whitespace().next().unwrap_or("") };
        !states.contains("new") && !states.contains('!')
    }))
}

/// One table's chains, judged: which accept rules there are and who they let in.
fn judge_table(table: &str, chains: &BTreeMap<String, Chain>, sets: &BTreeMap<String, String>, out: &mut Ruleset) {
    let jumps = |rule: &str| -> Vec<String> {
        let words: Vec<&str> = rule.split_whitespace().collect();
        words.windows(2).filter(|w| w[0] == "jump" || w[0] == "goto").map(|w| w[1].trim_matches([',', '}']).to_string()).collect()
    };
    let incoming = reached(chains, jumps);
    for (name, chain) in chains {
        let into = incoming.contains(name);
        for rule in &chain.rules {
            if !rule.split_whitespace().any(|w| w.trim_matches([',', '}']) == "accept") {
                continue;
            }
            // the members of a named set belong to the rule: a new member is a new permission
            let members: Vec<String> = rule
                .split_whitespace()
                .filter_map(|w| w.strip_prefix('@'))
                .filter_map(|n| sets.get(n.trim_matches([',', '}'])).map(|m| format!("[@{n} = {m}]")))
                .collect();
            let shown = format!("{rule} {}", members.join(" "));
            out.accepts.insert(format!("{} {table} {name}: {}", if into { "incoming" } else { "other" }, shown.trim_end()));
            if into && !replies_only(rule) && sources(rule, sets).iter().any(is_public) {
                out.public_allows.push(format!("chain {name}: {}", shown.trim_end()));
            }
        }
    }
}

/// Read the output of `nft list ruleset` (or an nftables settings file).
pub fn read_ruleset(text: &str) -> Ruleset {
    let mut out = Ruleset::default();
    let mut table = String::new();
    let mut chains: BTreeMap<String, Chain> = BTreeMap::new();
    let mut sets: BTreeMap<String, String> = BTreeMap::new();
    let mut chain = String::new();
    // the set being read: its name and text so far
    let mut set: Option<(String, String, i32)> = None;
    let braces = |l: &str| l.matches('{').count() as i32 - l.matches('}').count() as i32;
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        if let Some((name, body, depth)) = &mut set {
            body.push(' ');
            body.push_str(line);
            *depth += braces(line);
            if *depth <= 0 {
                if let Some((_, rest)) = body.split_once("elements = {") {
                    let list = rest.split('}').next().unwrap_or("");
                    let members: BTreeSet<String> = list.split(',').map(without_counter).filter(|m| !m.is_empty()).collect();
                    sets.insert(name.clone(), members.into_iter().collect::<Vec<_>>().join(", "));
                }
                set = None;
            }
        } else if let Some(rest) = line.strip_prefix("table ") {
            judge_table(&table, &chains, &sets, &mut out);
            table = rest.split('{').next().unwrap_or("").trim().to_string();
            chains.clear();
            sets.clear();
        } else if let Some(rest) = line.strip_prefix("set ").or_else(|| line.strip_prefix("map ")).filter(|r| r.ends_with('{')) {
            set = Some((rest.trim_end_matches('{').trim().to_string(), String::new(), 1));
        } else if let Some(rest) = line.strip_prefix("chain ") {
            chain = rest.split('{').next().unwrap_or("").trim().to_string();
            let named_incoming = chain.to_ascii_lowercase().contains("input");
            chains.entry(chain.clone()).or_default().incoming = named_incoming;
        } else if line == "}" {
            chain.clear();
        } else if line.starts_with("type ") && line.contains("hook ") {
            let hooked = line.contains("hook input");
            chains.entry(chain.clone()).or_default().incoming = hooked;
            out.protects |= hooked && line.contains("policy drop");
        } else if !chain.is_empty() {
            let rule = without_counter(line);
            let entry = chains.entry(chain.clone()).or_default();
            // "policy drop;" may stand on its own line in a settings file
            out.protects |= entry.incoming && (rule.starts_with("policy drop") || ["drop", "reject"].contains(&rule.split_whitespace().next().unwrap_or("")));
            entry.rules.push(rule);
        }
    }
    judge_table(&table, &chains, &sets, &mut out);
    out
}

/// Read what `iptables-legacy-save` (`family` "ip") or `ip6tables-legacy-save` ("ip6") prints.
pub fn read_iptables(saved: &str, family: &str) -> Ruleset {
    let mut out = Ruleset::default();
    let mut table = "";
    let mut chains: BTreeMap<String, Chain> = BTreeMap::new();
    for line in saved.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix('*') {
            table = name;
            chains.clear();
        } else if let Some(rest) = line.strip_prefix(':') {
            let mut words = rest.split_whitespace();
            let name = words.next().unwrap_or("").to_string();
            let incoming = table == "filter" && name.to_ascii_lowercase().contains("input");
            out.protects |= table == "filter" && name == "INPUT" && words.next() == Some("DROP");
            chains.entry(name).or_default().incoming = incoming;
        } else if let Some(rest) = line.strip_prefix("-A ") {
            let (name, rule) = rest.split_once(' ').unwrap_or((rest, ""));
            chains.entry(name.to_string()).or_default().rules.push(rule.to_string());
        } else if line == "COMMIT" {
            let jumps = |rule: &str| -> Vec<String> {
                let words: Vec<&str> = rule.split_whitespace().collect();
                words.windows(2).filter(|w| w[0] == "-j" || w[0] == "-g").map(|w| w[1].to_string()).collect()
            };
            let incoming = reached(&chains, jumps);
            for (name, chain) in &chains {
                let into = table == "filter" && incoming.contains(name);
                for rule in &chain.rules {
                    let words: Vec<&str> = rule.split_whitespace().collect();
                    let target = words.windows(2).find(|w| w[0] == "-j").map(|w| w[1]);
                    // a refusal without any condition
                    let bare = matches!(words.as_slice(), ["-j", "DROP" | "REJECT"] | ["-j", "REJECT", "--reject-with", _]);
                    out.protects |= table == "filter" && chain.incoming && bare;
                    if target != Some("ACCEPT") {
                        continue;
                    }
                    out.accepts.insert(format!("{} iptables-legacy {family} {table} {name}: {rule}", if into { "incoming" } else { "other" }));
                    let from_public = words.iter().enumerate().any(|(i, w)| {
                        matches!(*w, "-s" | "--source") && (i == 0 || words[i - 1] != "!") && words.get(i + 1).is_some_and(|list| addresses(list).any(|a| is_public(&a)))
                    });
                    if into && from_public && !replies_only(rule) {
                        out.public_allows.push(format!("chain {name}: {rule}  (iptables-legacy)"));
                    }
                }
            }
            chains.clear();
        }
    }
    out
}

/// What `iptables-legacy-save` and its IPv6 twin print. Only asked when the old system has tables
/// loaded: asking otherwise could make the kernel load them.
pub(crate) fn legacy_saved(ctx: &ScanCtx) -> Vec<(&'static str, String)> {
    if !ctx.sys.is_live() || !ctx.privileged {
        return Vec::new();
    }
    [("ip", "iptables-legacy-save", "/proc/net/ip_tables_names"), ("ip6", "ip6tables-legacy-save", "/proc/net/ip6_tables_names")]
        .into_iter()
        .filter(|(_, _, loaded)| ctx.sys.read_string(loaded).map(|t| !t.trim().is_empty()).unwrap_or(false))
        .filter_map(|(family, program, _)| {
            let program = crate::external_tools::find_binary(program)?;
            let out = crate::external_tools::run_capture(&program, &[], 30).ok().filter(|o| o.status == Some(0))?;
            Some((family, out.stdout))
        })
        .collect()
}

/// The loaded rules, if any of the two systems could be asked.
fn loaded_rules(ctx: &ScanCtx) -> Option<Ruleset> {
    if !ctx.sys.is_live() || !ctx.privileged {
        return None;
    }
    let nft = crate::external_tools::find_binary("nft")
        .and_then(|nft| crate::external_tools::run_capture(&nft, &["list", "ruleset"], 30).ok())
        .filter(|o| o.status == Some(0))
        .map(|o| read_ruleset(&o.stdout));
    let legacy = legacy_saved(ctx);
    if nft.is_none() && legacy.is_empty() {
        return None;
    }
    let mut rules = nft.unwrap_or_default();
    for (family, saved) in legacy {
        rules.merge(read_iptables(&saved, family));
    }
    Some(rules)
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
    let live = loaded_rules(ctx);
    if let Some(rules) = &live {
        col.inventory.firewall_rules = Some(rules.accepts.iter().cloned().collect());
        if !rules.public_allows.is_empty() {
            col.push(
                Finding::new(Severity::Medium, MODULE, "NET-FIREWALL-ALLOW", "The firewall lets certain internet addresses in")
                    .evidence(clip(&rules.public_allows.join("\n"), 900))
                    .description("These rules accept connections from an address on the internet, to every port or to the ports they name. A server of your own or a VPN may need one; an intruder adds one to get back in.")
                    .verify("nft list ruleset")
                    .verify("iptables-legacy-save"),
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
