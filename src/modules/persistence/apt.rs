//! Software sources (apt): sources that skip signature checks, sources outside Debian, and
//! commands that apt runs by itself.

use super::{record, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_command, clip, max_severity, reasons, shq, CmdIssue};
use crate::modules::{Collector, ScanCtx};
use crate::pkgverify::owned_paths;
use std::collections::BTreeMap;

/// One software source from a `.list` or `.sources` file.
#[derive(Debug, Clone, PartialEq)]
pub struct AptSource {
    pub uri: String,
    /// The suites it provides ("trixie", "trixie-security" …).
    pub suites: String,
    /// Signature checks are switched off for this source.
    pub unsigned: bool,
    /// Where it was found: "file:line".
    pub origin: String,
}

fn yes(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on" | "enable")
}

/// The one-line format: `deb [trusted=yes] http://host/debian trixie main`.
pub fn parse_list(path: &str, text: &str) -> Vec<AptSource> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((kind, mut rest)) = line.split_once(char::is_whitespace) else { continue };
        if kind != "deb" && kind != "deb-src" {
            continue;
        }
        rest = rest.trim_start();
        let mut unsigned = false;
        if let Some(options) = rest.strip_prefix('[') {
            let Some((options, tail)) = options.split_once(']') else { continue };
            unsigned = options.split_whitespace().any(|o| o.split_once('=').map(|(k, v)| (k == "trusted" || k == "allow-insecure") && yes(v)).unwrap_or(false));
            rest = tail.trim_start();
        }
        let mut words = rest.split_whitespace();
        let Some(uri) = words.next() else { continue };
        let suites = words.next().unwrap_or("").to_string();
        out.push(AptSource { uri: uri.to_string(), suites, unsigned, origin: format!("{path}:{}", i + 1) });
    }
    out
}

/// The deb822 format: stanzas of `Key: value`, separated by empty lines.
pub fn parse_deb822(path: &str, text: &str) -> Vec<AptSource> {
    let mut out = Vec::new();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut key = String::new();
    let mut start = 0;
    for (i, line) in text.lines().chain(std::iter::once("")).enumerate() {
        if line.starts_with('#') {
            continue;
        }
        if line.trim().is_empty() {
            let enabled = fields.get("enabled").map(|v| !matches!(v.trim().to_ascii_lowercase().as_str(), "no" | "false" | "0" | "off")).unwrap_or(true);
            if enabled {
                let unsigned = ["trusted", "allow-insecure"].iter().any(|k| fields.get(*k).map(|v| yes(v)).unwrap_or(false));
                for uri in fields.get("uris").map(|u| u.as_str()).unwrap_or("").split_whitespace() {
                    let suites = fields.get("suites").cloned().unwrap_or_default();
                    out.push(AptSource { uri: uri.to_string(), suites, unsigned, origin: format!("{path}:{}", start + 1) });
                }
            }
            fields.clear();
            key.clear();
        } else if line.starts_with(char::is_whitespace) {
            if let Some(v) = fields.get_mut(&key) {
                v.push(' ');
                v.push_str(line.trim());
            }
        } else if let Some((k, v)) = line.split_once(':') {
            if fields.is_empty() {
                start = i;
            }
            key = k.trim().to_ascii_lowercase();
            fields.insert(key.clone(), v.trim().to_string());
        }
    }
    out
}

/// "http://user:pw@host:80/debian" → "host"
pub fn host_of(uri: &str) -> Option<String> {
    let (_, rest) = uri.split_once("://")?;
    let authority = rest.split('/').next()?;
    let host = authority.rsplit('@').next()?;
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next()?,
        None => host.split(':').next()?,
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn trusted_host(host: &str, trusted: &[String]) -> bool {
    trusted.iter().any(|t| match t.strip_prefix("*.") {
        Some(domain) => host == domain || host.ends_with(&format!(".{domain}")),
        None => host.eq_ignore_ascii_case(t),
    })
}

/// Every enabled software source, with the files they come from.
pub fn read_sources(ctx: &ScanCtx) -> (Vec<AptSource>, Vec<String>) {
    let mut sources = Vec::new();
    let mut files = Vec::new();
    if let Ok(text) = ctx.sys.read_string("/etc/apt/sources.list") {
        files.push("/etc/apt/sources.list".to_string());
        sources.extend(parse_list("/etc/apt/sources.list", &text));
    }
    for name in ctx.sys.dir_names("/etc/apt/sources.list.d") {
        let path = format!("/etc/apt/sources.list.d/{name}");
        // apt ignores other files (.bak, .save, .distUpgrade)
        let list = name.ends_with(".list");
        if !list && !name.ends_with(".sources") {
            continue;
        }
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        sources.extend(if list { parse_list(&path, &text) } else { parse_deb822(&path, &text) });
        files.push(path);
    }
    (sources, files)
}

pub fn check_apt(ctx: &ScanCtx, col: &mut Collector) {
    let (sources, files) = read_sources(ctx);
    for path in files {
        record(ctx, col, &path);
    }
    // the keys apt trusts
    for dir in ["/etc/apt/trusted.gpg.d", "/etc/apt/keyrings", "/etc/apt/preferences.d"] {
        for name in ctx.sys.dir_names(dir) {
            record(ctx, col, &format!("{dir}/{name}"));
        }
    }
    record(ctx, col, "/etc/apt/trusted.gpg");

    let mut third_party: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for s in &sources {
        let line = format!("{} {}", s.origin, s.uri);
        if s.unsigned {
            col.push(
                Finding::new(Severity::Medium, MODULE, "PERS-APT-UNSIGNED", format!("Software source without signature check: {}", s.uri))
                    .evidence(line.clone())
                    .description("trusted=yes or allow-insecure=yes makes apt install packages from here without checking who made them. Whoever controls the server or the network can install anything as root.")
                    .verify(format!("cat {}", shq(s.origin.rsplit_once(':').map(|(p, _)| p).unwrap_or(&s.origin))))
                    .verify("apt-cache policy"),
            );
        }
        if let Some(path) = s.uri.strip_prefix("file:") {
            let path = path.trim_start_matches('/');
            let path = format!("/{path}");
            if ctx.cfg.is_temp_path(&path) || path.starts_with("/home/") {
                third_party.entry(path).or_default().push(line);
            }
        } else if let Some(host) = host_of(&s.uri) {
            if !trusted_host(&host, &ctx.cfg.trusted_apt_hosts) {
                third_party.entry(host).or_default().push(line);
            }
        }
    }
    for (host, mut lines) in third_party {
        lines.sort();
        lines.dedup();
        col.push(
            Finding::new(Severity::Low, MODULE, "PERS-APT-THIRDPARTY", format!("Software source outside Debian: {host}"))
                .evidence(clip(&lines.join("\n"), 600))
                .description("Packages from this source can run anything as root when they are installed or upgraded. Check that you added it yourself; then add the host to trusted_apt_hosts.")
                .verify("grep -rn . /etc/apt/sources.list /etc/apt/sources.list.d/")
                .verify("apt-cache policy"),
        );
    }

    check_hooks(ctx, col);
    check_settings(ctx, col);
    check_keyrings(ctx, col);
}

/// apt.conf settings as ("Acquire::http::Proxy", value), from both the flat form and blocks.
pub fn apt_settings(text: &str) -> Vec<(String, String)> {
    let text: String = text.lines().filter(|l| !l.trim_start().starts_with('#') && !l.trim_start().starts_with("//")).collect::<Vec<_>>().join("\n");
    let mut out = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut name: Option<String> = None;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                let value: String = chars.by_ref().take_while(|c| *c != '"').collect();
                if let Some(key) = &name {
                    let mut full = stack.clone();
                    full.push(key.clone());
                    out.push((full.join("::"), value));
                }
            }
            '{' => stack.push(name.take().unwrap_or_default()),
            '}' => {
                stack.pop();
            }
            ';' => name = None,
            c if c.is_whitespace() => {}
            c => {
                let mut word = c.to_string();
                while let Some(next) = chars.peek().filter(|n| !n.is_whitespace() && !"\"{};".contains(**n)) {
                    word.push(*next);
                    chars.next();
                }
                name = Some(word);
            }
        }
    }
    out
}

/// A setting that weakens or reroutes downloads: (severity, why).
pub fn judge_apt_setting(key: &str, value: &str) -> Option<(Severity, &'static str)> {
    let key = key.to_ascii_lowercase();
    let on = yes(value);
    let off = matches!(value.trim().to_ascii_lowercase().as_str(), "false" | "no" | "0" | "off");
    if ["allowinsecurerepositories", "allowdowngradetoinsecurerepositories", "allowunauthenticated"].iter().any(|k| key.ends_with(k)) && on {
        Some((Severity::Medium, "installs without checking signatures"))
    } else if (key.ends_with("verify-peer") || key.ends_with("verify-host")) && off {
        Some((Severity::Medium, "does not check the server's certificate"))
    } else if key.ends_with("check-valid-until") && off {
        Some((Severity::Low, "accepts old, outdated package lists"))
    } else if key.starts_with("acquire::") && (key.ends_with("::proxy") || key.ends_with("proxy-auto-detect")) && !value.is_empty() && value != "DIRECT" {
        Some((Severity::Low, "downloads go through another server"))
    } else {
        None
    }
}

/// "http://user:secret@proxy:3128" → "http://proxy:3128"
fn without_password(value: &str) -> String {
    match value.split_once("://") {
        Some((scheme, rest)) => format!("{scheme}://{}", rest.rsplit('@').next().unwrap_or(rest)),
        None => value.to_string(),
    }
}

fn check_settings(ctx: &ScanCtx, col: &mut Collector) {
    let mut files = vec!["/etc/apt/apt.conf".to_string()];
    files.extend(ctx.sys.dir_names("/etc/apt/apt.conf.d").into_iter().map(|n| format!("/etc/apt/apt.conf.d/{n}")));
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        let found: Vec<(Severity, String)> = apt_settings(&text)
            .into_iter()
            .filter_map(|(key, value)| judge_apt_setting(&key, &value).map(|(s, why)| (s, format!("{key} \"{}\"  ← {why}", without_password(&value)))))
            .collect();
        let Some(severity) = found.iter().map(|f| f.0).max() else { continue };
        let lines: Vec<String> = found.into_iter().map(|f| f.1).collect();
        col.push(
            Finding::new(severity, MODULE, "PERS-APT-CONFIG", format!("apt's download settings are changed: {path}"))
                .evidence(format!("{path}\n{}", clip(&lines.join("\n"), 600)))
                .description("These settings weaken the checks on what apt installs as root, or send the downloads through another server. Company mirrors and caches use some of them; check that you set it.")
                .verify(format!("grep -vi -E 'password|auth' {}", shq(&path))),
        );
    }
}

/// Signing keys that no package installed. Keys in `trusted.gpg.d` vouch for every source.
fn check_keyrings(ctx: &ScanCtx, col: &mut Collector) {
    let list = |dir: &str| -> Vec<String> { ctx.sys.dir_names(dir).into_iter().map(|n| format!("{dir}/{n}")).collect() };
    let mut everywhere = list("/etc/apt/trusted.gpg.d");
    everywhere.push("/etc/apt/trusted.gpg".to_string());
    let mut scoped = list("/usr/share/keyrings");
    for path in &scoped {
        record(ctx, col, path);
    }
    scoped.extend(list("/etc/apt/keyrings"));
    if ctx.sys.dir_names("/var/lib/dpkg/info").is_empty() {
        return;
    }
    let all: Vec<String> = everywhere.iter().chain(scoped.iter()).cloned().collect();
    let owned = owned_paths(ctx.sys, &all);
    let unknown = |paths: Vec<String>| -> Vec<String> {
        paths.into_iter().filter(|p| !owned.contains(p) && std::fs::metadata(ctx.sys.path(p)).map(|m| m.is_file() && m.len() > 0).unwrap_or(false)).collect()
    };
    for (severity, files, title, text) in [
        (Severity::Medium, unknown(everywhere), "Keys that apt trusts for every source, from no package", "A key here can sign packages that replace any program, whichever source they come from. Move third-party keys to /etc/apt/keyrings and name them with Signed-By in their source."),
        (Severity::Info, unknown(scoped), "Signing keys added outside the packages", "Third-party software sources bring such keys. Each one vouches for packages from the sources that name it."),
    ] {
        if files.is_empty() {
            continue;
        }
        let first = files[0].clone();
        col.push(
            Finding::new(severity, MODULE, "PERS-APT-KEY", title)
                .evidence(clip(&files.join("\n"), 900))
                .description(text)
                .verify(format!("gpg --show-keys {}", shq(&first))),
        );
    }
}

/// apt.conf can run commands before and after every update (`DPkg::Post-Invoke { "…"; };`).
fn check_hooks(ctx: &ScanCtx, col: &mut Collector) {
    let mut files = vec!["/etc/apt/apt.conf".to_string()];
    files.extend(ctx.sys.dir_names("/etc/apt/apt.conf.d").into_iter().map(|n| format!("/etc/apt/apt.conf.d/{n}")));
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        let mut in_hook = false;
        let mut issues: Vec<CmdIssue> = Vec::new();
        let mut lines = Vec::new();
        for line in text.lines().map(|l| l.trim()).filter(|l| !l.starts_with("//") && !l.starts_with('#')) {
            in_hook |= line.contains("Invoke") || line.contains("Pre-Install-Pkgs");
            if !in_hook {
                continue;
            }
            // the command is everything between the first and the last quote
            let command = match (line.find('"'), line.rfind('"')) {
                (Some(a), Some(b)) if b > a => &line[a + 1..b],
                _ => "",
            };
            let found: Vec<CmdIssue> = analyze_command(command, ctx.cfg).into_iter().filter(|i| i.severity >= Severity::High).collect();
            if !found.is_empty() {
                lines.push(line.to_string());
            }
            for i in found {
                if !issues.contains(&i) {
                    issues.push(i);
                }
            }
            if line.ends_with("};") || (line.ends_with(';') && !line.contains('{') && line.contains("Invoke")) {
                in_hook = false;
            }
        }
        if let Some(severity) = max_severity(&issues) {
            col.push(
                Finding::new(severity, MODULE, "PERS-APT-HOOK", format!("apt runs a suspicious command: {path}"))
                    .evidence(format!("{path}\n{}", clip(&lines.join("\n"), 600)))
                    .description(format!("apt runs this as root on every update or install. Suspicious: {}.", reasons(&issues)))
                    .verify(format!("cat {}", shq(&path)))
                    .verify(format!("dpkg -S {}", shq(&path))),
            );
        }
    }
}
