//! Web browsers (part of `fs_perms`): add-ons that did not come from the official stores,
//! settings that reroute or remote-control the browser, forced policies and changed launchers.
//! Only add-on lists and a few settings are read – never history, cookies or passwords.

use super::common::{clip, risky_home_place, shq};
use super::fs_perms::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use serde_json::Value;

const CHROMIUM_ROOTS: [&str; 11] = [
    ".config/google-chrome", ".config/google-chrome-beta", ".config/chromium", ".config/BraveSoftware/Brave-Browser",
    ".config/microsoft-edge", ".config/vivaldi", ".config/opera", ".var/app/org.chromium.Chromium/config/chromium",
    ".var/app/com.google.Chrome/config/google-chrome", ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
    ".var/app/com.microsoft.Edge/config/microsoft-edge",
];

const FIREFOX_ROOTS: [&str; 3] = [".mozilla/firefox", ".config/mozilla/firefox", ".var/app/org.mozilla.firefox/.mozilla/firefox"];

/// Permissions that let an add-on read or change everything.
const BROAD: [&str; 7] = ["<all_urls>", "*://*/*", "http://*/*", "https://*/*", "nativeMessaging", "debugger", "proxy"];

/// One add-on that deserves a look.
#[derive(Debug, Clone, PartialEq)]
pub struct AddOn {
    pub name: String,
    pub id: String,
    pub why: String,
    pub severity: Severity,
}

fn text<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

/// Judge `extensions.settings` of a Chromium-family `Preferences` file.
pub fn chromium_addons(ctx: &ScanCtx, preferences: &Value) -> Vec<AddOn> {
    let Some(list) = preferences.pointer("/extensions/settings").and_then(Value::as_object) else { return Vec::new() };
    let mut out = Vec::new();
    for (id, entry) in list {
        let disabled = entry.get("state").and_then(Value::as_i64) == Some(0)
            || entry.get("disable_reasons").map(|r| r.as_array().map(|a| !a.is_empty()).unwrap_or_else(|| r.as_i64().unwrap_or(0) != 0)).unwrap_or(false);
        let path = text(entry, "path");
        // add-ons that Debian packages install live under /usr
        if disabled || path.starts_with("/usr/") {
            continue;
        }
        let store = entry.get("from_webstore").and_then(Value::as_bool);
        // Chromium's "ManifestLocation": 4 and 8 are loaded from a folder, 7 and 9 forced by policy
        let (mut severity, why) = match entry.get("location").and_then(Value::as_i64) {
            Some(4) => (Severity::Medium, "loaded from a folder (developer mode)"),
            Some(8) => (Severity::Medium, "loaded by a command line option"),
            Some(7 | 9) => (Severity::Medium, "forced on the browser by a policy"),
            Some(1) if store == Some(false) => (Severity::Medium, "installed from a file, not from the web store"),
            Some(2 | 3 | 6) if store != Some(true) => (Severity::Medium, "added by another program, not from the web store"),
            _ => continue,
        };
        let manifest = entry.get("manifest");
        let broad: Vec<&str> = ["permissions", "host_permissions"]
            .iter()
            .filter_map(|k| manifest.and_then(|m| m.get(*k)).and_then(Value::as_array))
            .flatten()
            .filter_map(Value::as_str)
            .filter(|p| BROAD.contains(p))
            .collect();
        let odd_place = ctx.cfg.is_temp_path(path) || risky_home_place(path, ctx.cfg).is_some();
        if odd_place {
            severity = Severity::High;
        }
        let mut why = why.to_string();
        if !path.is_empty() && path.starts_with('/') {
            why.push_str(&format!(" ({path})"));
        }
        if !broad.is_empty() {
            why.push_str(&format!("; may use {}", broad.join(", ")));
        }
        let name = manifest.map(|m| text(m, "name")).filter(|n| !n.is_empty()).unwrap_or("(name unknown)");
        out.push(AddOn { name: name.to_string(), id: id.clone(), why, severity });
    }
    out
}

/// Judge Firefox's `extensions.json`.
pub fn firefox_addons(data: &Value) -> Vec<AddOn> {
    let Some(list) = data.get("addons").and_then(Value::as_array) else { return Vec::new() };
    let mut out = Vec::new();
    for a in list {
        let location = text(a, "location");
        let built_in = ["app-builtin", "app-builtin-addons", "app-system-defaults", "app-system-addons"].contains(&location);
        if a.get("active").and_then(Value::as_bool) != Some(true) || built_in || text(a, "path").starts_with("/usr/") || text(a, "type") != "extension" {
            continue;
        }
        let unsigned = a.get("signedState").and_then(Value::as_i64).map(|s| s <= 0).unwrap_or(false);
        let why = if location == "app-temporary" {
            "loaded temporarily from a file"
        } else if unsigned {
            "not signed by Mozilla"
        } else if a.get("foreignInstall").and_then(Value::as_bool) == Some(true) {
            "added by another program, not by you in Firefox"
        } else {
            continue;
        };
        let name = a.pointer("/defaultLocale/name").and_then(Value::as_str).unwrap_or("(name unknown)");
        out.push(AddOn { name: name.to_string(), id: text(a, "id").to_string(), why: why.to_string(), severity: Severity::Medium });
    }
    out
}

/// "http://user:secret@host/x" → "http://host/x"
fn without_password(value: &str) -> String {
    match (value.find("://"), value.rfind('@')) {
        (Some(a), Some(b)) if b > a => format!("{}{}", &value[..a + 3], &value[b + 1..]),
        _ => value.to_string(),
    }
}

/// Settings in `prefs.js` / `user.js` that reroute or open up Firefox: (severity, description).
pub fn firefox_settings(prefs: &str) -> Vec<(Severity, String)> {
    let mut map = std::collections::BTreeMap::new();
    for line in prefs.lines() {
        let Some(rest) = line.trim().strip_prefix("user_pref(\"") else { continue };
        let Some((key, value)) = rest.split_once('"') else { continue };
        let value = value.trim_start_matches(',').trim().trim_end_matches(';').trim_end_matches(')').trim().trim_matches('"');
        map.insert(key.to_string(), value.to_string());
    }
    let get = |k: &str| map.get(k).map(String::as_str).unwrap_or("");
    let mut out = Vec::new();
    match get("network.proxy.type") {
        "1" => {
            let hosts: Vec<String> = ["http", "ssl", "socks"]
                .iter()
                .filter_map(|p| {
                    let host = get(&format!("network.proxy.{p}"));
                    (!host.is_empty()).then(|| format!("{p} {}", without_password(host)))
                })
                .collect();
            if !hosts.is_empty() {
                out.push((Severity::Medium, format!("traffic goes through a proxy: {}", hosts.join(", "))));
            }
        }
        "2" if !get("network.proxy.autoconfig_url").is_empty() => {
            out.push((Severity::Medium, format!("a proxy script decides where traffic goes: {}", without_password(get("network.proxy.autoconfig_url")))));
        }
        _ => {}
    }
    if get("xpinstall.signatures.required") == "false" {
        out.push((Severity::Medium, "unsigned add-ons are allowed (xpinstall.signatures.required = false)".into()));
    }
    if get("devtools.debugger.remote-enabled") == "true" && get("devtools.debugger.prompt-connection") == "false" {
        out.push((Severity::High, "remote control of the browser is on, without asking".into()));
    }
    out
}

/// Dangerous options on a browser's command line.
pub fn browser_options(line: &str) -> Vec<(Severity, &'static str)> {
    let checks: [(&str, Severity, &str); 6] = [
        ("--remote-debugging-port", Severity::High, "lets other programs control the browser (--remote-debugging-port)"),
        ("--load-extension", Severity::High, "loads an add-on from a folder (--load-extension)"),
        ("--disable-web-security", Severity::High, "switches off the web's protection between sites"),
        ("--proxy-server", Severity::Medium, "sends traffic through a proxy (--proxy-server)"),
        ("--proxy-pac-url", Severity::Medium, "uses a proxy script (--proxy-pac-url)"),
        ("--ignore-certificate-errors", Severity::High, "ignores false certificates"),
    ];
    checks.iter().filter(|(flag, _, _)| line.contains(flag)).map(|(_, s, why)| (*s, *why)).collect()
}

fn read_json(ctx: &ScanCtx, path: &str) -> Option<Value> {
    serde_json::from_str(&ctx.sys.read_string(path).ok()?).ok()
}

fn report_addons(col: &mut Collector, profile: &str, addons: Vec<AddOn>) {
    for a in addons {
        col.push(
            Finding::new(a.severity, MODULE, "FS-BROWSER-ADDON", format!("Browser add-on to check: {} ({})", clip(&a.name, 60), a.id))
                .evidence(format!("profile {profile}\n{} [{}]: {}", clip(&a.name, 120), a.id, a.why))
                .description("Add-ons can read pages, passwords as you type them, and send data away. This one did not come the normal way through the browser's store. Remove it in the browser if you do not know it.")
                .verify(format!("ls -la {}", shq(profile))),
        );
    }
}

fn report_settings(col: &mut Collector, place: &str, found: Vec<(Severity, String)>) {
    let Some(severity) = found.iter().map(|(s, _)| *s).max() else { return };
    let lines: Vec<String> = found.into_iter().map(|(_, l)| l).collect();
    col.push(
        Finding::new(severity, MODULE, "FS-BROWSER-SETTING", format!("Browser setting to check: {place}"))
            .evidence(format!("{place}\n{}", clip(&lines.join("\n"), 800)))
            .description("A setting or start option reroutes, opens up or weakens the browser. VPNs, company networks and web developers use these; so does malware that spies on browsing. Change it back if you did not choose it.")
            .verify(format!("ls -l --time-style=full-iso {}", shq(place))),
    );
}

fn check_chromium(ctx: &ScanCtx, col: &mut Collector, home: &str) {
    for root in CHROMIUM_ROOTS {
        let root = format!("{home}/{root}");
        let mut profiles: Vec<String> = ctx.sys.dir_names(&root).into_iter().filter(|n| n == "Default" || n.starts_with("Profile ")).map(|n| format!("{root}/{n}")).collect();
        profiles.push(root.clone()); // Opera keeps one profile in the folder itself
        for profile in profiles {
            let mut addons: Vec<AddOn> = Vec::new();
            let mut settings = Vec::new();
            for file in ["Preferences", "Secure Preferences"] {
                let Some(data) = read_json(ctx, &format!("{profile}/{file}")) else { continue };
                for a in chromium_addons(ctx, &data) {
                    if !addons.iter().any(|x| x.id == a.id) {
                        addons.push(a);
                    }
                }
                let mode = data.pointer("/proxy/mode").and_then(Value::as_str).unwrap_or("");
                if mode == "fixed_servers" || mode == "pac_script" {
                    let target = data.pointer("/proxy/server").or_else(|| data.pointer("/proxy/pac_url")).and_then(Value::as_str).unwrap_or("?");
                    settings.push((Severity::Medium, format!("proxy ({mode}): {}", without_password(target))));
                }
            }
            report_addons(col, &profile, addons);
            report_settings(col, &profile, settings);
        }
    }
}

fn check_firefox(ctx: &ScanCtx, col: &mut Collector, home: &str) {
    for root in FIREFOX_ROOTS {
        let root = format!("{home}/{root}");
        for name in ctx.sys.dir_names(&root) {
            let profile = format!("{root}/{name}");
            if let Some(data) = read_json(ctx, &format!("{profile}/extensions.json")) {
                report_addons(col, &profile, firefox_addons(&data));
            }
            // user.js wins over prefs.js, so it comes last
            let prefs: Vec<String> = ["prefs.js", "user.js"].iter().filter_map(|f| ctx.sys.read_string(format!("{profile}/{f}")).ok()).collect();
            report_settings(col, &profile, firefox_settings(&prefs.join("\n")));
        }
    }
}

/// Start options in launchers a user (or malware) can change without root.
fn check_launchers(ctx: &ScanCtx, col: &mut Collector, home: &str) {
    const BROWSERS: [&str; 7] = ["chrom", "brave", "firefox", "msedge", "microsoft-edge", "vivaldi", "opera"];
    let apps = format!("{home}/.local/share/applications");
    let mut files: Vec<String> = ctx.sys.dir_names(&apps).into_iter().filter(|n| n.ends_with(".desktop")).map(|n| format!("{apps}/{n}")).collect();
    files.extend(["chromium-flags.conf", "chrome-flags.conf", "brave-flags.conf"].iter().map(|n| format!("{home}/.config/{n}")));
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        let desktop = path.ends_with(".desktop");
        let mut found: Vec<(Severity, String)> = Vec::new();
        for line in text.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
            if desktop && !(line.starts_with("Exec=") && BROWSERS.iter().any(|b| line.to_lowercase().contains(b))) {
                continue;
            }
            for (severity, why) in browser_options(line) {
                found.push((severity, format!("{why}: {}", clip(line, 200))));
            }
        }
        report_settings(col, &path, found);
    }
}

/// System-wide browser policies that install add-ons or set a proxy.
fn check_policies(ctx: &ScanCtx, col: &mut Collector) {
    let mut files = Vec::new();
    for dir in ["/etc/opt/chrome/policies/managed", "/etc/chromium/policies/managed", "/etc/brave/policies/managed", "/etc/opt/edge/policies/managed"] {
        files.extend(ctx.sys.dir_names(dir).into_iter().map(|n| format!("{dir}/{n}")));
    }
    files.extend(["/etc/firefox/policies/policies.json", "/etc/firefox-esr/policies/policies.json", "/usr/lib/firefox-esr/distribution/policies.json", "/usr/lib/firefox/distribution/policies.json"].map(String::from));
    for path in files {
        let Some(data) = read_json(ctx, &path) else { continue };
        let mut found = Vec::new();
        for key in ["ExtensionInstallForcelist", "ProxySettings", "ProxyMode", "ProxyServer"] {
            if let Some(v) = data.get(key) {
                found.push((Severity::Medium, format!("{key}: {}", clip(&without_password(&v.to_string()), 300))));
            }
        }
        for key in ["/policies/Extensions/Install", "/policies/Proxy"] {
            if let Some(v) = data.pointer(key) {
                found.push((Severity::Medium, format!("{}: {}", &key[10..], clip(&without_password(&v.to_string()), 300))));
            }
        }
        report_settings(col, &path, found);
    }
    // Debian's Chromium reads start options from /etc/chromium.d
    for name in ctx.sys.dir_names("/etc/chromium.d") {
        let path = format!("/etc/chromium.d/{name}");
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        let found: Vec<(Severity, String)> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#'))
            .flat_map(|l| browser_options(l).into_iter().map(move |(s, why)| (s, format!("{why}: {}", clip(l, 200)))))
            .collect();
        report_settings(col, &path, found);
    }
}

pub(crate) fn check_browsers(ctx: &ScanCtx, col: &mut Collector, homes: &[String]) {
    for home in homes {
        check_chromium(ctx, col, home);
        check_firefox(ctx, col, home);
        check_launchers(ctx, col, home);
    }
    check_policies(ctx, col);
}
