//! Web browsers (part of `fs_perms`): add-ons that did not come from the official stores,
//! settings that reroute or remote-control the browser, forced policies and changed launchers.
//! Only add-on lists and a few settings are read – never history, cookies or passwords.

use super::common::{clip, risky_home_place, shq};
use super::fs_perms::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::modules::persistence::history::judge_command;
use crate::pkgverify::owned_paths;
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
    // 2 and 3 send name lookups to the server in network.trr.uri
    if ["2", "3"].contains(&get("network.trr.mode")) && !get("network.trr.uri").is_empty() && !is_known_dns(get("network.trr.uri")) {
        out.push((Severity::Medium, format!("name lookups go to an unfamiliar server: {}", without_password(get("network.trr.uri")))));
    }
    let home_page = get("browser.startup.homepage");
    if home_page.starts_with("http://") {
        out.push((Severity::Low, format!("the home page is an unencrypted address: {}", without_password(home_page))));
    }
    if get("xpinstall.signatures.required") == "false" {
        out.push((Severity::Medium, "unsigned add-ons are allowed (xpinstall.signatures.required = false)".into()));
    }
    if get("devtools.debugger.remote-enabled") == "true" && get("devtools.debugger.prompt-connection") == "false" {
        out.push((Severity::High, "remote control of the browser is on, without asking".into()));
    }
    out
}

/// Is an address on one of these sites (or below it)?
fn on_site(url: &str, sites: &[&str]) -> bool {
    let host = crate::modules::persistence::apt::host_of(url).unwrap_or_default();
    sites.iter().any(|s| host == *s || host.ends_with(&format!(".{s}")))
}

fn is_known_dns(url: &str) -> bool {
    on_site(url, &["cloudflare-dns.com", "dns.google", "quad9.net", "opendns.com", "nextdns.io", "adguard.com", "adguard-dns.com", "mullvad.net", "controld.com", "cleanbrowsing.org"])
}

const SEARCH_ENGINES: [&str; 13] = [
    "google.com", "google.se", "duckduckgo.com", "bing.com", "yahoo.com", "ecosia.org", "startpage.com", "brave.com",
    "qwant.com", "kagi.com", "yandex.com", "baidu.com", "swisscows.com",
];

/// A replaced search engine, start pages and DNS server in a Chromium-family `Preferences` file.
pub fn chromium_settings(data: &Value) -> Vec<(Severity, String)> {
    let mut out = Vec::new();
    let engine = data
        .pointer("/default_search_provider_data/template_url_data/url")
        .or_else(|| data.pointer("/default_search_provider/search_url"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if engine.starts_with("http") && !on_site(engine, &SEARCH_ENGINES) {
        out.push((Severity::Medium, format!("searches go to an unfamiliar search engine: {}", without_password(engine))));
    }
    if data.pointer("/session/restore_on_startup").and_then(Value::as_i64) == Some(4) {
        let pages: Vec<String> = data.pointer("/session/startup_urls").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(without_password).collect();
        let odd: Vec<&String> = pages.iter().filter(|p| p.starts_with("http://")).collect();
        if !odd.is_empty() {
            out.push((Severity::Low, format!("unencrypted pages open at start: {}", odd.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))));
        }
    }
    let dns = data.pointer("/dns_over_https/templates").and_then(Value::as_str).unwrap_or("");
    if dns.starts_with("http") && !is_known_dns(dns) {
        out.push((Severity::Medium, format!("name lookups go to an unfamiliar server: {}", without_password(dns))));
    }
    out
}

// ---------------------------------------------------------------- native messaging

pub(crate) const NATIVE_HOME: [&str; 6] = [
    ".mozilla/native-messaging-hosts", ".config/google-chrome/NativeMessagingHosts", ".config/chromium/NativeMessagingHosts",
    ".config/BraveSoftware/Brave-Browser/NativeMessagingHosts", ".config/microsoft-edge/NativeMessagingHosts",
    ".config/vivaldi/NativeMessagingHosts",
];
pub(crate) const NATIVE_SYSTEM: [&str; 6] = [
    "/etc/opt/chrome/native-messaging-hosts", "/etc/chromium/native-messaging-hosts", "/etc/opt/edge/native-messaging-hosts",
    "/usr/lib/mozilla/native-messaging-hosts", "/usr/local/lib/mozilla/native-messaging-hosts", "/usr/lib64/mozilla/native-messaging-hosts",
];

/// Programs on this computer that browser add-ons may talk to.
fn check_native_messaging(ctx: &ScanCtx, col: &mut Collector, homes: &[String]) {
    let mut files: Vec<(String, bool)> = Vec::new();
    for dir in NATIVE_SYSTEM {
        files.extend(ctx.sys.dir_names(dir).into_iter().filter(|n| n.ends_with(".json")).map(|n| (format!("{dir}/{n}"), false)));
    }
    for home in homes {
        for dir in NATIVE_HOME {
            files.extend(ctx.sys.dir_names(format!("{home}/{dir}")).into_iter().filter(|n| n.ends_with(".json")).map(|n| (format!("{home}/{dir}/{n}"), true)));
        }
    }
    let hosts: Vec<(String, bool, String)> = files
        .into_iter()
        .filter_map(|(path, own)| {
            let program = text(&read_json(ctx, &path)?, "path").to_string();
            (!program.is_empty()).then_some((path, own, program))
        })
        .collect();
    let has_dpkg = !ctx.sys.dir_names("/var/lib/dpkg/info").is_empty();
    let owned = owned_paths(ctx.sys, &hosts.iter().map(|h| h.2.clone()).collect::<Vec<_>>());
    for (path, own, program) in hosts {
        let odd = ctx.cfg.is_temp_path(&program) || risky_home_place(&program, ctx.cfg).is_some();
        let in_home = program.starts_with("/home/") || program.starts_with("/root/");
        // a helper that is a script can be read: does it hold a break-in command?
        let script = ctx.sys.read_bytes(&program).ok().filter(|b| b.starts_with(b"#!") && b.len() < 256 * 1024);
        let suspicious = script.and_then(|b| {
            String::from_utf8_lossy(&b).lines().filter(|l| !l.starts_with('#') && !l.contains("grep")).find_map(|l| match judge_command(ctx, l) {
                Some((Severity::High | Severity::Critical, why)) => Some(why),
                _ => None,
            })
        });
        let (severity, why) = if suspicious.is_some() {
            (Severity::Critical, "the program is a script with a command typical of a break-in")
        } else if odd {
            (Severity::High, "the program is in a temporary, download, cache or hidden place")
        } else if has_dpkg && !in_home && !owned.contains(&program) {
            (Severity::Medium, "no package installed the program")
        } else if in_home || (own && has_dpkg && !owned.contains(&program)) {
            (Severity::Low, "the program is your own")
        } else {
            // an installed program; browser integration packages create these entries
            continue;
        };
        col.push(
            Finding::new(severity, MODULE, "FS-BROWSER-NATIVE", format!("Browser add-ons can start a program: {path}"))
                .evidence(format!("{path}\npath: {program}\n{why}"))
                .description("This 'native messaging host' lets a browser add-on run a program on your computer, outside the browser's protection. Password managers and desktop integration use it; check that you know the program.")
                .verify(format!("cat {}", shq(&path)))
                .verify(format!("ls -l {}", shq(&program)))
                .verify(format!("dpkg -S {}", shq(&program))),
        );
    }
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
                for s in chromium_settings(&data) {
                    if !settings.contains(&s) {
                        settings.push(s);
                    }
                }
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
    check_native_messaging(ctx, col, homes);
}
