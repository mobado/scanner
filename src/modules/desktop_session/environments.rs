//! Path rules for single desktops: session D-Bus services and portals (all desktops), KDE
//! Plasma, GNOME, XFCE and the lighter window managers. Only commands that are suspicious or
//! start something from an odd place are reported, plus settings that reroute traffic, open
//! the screen to others or switch the screen lock off.

use super::gvdb::{self, Setting};
use super::MODULE;
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_user_command, clip, shq};
use crate::modules::persistence::{parse_unit, record};
use crate::modules::{Collector, ScanCtx};
use crate::pkgverify::owned_paths;
use std::collections::{BTreeMap, HashSet};

type Homes = [(String, u32, String)];

/// Why a command found in a desktop setting deserves a look.
pub fn judge_desktop_command(ctx: &ScanCtx, command: &str) -> Option<(Severity, String)> {
    let issues: Vec<_> = analyze_user_command(command, ctx.cfg)
        .into_iter()
        .filter(|i| i.severity >= Severity::High || i.reason.starts_with("runs a program from"))
        .collect();
    let worst = issues.iter().map(|i| i.severity).max()?;
    Some((worst, crate::modules::common::reasons(&issues)))
}

/// One finding for the commands of one file that deserve a look.
fn report_commands(ctx: &ScanCtx, col: &mut Collector, path: &str, kind: &str, commands: &[String]) {
    let mut worst = None;
    let mut lines = Vec::new();
    for command in commands {
        if let Some((severity, why)) = judge_desktop_command(ctx, command) {
            worst = worst.max(Some(severity));
            lines.push(format!("{}  ← {why}", clip(command, 250)));
        }
    }
    let Some(severity) = worst else { return };
    lines.truncate(10);
    col.push(
        Finding::new(severity, MODULE, "PERS-DESKTOP-COMMAND", format!("{kind} runs a suspicious command: {path}"))
            .evidence(format!("{path}\n{}", lines.join("\n")))
            .description(format!("{kind} starts this without asking. Check that you set it up; remove it in the desktop's settings if not."))
            .verify(format!("ls -l --time-style=full-iso {}", shq(path)))
            .verify(format!("less {}", shq(path))),
    );
}

fn setting_finding(col: &mut Collector, severity: Severity, rule: &str, title: String, path: &str, evidence: Vec<String>, description: &str) {
    col.push(
        Finding::new(severity, MODULE, rule, title)
            .evidence(format!("{path}\n{}", clip(&evidence.join("\n"), 800)))
            .description(description.to_string())
            .verify(format!("ls -l --time-style=full-iso {}", shq(path))),
    );
}

/// "http://user:secret@host" → "http://host"
fn without_password(value: &str) -> String {
    match value.rsplit_once('@') {
        Some((before, after)) => format!("{}{after}", before.split_once("://").map(|(s, _)| format!("{s}://")).unwrap_or_default()),
        None => value.to_string(),
    }
}

// ---------------------------------------------------------------- D-Bus services and portals

fn check_dbus_and_portals(ctx: &ScanCtx, col: &mut Collector, homes: &Homes, has_dpkg: bool) {
    // names that the installed system already provides
    let system: HashSet<String> = ctx
        .sys
        .dir_names("/usr/share/dbus-1/services")
        .iter()
        .filter_map(|n| ctx.sys.read_string(format!("/usr/share/dbus-1/services/{n}")).ok())
        .flat_map(|t| parse_unit(&t).into_iter().filter(|(_, k, _)| k == "Name").map(|(_, _, v)| v))
        .collect();
    let mut dirs = vec!["/usr/local/share/dbus-1/services".to_string(), "/usr/local/share/dbus-1/system-services".to_string()];
    dirs.extend(homes.iter().map(|(_, _, h)| format!("{h}/.local/share/dbus-1/services")));
    for dir in dirs {
        for name in ctx.sys.dir_names(&dir).into_iter().filter(|n| n.ends_with(".service")) {
            let path = format!("{dir}/{name}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            let entries = parse_unit(&text);
            let get = |key: &str| entries.iter().find(|(_, k, _)| k == key).map(|(_, _, v)| v.clone()).unwrap_or_default();
            let (service, exec) = (get("Name"), get("Exec"));
            let judged = judge_desktop_command(ctx, &exec);
            let replaces = system.contains(&service);
            let severity = match &judged {
                Some((s, _)) => (*s).max(Severity::Medium),
                None if replaces => Severity::Medium,
                None => Severity::Low,
            };
            let mut evidence = vec![format!("Name={service}"), format!("Exec={exec}")];
            evidence.extend(judged.map(|(_, why)| why));
            if replaces {
                evidence.push("a service with this name is installed with the system; this file takes its place".into());
            }
            setting_finding(col, severity, "PERS-DBUS-SERVICE", format!("Own D-Bus service: {path}"), &path, evidence, "The session starts this program by itself as soon as anything asks for the service, for example a portal or a notification. A file here can quietly replace a system service.");
        }
    }
    let mut portal_dirs = vec!["/usr/local/share/xdg-desktop-portal/portals".to_string()];
    portal_dirs.extend(homes.iter().map(|(_, _, h)| format!("{h}/.local/share/xdg-desktop-portal/portals")));
    for dir in portal_dirs {
        for name in ctx.sys.dir_names(&dir).into_iter().filter(|n| n.ends_with(".portal")) {
            let path = format!("{dir}/{name}");
            record(ctx, col, &path);
            if !has_dpkg || !owned_paths(ctx.sys, std::slice::from_ref(&path)).contains(&path) {
                let text = ctx.sys.read_string(&path).unwrap_or_default();
                setting_finding(col, Severity::Medium, "PERS-PORTAL", format!("Desktop portal added outside the packages: {path}"), &path, text.lines().map(str::to_string).collect(), "Portals hand programs files, screen pictures and key presses. One that no package installed can see all of that.");
            }
        }
    }
    for (_, _, home) in homes {
        let dir = format!("{home}/.config/xdg-desktop-portal");
        for name in ctx.sys.dir_names(&dir) {
            // choosing a portal is recorded so that the baseline notices a change
            record(ctx, col, &format!("{dir}/{name}"));
        }
    }
}

// ---------------------------------------------------------------- KDE Plasma

/// Lines "key=value" whose key starts with `prefix`.
fn values_of(text: &str, prefix: &str) -> Vec<String> {
    parse_unit(text).into_iter().filter(|(_, k, v)| k.starts_with(prefix) && !v.is_empty()).map(|(_, _, v)| v).collect()
}

/// Window rules that make windows invisible: the names of the rule groups.
pub fn hiding_window_rules(text: &str) -> Vec<String> {
    let mut rules: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    for (group, key, value) in parse_unit(text) {
        rules.entry(group).or_default().insert(key, value);
    }
    rules
        .into_iter()
        .filter(|(_, r)| {
            let is = |k: &str, v: &str| r.get(k).map(|x| x == v).unwrap_or(false);
            is("opacityactive", "0") || (is("opacityinactive", "0") && is("skiptaskbar", "true"))
        })
        .map(|(group, r)| format!("rule {group}: {}", r.get("Description").cloned().unwrap_or_default()))
        .collect()
}

fn check_kde(ctx: &ScanCtx, col: &mut Collector, home: &str) {
    let config = format!("{home}/.config");
    let restore = format!("{config}/ksmserverrc");
    if let Ok(text) = ctx.sys.read_string(&restore) {
        // programs that Plasma starts again at login
        let commands: Vec<String> = values_of(&text, "restoreCommand").iter().map(|v| v.replace(',', " ")).collect();
        report_commands(ctx, col, &restore, "Plasma's saved session", &commands);
    }
    // "run a command" actions of notifications, such as when the screen locks
    for name in ctx.sys.dir_names(&config).into_iter().filter(|n| n.ends_with(".notifyrc")) {
        let path = format!("{config}/{name}");
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        report_commands(ctx, col, &path, "A Plasma notification (lock, login …)", &values_of(&text, "Execute"));
    }
    let hotkeys = format!("{config}/khotkeysrc");
    if let Ok(text) = ctx.sys.read_string(&hotkeys) {
        report_commands(ctx, col, &hotkeys, "A Plasma keyboard shortcut", &values_of(&text, "CommandURL"));
    }
    let accel = format!("{home}/.local/share/kglobalaccel");
    for name in ctx.sys.dir_names(&accel).into_iter().filter(|n| n.ends_with(".desktop")) {
        let path = format!("{accel}/{name}");
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        report_commands(ctx, col, &path, "A Plasma keyboard shortcut", &values_of(&text, "Exec"));
    }
    let enabled: Vec<String> = ctx
        .sys
        .read_string(format!("{config}/kwinrc"))
        .map(|t| parse_unit(&t).into_iter().filter(|(g, k, v)| g == "Plugins" && k.ends_with("Enabled") && v == "true").map(|(_, k, _)| k.trim_end_matches("Enabled").to_string()).collect())
        .unwrap_or_default();
    let scripts = format!("{home}/.local/share/kwin/scripts");
    for id in ctx.sys.dir_names(&scripts) {
        let mut code = String::new();
        for file in ["contents/code/main.js", "contents/ui/main.qml"] {
            let path = format!("{scripts}/{id}/{file}");
            if let Ok(text) = ctx.sys.read_string(&path) {
                record(ctx, col, &path);
                code.push_str(&text);
            }
        }
        if !enabled.contains(&id) {
            continue;
        }
        // callDBus can ask systemd or the launcher to start programs
        let starts = code.contains("callDBus") && ["systemd1", "klauncher", "krunner", "org.freedesktop.Flatpak"].iter().any(|s| code.contains(s));
        let path = format!("{scripts}/{id}");
        setting_finding(
            col,
            if starts { Severity::Medium } else { Severity::Low },
            "PERS-KWIN-SCRIPT",
            format!("Own KWin script is switched on: {id}"),
            &path,
            vec![if starts { "the script can ask other services to start programs (callDBus)".to_string() } else { "switched on in kwinrc".to_string() }],
            "KWin scripts run inside the window manager and see every window. Ones from the KDE store are normal; check that you added it.",
        );
    }
    let rules = format!("{config}/kwinrulesrc");
    if let Ok(text) = ctx.sys.read_string(&rules) {
        let hiding = hiding_window_rules(&text);
        if !hiding.is_empty() {
            setting_finding(col, Severity::Low, "PERS-KWIN-RULE", format!("Window rules make windows invisible: {rules}"), &rules, hiding, "A rule makes certain windows fully transparent. Some people do that on purpose; it can also hide a window you should see.");
        }
    }
    let locker = format!("{config}/kscreenlockerrc");
    if let Ok(text) = ctx.sys.read_string(&locker) {
        if parse_unit(&text).iter().any(|(g, k, v)| g == "Daemon" && k == "Autolock" && v == "false") {
            setting_finding(col, Severity::Low, "PERS-SCREEN-LOCK", format!("The automatic screen lock is switched off: {locker}"), &locker, vec!["Autolock=false".into()], "The screen stays open when you leave. Switch on automatic locking if you did not choose this.");
        }
    }
    let proxy = format!("{config}/kioslaverc");
    if let Ok(text) = ctx.sys.read_string(&proxy) {
        let entries: Vec<(String, String)> = parse_unit(&text).into_iter().filter(|(g, _, _)| g == "Proxy Settings").map(|(_, k, v)| (k, v)).collect();
        if entries.iter().any(|(k, v)| k == "ProxyType" && (v == "1" || v == "2")) {
            let lines = entries.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| format!("{k}={}", without_password(v))).collect();
            setting_finding(col, Severity::Medium, "PERS-DESKTOP-PROXY", format!("KDE sends traffic through a proxy: {proxy}"), &proxy, lines, "Programs that follow the desktop's settings send their traffic through this server. VPNs and company networks do that; malware does it to read traffic.");
        }
    }
}

// ---------------------------------------------------------------- GNOME

/// Judge GNOME settings (from a user database or a system key file).
fn judge_gnome(ctx: &ScanCtx, col: &mut Collector, path: &str, settings: &BTreeMap<String, Setting>) {
    let text = |key: &str| settings.get(key).and_then(Setting::text).unwrap_or("");
    let flag = |key: &str, value: bool| settings.get(key) == Some(&Setting::Flag(value));
    let commands: Vec<String> = settings
        .iter()
        .filter(|(k, _)| (k.contains("/custom-keybindings/") && k.ends_with("/command")) || k.ends_with("/default-applications/terminal/exec"))
        .filter_map(|(_, v)| v.text().map(str::to_string))
        .collect();
    report_commands(ctx, col, path, "A GNOME keyboard shortcut or default program", &commands);
    let mode = text("/system/proxy/mode");
    if mode == "manual" || mode == "auto" {
        let lines = settings
            .iter()
            .filter(|(k, _)| k.starts_with("/system/proxy/") && !k.ends_with("password") && !k.ends_with("user"))
            .filter_map(|(k, v)| v.text().filter(|v| !v.is_empty()).map(|v| format!("{k} = {}", without_password(v))))
            .collect();
        setting_finding(col, Severity::Medium, "PERS-DESKTOP-PROXY", format!("GNOME settings send traffic through a proxy: {path}"), path, lines, "Programs that follow the desktop's settings send their traffic through this server. VPNs and company networks do that; malware does it to read traffic.");
    }
    let sharing: Vec<String> = ["rdp", "vnc"].iter().filter(|p| flag(&format!("/org/gnome/desktop/remote-desktop/{p}/enable"), true)).map(|p| format!("remote desktop ({p}) is on")).collect();
    if !sharing.is_empty() {
        setting_finding(col, Severity::Medium, "PERS-REMOTE-DESKTOP", format!("Remote desktop is switched on: {path}"), path, sharing, "Others on the network can see and control the screen. Switch it off in the sharing settings if you do not use it.");
    }
    if flag("/org/gnome/desktop/screensaver/lock-enabled", false) || flag("/org/gnome/desktop/lockdown/disable-lock-screen", true) {
        setting_finding(col, Severity::Low, "PERS-SCREEN-LOCK", format!("The screen lock is switched off: {path}"), path, vec!["lock-enabled = false or disable-lock-screen = true".into()], "Anyone at the keyboard gets your session. Switch the lock on again if you did not choose this.");
    }
}

fn check_gnome(ctx: &ScanCtx, col: &mut Collector, home: &str) {
    let database = format!("{home}/.config/dconf/user");
    if let Ok(bytes) = ctx.sys.read_bytes(&database) {
        match gvdb::read_database(&bytes) {
            Some(settings) => {
                judge_gnome(ctx, col, &database, &settings);
                if let Some(Setting::List(enabled)) = settings.get("/org/gnome/shell/enabled-extensions") {
                    let own: Vec<String> = enabled.iter().filter(|e| !e.contains('/') && ctx.sys.exists(format!("{home}/.local/share/gnome-shell/extensions/{e}"))).cloned().collect();
                    if !own.is_empty() {
                        setting_finding(col, Severity::Low, "PERS-GNOME-EXTENSION", format!("Own GNOME Shell extensions are switched on for {home}"), &database, own, "Extensions run inside the desktop shell and see everything on screen. Check that you installed each of them.");
                    }
                }
            }
            None => col.note(format!("{database} is not a settings database that can be read")),
        }
    }
    // GNOME starts saved-session programs again at login
    for dir in [format!("{home}/.config/gnome-session/saved-session"), format!("{home}/.config/gnome-session/sessions")] {
        for name in ctx.sys.dir_names(&dir) {
            let path = format!("{dir}/{name}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            report_commands(ctx, col, &path, "GNOME's saved session", &values_of(&text, "Exec"));
        }
    }
}

// ---------------------------------------------------------------- XFCE

fn xml_text(value: &str) -> String {
    value.replace("&quot;", "\"").replace("&apos;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

fn attribute<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.split_once(&format!(" {name}=\""))?.1.split('"').next()
}

/// Commands in an XFCE settings file: the values of `Client…_Command` lists (joined) and of
/// string properties.
pub fn xfconf_commands(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut list: Option<Vec<String>> = None;
    for line in text.lines().map(str::trim) {
        let value = attribute(line, "value").map(xml_text);
        if line.starts_with("<property") && attribute(line, "name").map(|n| n.ends_with("_Command")).unwrap_or(false) && !line.ends_with("/>") {
            list = Some(Vec::new());
        } else if let Some(parts) = list.as_mut() {
            if line.starts_with("<value") {
                parts.extend(value);
            } else if line.starts_with("</property") {
                out.push(list.take().unwrap_or_default().join(" "));
            }
        } else if line.starts_with("<property") && attribute(line, "type") == Some("string") {
            out.extend(value);
        }
    }
    out
}

fn check_xfce(ctx: &ScanCtx, col: &mut Collector, home: &str) {
    let settings = format!("{home}/.config/xfce4/xfconf/xfce-perchannel-xml");
    for name in ["xfce4-session.xml", "xfce4-keyboard-shortcuts.xml", "xfce4-power-manager.xml", "xfce4-screensaver.xml"] {
        let path = format!("{settings}/{name}");
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        report_commands(ctx, col, &path, "An XFCE setting (session or shortcut)", &xfconf_commands(&text));
    }
    let sessions = format!("{home}/.cache/sessions");
    for name in ctx.sys.dir_names(&sessions).into_iter().filter(|n| n.starts_with("xfce4-session")) {
        let path = format!("{sessions}/{name}");
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        let commands: Vec<String> = text.lines().filter_map(|l| l.split_once("_RestartCommand=")).map(|(_, v)| v.replace(',', " ")).collect();
        report_commands(ctx, col, &path, "XFCE's saved session", &commands);
    }
    let panel = format!("{home}/.config/xfce4/panel");
    for launcher in ctx.sys.dir_names(&panel).into_iter().filter(|n| n.starts_with("launcher-")) {
        for name in ctx.sys.dir_names(format!("{panel}/{launcher}")) {
            let path = format!("{panel}/{launcher}/{name}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            report_commands(ctx, col, &path, "An XFCE panel button", &values_of(&text, "Exec"));
        }
    }
}

// ---------------------------------------------------------------- window managers

/// The quoted parts of a line.
fn quoted(line: &str) -> impl Iterator<Item = &str> {
    line.split(['\'', '"']).skip(1).step_by(2)
}

/// The commands that a window manager or idle daemon configuration starts. Shell-like files
/// (openbox, LXDE, labwc, fluxbox autostart) are commands line by line.
pub fn window_manager_commands(path: &str, text: &str) -> Vec<String> {
    let shell_like = path.ends_with("/autostart") || path.ends_with("/startup");
    let idle = path.ends_with("swayidle/config");
    let mut out = Vec::new();
    let mut section = String::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with(['#', ';'])) {
        if shell_like {
            out.push(line.trim_start_matches('@').trim_end_matches('&').trim().to_string());
        } else if idle {
            out.extend(quoted(line).map(str::to_string));
        } else if path.ends_with("wayfire.ini") {
            if line.starts_with('[') {
                section = line.to_string();
            } else if section == "[autostart]" || line.starts_with("command") {
                out.extend(line.split_once('=').map(|(_, v)| v.trim().to_string()));
            }
        } else if path.ends_with(".xscreensaver") {
            if line.starts_with("lock-command") || line.starts_with("unlock-command") {
                out.extend(line.split_once(':').map(|(_, v)| v.trim().to_string()));
            }
        } else {
            // sway, i3 and Hyprland: "exec …", "bindsym … exec …", "bind = …, exec, …", "lock_cmd = …",
            // and Hyprland's compositor plugins ("plugin = /path.so")
            let command = if let Some(rest) = line.strip_prefix("exec_always ").or_else(|| line.strip_prefix("exec ")) {
                Some(rest)
            } else if line.starts_with("exec-once") || line.starts_with("exec =") || line.starts_with("exec=") || line.starts_with("plugin =") {
                line.split_once('=').map(|(_, v)| v)
            } else if ["lock_cmd", "unlock_cmd", "on-timeout", "on-resume", "before_sleep_cmd", "after_sleep_cmd"].iter().any(|k| line.starts_with(k)) {
                line.split_once('=').map(|(_, v)| v)
            } else {
                line.split_once(", exec, ").or_else(|| line.split_once(" exec ")).map(|(_, v)| v)
            };
            out.extend(command.map(|c| c.trim().trim_start_matches("--no-startup-id ").trim_matches('"').to_string()));
        }
    }
    out
}

const HOME_MANAGERS: [&str; 11] = [
    ".config/sway/config", ".config/i3/config", ".i3/config", ".config/hypr/hyprland.conf", ".config/hypr/hypridle.conf",
    ".config/swayidle/config", ".config/openbox/autostart", ".config/labwc/autostart", ".config/wayfire.ini",
    ".fluxbox/startup", ".xscreensaver",
];

fn check_window_managers(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let mut files = vec!["/etc/xdg/openbox/autostart".to_string()];
    files.extend(ctx.sys.dir_names("/etc/xdg/lxsession").into_iter().map(|p| format!("/etc/xdg/lxsession/{p}/autostart")));
    files.extend(ctx.sys.dir_names("/etc/sway/config.d").into_iter().map(|n| format!("/etc/sway/config.d/{n}")));
    for (_, _, home) in homes {
        files.extend(HOME_MANAGERS.iter().map(|f| format!("{home}/{f}")));
        let lx = format!("{home}/.config/lxsession");
        files.extend(ctx.sys.dir_names(&lx).into_iter().map(|p| format!("{lx}/{p}/autostart")));
    }
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        record(ctx, col, &path);
        report_commands(ctx, col, &path, "The window manager or screen lock", &window_manager_commands(&path, &text));
    }
}

// ---------------------------------------------------------------- X11 access

/// Does a line let other users or programs into the X11 display (`xhost +`)?
pub fn opens_x11(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    words.windows(2).any(|w| crate::procinfo::basename(w[0]) == "xhost" && w[1].starts_with('+') && !w[1].to_lowercase().starts_with("+si:"))
}

fn check_x11_access(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let mut files: Vec<String> = ctx.sys.dir_names("/etc/X11/Xsession.d").into_iter().map(|n| format!("/etc/X11/Xsession.d/{n}")).collect();
    files.push("/etc/profile".into());
    for (_, _, home) in homes {
        files.extend([".xprofile", ".xinitrc", ".xsessionrc", ".xsession", ".profile", ".bashrc", ".config/openbox/autostart"].iter().map(|f| format!("{home}/{f}")));
    }
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        let lines: Vec<String> = text.lines().map(str::trim).filter(|l| !l.starts_with('#') && opens_x11(l)).map(str::to_string).collect();
        if !lines.is_empty() {
            setting_finding(col, Severity::Medium, "PERS-X11-OPEN", format!("The X11 display is opened to others: {path}"), &path, lines, "xhost + lets other users, or the whole network, read the keyboard and screen and type into your windows. Remove the line, or allow only a named user (xhost +si:localuser:name).");
        }
    }
}

pub fn check_environments(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let has_dpkg = !ctx.sys.dir_names("/var/lib/dpkg/info").is_empty();
    check_dbus_and_portals(ctx, col, homes, has_dpkg);
    for (_, _, home) in homes {
        check_kde(ctx, col, home);
        check_gnome(ctx, col, home);
        check_xfce(ctx, col, home);
    }
    // settings an administrator (or someone with root) imposes on every GNOME user
    for database in ctx.sys.dir_names("/etc/dconf/db") {
        if !database.ends_with(".d") {
            continue;
        }
        let dir = format!("/etc/dconf/db/{database}");
        for name in ctx.sys.dir_names(&dir) {
            let path = format!("{dir}/{name}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            judge_gnome(ctx, col, &path, &gvdb::read_keyfile(&text));
        }
    }
    check_window_managers(ctx, col, homes);
    check_x11_access(ctx, col, homes);
}
