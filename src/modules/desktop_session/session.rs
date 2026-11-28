//! Getting into a session without a password and reaching into it: automatic login, lingering
//! users, current login sessions, XWayland exposure and programs that can type for you.

use super::MODULE;
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, risky_home_place, shq};
use crate::modules::persistence::{parse_unit, record};
use crate::modules::{Collector, ScanCtx};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;

type Homes = [(String, u32, String)];

fn finding(col: &mut Collector, severity: Severity, rule: &str, title: String, evidence: String, description: &str, verify: &str) {
    col.push(Finding::new(severity, MODULE, rule, title).evidence(clip(&evidence, 900)).description(description.to_string()).verify(verify.to_string()));
}

// ---------------------------------------------------------------- automatic login

/// Users that a display manager's settings log in without a password.
pub fn automatic_logins(path: &str, text: &str) -> Vec<String> {
    let entries = parse_unit(text);
    let value = |section: &str, key: &str| {
        entries.iter().filter(|(s, k, _)| (section.is_empty() || s.eq_ignore_ascii_case(section)) && k.eq_ignore_ascii_case(key)).map(|(_, _, v)| v.trim().trim_matches('"').to_string()).next_back()
    };
    let on = |v: Option<String>| v.map(|v| v.eq_ignore_ascii_case("true") || v == "1").unwrap_or(false);
    let named = |v: Option<String>| v.filter(|v| !v.is_empty());
    let mut out = Vec::new();
    if path.contains("sddm") {
        out.extend(named(value("Autologin", "User")).map(|u| format!("[Autologin] User={u}")));
    } else if path.contains("gdm") {
        for (switch, user) in [("AutomaticLoginEnable", "AutomaticLogin"), ("TimedLoginEnable", "TimedLogin")] {
            if on(value("daemon", switch)) {
                out.push(format!("{switch}=true {user}={}", value("daemon", user).unwrap_or_default()));
            }
        }
    } else if path.contains("lightdm") {
        out.extend(named(value("", "autologin-user")).map(|u| format!("autologin-user={u}")));
    } else if path.contains("greetd") {
        out.extend(named(value("initial_session", "user")).map(|u| format!("[initial_session] user = {u}")));
    }
    out
}

fn check_autologin(ctx: &ScanCtx, col: &mut Collector) {
    let mut files: Vec<String> = ["/etc/sddm.conf", "/etc/gdm3/daemon.conf", "/etc/gdm3/custom.conf", "/etc/lightdm/lightdm.conf", "/etc/greetd/config.toml"].map(String::from).to_vec();
    for dir in ["/usr/lib/sddm/sddm.conf.d", "/etc/sddm.conf.d", "/usr/share/lightdm/lightdm.conf.d", "/etc/lightdm/lightdm.conf.d"] {
        files.extend(ctx.sys.dir_names(dir).into_iter().map(|n| format!("{dir}/{n}")));
    }
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        if path.starts_with("/etc/") {
            record(ctx, col, &path);
        }
        let logins = automatic_logins(&path, &text);
        if !logins.is_empty() {
            finding(col, Severity::Medium, "DESK-AUTOLOGIN", format!("The computer logs in by itself: {path}"), format!("{path}\n{}", logins.join("\n")),
                "Whoever switches the computer on gets this user's desktop without a password. Switch automatic login off if you did not choose it.", &format!("cat {}", shq(&path)));
        }
    }
}

// ---------------------------------------------------------------- lingering users and sessions

/// "KEY=value" lines of a logind session file.
fn session_fields(text: &str) -> BTreeMap<&str, &str> {
    text.lines().filter(|l| !l.starts_with('#')).filter_map(|l| l.split_once('=')).collect()
}

fn check_sessions(ctx: &ScanCtx, col: &mut Collector) {
    let lingering = ctx.sys.dir_names("/var/lib/systemd/linger");
    if !lingering.is_empty() {
        for user in &lingering {
            record(ctx, col, &format!("/var/lib/systemd/linger/{user}"));
        }
        finding(col, Severity::Low, "DESK-LINGER", "Services run for users who are not logged in".into(), lingering.join("\n"),
            "With lingering on, a user's services and timers start at boot and keep running after logout. Servers and sync tools use it; it is also a way to keep a program running.", "loginctl list-users; ls -l /var/lib/systemd/linger");
    }
    for id in ctx.sys.dir_names("/run/systemd/sessions").into_iter().filter(|n| !n.contains('.')) {
        let Ok(text) = ctx.sys.read_string(format!("/run/systemd/sessions/{id}")) else { continue };
        let fields = session_fields(&text);
        let get = |key: &str| fields.get(key).copied().unwrap_or("");
        if get("CLASS") != "user" || get("STATE") == "closing" {
            continue;
        }
        let graphical = ["x11", "wayland", "mir"].contains(&get("TYPE"));
        let remote = get("REMOTE") == "1";
        let line = format!("session {id}: user {} type {} service {}{}", get("USER"), get("TYPE"), get("SERVICE"), if remote { format!(" from {}", get("REMOTE_HOST")) } else { String::new() });
        if remote && (graphical || get("SERVICE").contains("xrdp")) {
            finding(col, Severity::Medium, "DESK-SESSION-REMOTE", format!("A graphical session from another computer: {}", get("USER")), line,
                "Someone is using a desktop on this machine over the network. Check that it is you.", &format!("loginctl session-status {id}"));
        } else if remote {
            finding(col, Severity::Info, "DESK-SESSION-REMOTE", format!("Logged in from another computer right now: {}", get("USER")), line,
                "A remote login is open at the moment.", &format!("loginctl session-status {id}"));
        } else if graphical && get("USER") == "root" {
            finding(col, Severity::Medium, "DESK-SESSION-ROOT", "root is logged in to a graphical desktop".into(), line,
                "A whole desktop running as root gives every program in it full control. Log in as yourself and use sudo.", &format!("loginctl session-status {id}"));
        }
    }
}

// ---------------------------------------------------------------- X11 and XWayland

fn check_x_servers(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    for p in ctx.processes.iter().filter(|p| ["Xwayland", "Xorg", "X"].contains(&p.display_name().as_str())) {
        let args = &p.cmdline;
        let open_network = args.windows(2).any(|w| w[0] == "-listen" && w[1] == "tcp");
        let no_check = args.iter().any(|a| a == "-ac");
        if open_network || no_check {
            let why = if no_check { "access control is switched off (-ac)" } else { "it accepts connections over the network (-listen tcp)" };
            finding(col, Severity::High, "DESK-XSERVER-OPEN", format!("The X display is open to others: {}", p.display_name()),
                format!("PID {} UID {}\ncmdline=\"{}\"\n{why}", p.pid, p.uid, clip(&p.cmdline_str(), 300)),
                "Anyone who can reach the X display can read what is typed in X11 programs, take pictures of them and type into them.", "ss -tlnp | grep ':60'");
        }
    }
    for (_, _, home) in homes {
        let path = format!("{home}/.config/kwinrc");
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        let setting = |key: &str| parse_unit(&text).into_iter().find(|(g, k, _)| g == "Xwayland" && k == key).map(|(_, _, v)| v);
        let all_keys = setting("XwaylandEavesdrops").as_deref() == Some("All");
        let mouse = setting("XwaylandEavesdropsMouse").as_deref() == Some("true");
        if all_keys || mouse {
            let mut lines = vec![path.clone()];
            lines.extend(all_keys.then(|| "XwaylandEavesdrops=All (every key)".to_string()));
            lines.extend(mouse.then(|| "XwaylandEavesdropsMouse=true".to_string()));
            finding(col, if all_keys { Severity::Medium } else { Severity::Low }, "DESK-XWAYLAND-KEYS", format!("Old X11 programs may listen to {}: {path}", if all_keys { "all typing" } else { "the mouse" }), lines.join("\n"),
                "Under Wayland, this KDE setting lets X11 programs see input meant for other windows, passwords included. Choose a stricter level in System Settings, Legacy X11 App Support.", &format!("cat {}", shq(&path)));
        }
    }
}

// ---------------------------------------------------------------- typing for you

/// Programs that send key presses and clicks to other windows.
const INJECTORS: [&str; 7] = ["ydotool", "ydotoold", "wtype", "dotool", "dotoold", "wlrctl", "xdotool"];

/// Programs that create virtual input devices as part of their job.
const UINPUT_USERS: [&str; 16] = [
    "systemd", "systemd-logind", "systemd-udevd", "keyd", "input-remapper-service", "input-remapper-reader-service", "steam",
    "kwin_wayland", "gnome-shell", "Xwayland", "solaar", "logid", "sunshine", "bluetoothd", "interception", "udevmon",
];

/// udev rules that open the keyboard devices or the virtual keyboard to everybody.
pub fn open_input_rules(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && (l.contains("uinput") || l.contains("SUBSYSTEM==\"input\"")))
        .filter(|l| ["MODE=\"0666\"", "MODE=\"666\"", "MODE=\"0777\"", "MODE:=\"0666\""].iter().any(|m| l.contains(m)))
        .map(str::to_string)
        .collect()
}

fn check_injection(ctx: &ScanCtx, col: &mut Collector) {
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread()) {
        let name = p.display_name();
        let exe = p.exe_path().unwrap_or("");
        let system = ["/usr/", "/opt/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
        let odd = ctx.cfg.is_temp_path(exe) || risky_home_place(exe, ctx.cfg).is_some();
        let typing = INJECTORS.contains(&name.as_str());
        let uinput = ctx.sys.dir_names(format!("/proc/{}/fd", p.pid)).iter().any(|fd| ctx.sys.read_link(format!("/proc/{}/fd/{fd}", p.pid)).as_deref() == Some("/dev/uinput"));
        if !typing && !uinput || uinput && !typing && system && p.is_program(&UINPUT_USERS) {
            continue;
        }
        let severity = if odd { Severity::High } else if !system || uinput { Severity::Medium } else { Severity::Low };
        finding(col, severity, "DESK-INPUT-INJECT", format!("A program can type and click for you: {name}"),
            format!("PID {} UID {} exe={}\ncmdline=\"{}\"{}", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 300), if uinput { "\nholds /dev/uinput (a virtual keyboard)" } else { "" }),
            "It can send key presses and mouse clicks, also under Wayland. Automation and remote-control tools do this; a program you do not know could run commands as you. A tool written in a script language runs as python3 or similar and cannot be recognised by its file: hide the finding if it is yours.",&format!("ls -l /proc/{}/fd | grep uinput", p.pid));
    }
    let people: Vec<String> = ctx
        .sys
        .read_string("/etc/group")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.strip_prefix("input:"))
        .flat_map(|rest| rest.rsplit(':').next().unwrap_or("").split(',').map(str::trim).filter(|m| !m.is_empty()).map(String::from).collect::<Vec<_>>())
        .collect();
    if !people.is_empty() {
        finding(col, Severity::Medium, "DESK-INPUT-GROUP", "Users who can read every keyboard".into(), format!("members of the group input: {}", people.join(", ")),
            "Every program these users start can read all key presses, passwords included, past Wayland's protection. Remove the group unless a tool you use needs it.", "getent group input");
    }
    let mut rules = Vec::new();
    for dir in ["/etc/udev/rules.d", "/usr/local/lib/udev/rules.d"] {
        for name in ctx.sys.dir_names(dir) {
            let path = format!("{dir}/{name}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            rules.extend(open_input_rules(&text).into_iter().map(|l| format!("{path}: {l}")));
        }
    }
    if let Ok(meta) = std::fs::metadata(ctx.sys.path("/dev/uinput")) {
        if meta.mode() & 0o002 != 0 {
            rules.push(format!("/dev/uinput is writable by everyone (mode {:04o})", meta.mode() & 0o7777));
        }
    }
    if !rules.is_empty() {
        finding(col, Severity::High, "DESK-INPUT-OPEN", "Everyone may reach the keyboard devices".into(), rules.join("\n"),
            "Any program of any user can read what is typed or type itself. Remove the rule.", "ls -l /dev/uinput /dev/input");
    }
}

/// Runs on any machine: typing tools and open input devices.
pub(super) fn check_input_reach(ctx: &ScanCtx, col: &mut Collector) {
    check_injection(ctx, col);
}

pub(super) fn check_session(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    check_autologin(ctx, col);
    check_sessions(ctx, col);
    check_x_servers(ctx, col, homes);
}
