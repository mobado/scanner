//! desktop_session: everything tied to a graphical session, gathered in one module. Shared XDG
//! standards (autostart, portals, session and login-screen scripts), path rules for KDE Plasma,
//! GNOME, XFCE and lighter window managers, keyboard readers, and whether sessions run Wayland
//! or X11. Every finding is labelled [xdg], [kde], [gnome], [xfce], [wm], [login], [x11] or
//! [input]. On a machine without a graphical desktop (a server) only the keyboard check runs,
//! and the baseline tells when a desktop appears there.

pub mod environments;
pub mod gvdb;
pub mod input;
pub mod xdg;

use super::persistence::home_dirs;
use super::{Collector, ScanCtx};
use crate::procinfo::read_accounts;

pub const MODULE: &str = "desktop_session";

const LOGIN_SCREENS: [(&str, &str); 6] = [
    ("/usr/bin/sddm", "sddm"), ("/usr/sbin/gdm3", "gdm3"), ("/usr/sbin/lightdm", "lightdm"), ("/usr/sbin/lxdm", "lxdm"),
    ("/usr/sbin/greetd", "greetd"), ("/usr/bin/greetd", "greetd"),
];

/// Display servers, window managers and remote-screen servers.
const GRAPHICAL_PROCESSES: [&str; 20] = [
    "Xorg", "Xwayland", "gnome-shell", "kwin_wayland", "kwin_x11", "plasmashell", "xfce4-session", "sway", "Hyprland",
    "labwc", "wayfire", "weston", "openbox", "i3", "lxqt-session", "cinnamon", "mate-session", "Xvnc", "x11vnc", "Xvfb",
];

/// What shows that this machine has (or runs) a graphical desktop. Empty on a plain server.
pub fn graphical_signs(ctx: &ScanCtx) -> Vec<String> {
    let mut signs = Vec::new();
    for dir in ["/usr/share/xsessions", "/usr/share/wayland-sessions"] {
        signs.extend(ctx.sys.dir_names(dir).into_iter().filter(|n| n.ends_with(".desktop")).map(|n| format!("installed: session {n}")));
    }
    signs.extend(LOGIN_SCREENS.iter().filter(|(p, _)| ctx.sys.exists(p)).map(|(_, n)| format!("installed: login screen {n}")));
    if ctx.sys.exists("/usr/lib/xorg/Xorg") {
        signs.push("installed: X server".into());
    }
    for p in ctx.processes {
        let name = p.display_name();
        if GRAPHICAL_PROCESSES.contains(&name.as_str()) {
            signs.push(format!("running: {name}"));
        }
    }
    signs.sort();
    signs.dedup();
    signs
}

/// Is this a file that the desktop_session module records for the baseline?
pub fn is_desktop_path(path: &str) -> bool {
    const PARTS: [&str; 29] = [
        "/autostart/", "/autostart-scripts/", "/plasma-workspace/", "/etc/X11/", "/etc/gdm3/", "/etc/sddm", "/etc/lightdm/",
        "/dbus-1/", "/xdg-desktop-portal/", "/.config/sway/", "/.config/swayidle/", "/.config/i3/", "/.i3/", "openbox/",
        "lxsession/", "/.config/hypr/", "/.config/labwc/", "/.config/wayfire.ini", "/.fluxbox/", "/.xscreensaver",
        "/etc/sway/", "/kwin/", "/kglobalaccel/", "/.config/xfce4/", "/gnome-session/", "/etc/dconf/", "/.xprofile",
        "/.xinitrc", "/.xsession",
    ];
    PARTS.iter().any(|p| path.contains(p))
}

/// The label of a finding, from its rule and the file it is about (the first evidence line).
pub fn label_of(rule: &str, evidence: &str) -> &'static str {
    match rule {
        "PERS-KWIN-SCRIPT" | "PERS-KWIN-RULE" => return "kde",
        "PERS-REMOTE-DESKTOP" | "PERS-SCREEN-LOCK" | "PERS-GNOME-EXTENSION" => return "gnome",
        "PERS-DM-SCRIPT" => return "login",
        "PERS-X11-OPEN" => return "x11",
        "PROC-INPUT-READER" => return "input",
        _ => {}
    }
    let path = evidence.lines().next().unwrap_or("");
    let has = |parts: &[&str]| parts.iter().any(|p| path.contains(p));
    if has(&["plasma", "autostart-scripts", "ksmserverrc", "notifyrc", "khotkeysrc", "kglobalaccel", "kioslaverc", "kwin"]) {
        "kde"
    } else if has(&["/etc/gdm3", "/etc/sddm", "/etc/lightdm"]) {
        "login"
    } else if has(&["dconf", "gnome"]) {
        "gnome"
    } else if has(&["xfce"]) {
        "xfce"
    } else if has(&["/sway", "/i3/", "/.i3/", "/hypr/", "openbox", "lxsession", "labwc", "wayfire", "fluxbox", "xscreensaver"]) {
        "wm"
    } else {
        "xdg"
    }
}

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    let first = col.findings.len();
    // a program that records the keyboard matters on any machine
    input::check_input(ctx, col);
    let signs = graphical_signs(ctx);
    if signs.is_empty() {
        col.note("desktop_session: no graphical desktop was found on this machine, so the desktop checks were skipped (the baseline reports if one appears)");
    } else {
        let accounts = read_accounts(ctx.sys);
        let homes = home_dirs(ctx, &accounts);
        xdg::check_xdg(ctx, col, &homes);
        environments::check_environments(ctx, col, &homes);
        input::note_sessions(ctx, col);
    }
    col.inventory.desktop = Some(signs);
    for f in col.findings.iter_mut().skip(first) {
        f.title = format!("[{}] {}", label_of(&f.rule, &f.evidence), f.title);
        f.module = MODULE.to_string();
    }
}
