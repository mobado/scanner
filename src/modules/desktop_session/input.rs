//! Who reads the keyboard, and what kind of session (Wayland or X11) is running.

use crate::finding::{Finding, Severity};
use crate::modules::common::clip;
use crate::modules::secrets::foreign_note;
use crate::modules::{Collector, ScanCtx};
use std::collections::BTreeSet;

/// Programs that read the keyboard and mouse devices as part of their job.
const INPUT_READERS: [&str; 34] = [
    "systemd", "systemd-logind", "Xorg", "Xwayland", "kwin_wayland", "gnome-shell", "mutter", "sway", "Hyprland",
    "wayfire", "labwc", "weston", "cosmic-comp", "upowerd", "thermald", "acpid", "thd", "keyd", "input-remapper-service",
    "interception", "ydotoold", "org_kde_powerdevil", "gsd-media-keys", "steam", "sddm", "lightdm", "gdm3", "bluetoothd",
    "solaar", "brltty", "touchegg", "logid", "iio-sensor-proxy", "systemd-udevd",
];

/// Names of programs written to record what is typed.
const KEYLOGGERS: [&str; 6] = ["logkeys", "xspy", "lkl", "uberkey", "xkbcat", "xmacrorec2"];

/// Report programs that read the keyboard directly.
pub(super) fn check_input(ctx: &ScanCtx, col: &mut Collector) {
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread()) {
        let name = p.display_name();
        let exe = p.exe_path().unwrap_or("");
        let system = ["/usr/", "/opt/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
        // "xinput test <keyboard>" prints every key pressed in an X11 session
        let spying = KEYLOGGERS.contains(&name.as_str()) || (name == "xinput" && p.cmdline.iter().any(|a| a == "test" || a.starts_with("test-xi") || a == "--test-xi2"));
        let devices: Vec<String> = ctx
            .sys
            .dir_names(format!("/proc/{}/fd", p.pid))
            .into_iter()
            .filter_map(|fd| ctx.sys.read_link(format!("/proc/{}/fd/{fd}", p.pid)))
            .filter(|t| t.starts_with("/dev/input/event") || t.starts_with("/dev/input/mice") || t.starts_with("/dev/input/mouse"))
            .collect();
        let expected = system && p.is_clean_program(ctx, &INPUT_READERS);
        if !spying && (devices.is_empty() || expected) {
            continue;
        }
        // an expected reader that runs foreign code is no longer excused, and weighs more; nor
        // is one whose code cannot be seen
        let unexcused = (system && p.is_program(&INPUT_READERS) && !expected).then(|| p.foreign_code(ctx.sys));
        let tainted = unexcused.as_ref().is_some_and(|code| code.is_some());
        let severity = if spying || !system || tainted { Severity::High } else { Severity::Medium };
        let foreign = unexcused.as_ref().map(foreign_note).unwrap_or_default();
        col.push(
            Finding::new(severity, super::MODULE, "PROC-INPUT-READER", format!("Program reads the keyboard or mouse directly: {name}"))
                .evidence(format!(
                    "PID {} UID {} exe={}\ncmdline=\"{}\"\n{}{foreign}",
                    p.pid,
                    p.uid,
                    p.exe.as_deref().unwrap_or("?"),
                    clip(&p.cmdline_str(), 300),
                    clip(&devices.join(", "), 300)
                ))
                .description("A program that reads the input devices sees everything typed, passwords included, under both Wayland and X11. Key remappers and game or mouse tools do this on purpose; check that you installed this one. A program written in a script language runs as python3 or similar and cannot be recognised by its file: hide the finding if it is yours.")
                .verify(format!("ls -l /proc/{}/fd | grep input", p.pid))
                .verify(format!("ps -o pid,user,etime,cmd -p {}", p.pid)),
        );
    }
}

/// Say which kind of desktop session each user runs (from XDG_SESSION_TYPE of their programs).
pub(super) fn note_sessions(ctx: &ScanCtx, col: &mut Collector) {
    let mut sessions = BTreeSet::new();
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread() && p.uid >= 1000) {
        let Ok(env) = ctx.sys.read_bytes(format!("/proc/{}/environ", p.pid)) else { continue };
        let value = |key: &str| env.split(|b| *b == 0).find_map(|v| String::from_utf8_lossy(v).strip_prefix(key).map(String::from));
        if let Some(kind) = value("XDG_SESSION_TYPE=").filter(|k| k == "x11" || k == "wayland") {
            sessions.insert((p.uid, kind, value("XDG_CURRENT_DESKTOP=").unwrap_or_else(|| "unknown desktop".into())));
        }
    }
    for (uid, kind, desktop) in sessions {
        col.note(if kind == "x11" {
            format!("Desktop session of user {uid}: X11 ({desktop}). In X11 every program in the session can read what is typed and take pictures of the screen, so an unknown program matters more")
        } else {
            format!("Desktop session of user {uid}: Wayland ({desktop}). Programs cannot read each other's keyboard input; only the input devices themselves would give that away")
        });
    }
}
