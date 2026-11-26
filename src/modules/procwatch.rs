//! More process checks (part of `proc_audit`): processes that are being traced (code
//! injection, password theft) and mounts that hide processes or replace system files.

use super::common::{clip, shq};
use super::proc_audit::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::procinfo::{status_field, ProcInfo};

/// Programs that hold passwords or keys, or decide who may log in.
const SENSITIVE: [&str; 24] = [
    "sshd", "sshd-session", "sshd-auth", "sudo", "su", "login", "passwd", "ssh", "ssh-agent", "gpg-agent",
    "gnome-keyring-daemon", "kwalletd5", "kwalletd6", "keepassxc", "firefox", "firefox-esr", "chromium", "chrome",
    "brave", "thunderbird", "sddm-helper", "gdm-session-worker", "polkitd", "kscreenlocker_greet",
];

const DEBUGGERS: [&str; 10] = ["gdb", "lldb", "lldb-server", "strace", "ltrace", "rr", "perf", "valgrind", "dlv", "delve"];

/// How worrying it is that `tracer` traces `tracee`. `None` for the normal cases.
pub fn judge_trace(tracee: &str, tracee_exe: &str, tracer: &str, tracer_exe: &str) -> Option<Severity> {
    let folder = |p: &str| p.rsplit_once('/').map(|(d, _)| d.to_string()).unwrap_or_default();
    // browsers watch their own parts, Wine its programs
    let own_family = (!tracee_exe.is_empty() && tracee_exe.starts_with("/usr/") && folder(tracee_exe) == folder(tracer_exe) && !["/usr/bin", "/usr/sbin"].contains(&folder(tracee_exe).as_str()))
        || tracer == "wineserver";
    if own_family {
        return None;
    }
    let sensitive = SENSITIVE.contains(&tracee);
    let debugger = DEBUGGERS.contains(&tracer) && tracer_exe.starts_with("/usr/");
    Some(match (sensitive, debugger) {
        (true, false) => Severity::Critical,
        (true, true) => Severity::High,
        (false, false) => Severity::High,
        (false, true) => Severity::Low,
    })
}

pub(crate) fn check_tracing(ctx: &ScanCtx, col: &mut Collector) {
    for p in ctx.processes {
        let Ok(status) = ctx.sys.read_string(format!("/proc/{}/status", p.pid)) else { continue };
        let tracer_pid: u32 = status_field(&status, "TracerPid").and_then(|v| v.parse().ok()).unwrap_or(0);
        if tracer_pid == 0 {
            continue;
        }
        let tracer: Option<&ProcInfo> = ctx.processes.iter().find(|t| t.pid == tracer_pid || t.tgid == tracer_pid);
        let name = tracer.map(|t| t.display_name()).unwrap_or_else(|| "a process that is not listed".into());
        let tracer_exe = tracer.and_then(|t| t.exe_path()).unwrap_or("");
        let Some(severity) = judge_trace(&p.display_name(), p.exe_path().unwrap_or(""), &name, tracer_exe) else { continue };
        col.push(
            Finding::new(severity, MODULE, "PROC-TRACED", format!("{} is being traced by {name}", p.display_name()))
                .evidence(format!(
                    "PID {} exe={}\ntraced by PID {tracer_pid} exe={}",
                    p.pid,
                    p.exe.as_deref().unwrap_or("?"),
                    if tracer_exe.is_empty() { "?" } else { tracer_exe }
                ))
                .description("A tracing process can read everything the other one handles (passwords, keys) and change what it does. Developers do this with debuggers; attackers inject code into sshd, sudo or browsers this way.")
                .verify(format!("grep TracerPid /proc/{}/status", p.pid))
                .verify(format!("ps -o pid,user,etime,cmd -p {tracer_pid}"))
                .verify(format!("ls -l /proc/{tracer_pid}/exe")),
        );
    }
}

// ---------------------------------------------------------------- desktop session and input

/// Programs that read the keyboard and mouse devices as part of their job.
const INPUT_READERS: [&str; 34] = [
    "systemd", "systemd-logind", "Xorg", "Xwayland", "kwin_wayland", "gnome-shell", "mutter", "sway", "Hyprland",
    "wayfire", "labwc", "weston", "cosmic-comp", "upowerd", "thermald", "acpid", "thd", "keyd", "input-remapper-service",
    "interception", "ydotoold", "org_kde_powerdevil", "gsd-media-keys", "steam", "sddm", "lightdm", "gdm3", "bluetoothd",
    "solaar", "brltty", "touchegg", "logid", "iio-sensor-proxy", "systemd-udevd",
];

/// Names of programs written to record what is typed.
const KEYLOGGERS: [&str; 6] = ["logkeys", "xspy", "lkl", "uberkey", "xkbcat", "xmacrorec2"];

/// Report programs that read the keyboard directly, and say which kind of desktop session runs.
pub(crate) fn check_input_and_session(ctx: &ScanCtx, col: &mut Collector) {
    let mut sessions = std::collections::BTreeSet::new();
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread()) {
        if p.uid >= 1000 {
            if let Ok(env) = ctx.sys.read_bytes(format!("/proc/{}/environ", p.pid)) {
                let value = |key: &str| env.split(|b| *b == 0).find_map(|v| String::from_utf8_lossy(v).strip_prefix(key).map(String::from));
                if let Some(kind) = value("XDG_SESSION_TYPE=").filter(|k| k == "x11" || k == "wayland") {
                    sessions.insert((p.uid, kind, value("XDG_CURRENT_DESKTOP=").unwrap_or_else(|| "unknown desktop".into())));
                }
            }
        }
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
        let expected = system && (INPUT_READERS.contains(&name.as_str()) || INPUT_READERS.contains(&p.comm.as_str()));
        if !spying && (devices.is_empty() || expected) {
            continue;
        }
        let severity = if spying || !system { Severity::High } else { Severity::Medium };
        col.push(
            Finding::new(severity, MODULE, "PROC-INPUT-READER", format!("Program reads the keyboard or mouse directly: {name}"))
                .evidence(format!(
                    "PID {} UID {} exe={}\ncmdline=\"{}\"\n{}",
                    p.pid,
                    p.uid,
                    p.exe.as_deref().unwrap_or("?"),
                    clip(&p.cmdline_str(), 300),
                    clip(&devices.join(", "), 300)
                ))
                .description("A program that reads the input devices sees everything typed, passwords included, under both Wayland and X11. Key remappers and game or mouse tools do this on purpose; check that you installed this one.")
                .verify(format!("ls -l /proc/{}/fd | grep input", p.pid))
                .verify(format!("ps -o pid,user,etime,cmd -p {}", p.pid)),
        );
    }
    for (uid, kind, desktop) in sessions {
        col.note(if kind == "x11" {
            format!("Desktop session of user {uid}: X11 ({desktop}). In X11 every program in the session can read what is typed and take pictures of the screen, so an unknown program matters more")
        } else {
            format!("Desktop session of user {uid}: Wayland ({desktop}). Programs cannot read each other's keyboard input; only the input devices themselves would give that away")
        });
    }
}

/// One line of /proc/<pid>/mountinfo: (mount point, root within the file system, type, source).
pub fn parse_mount(line: &str) -> Option<(String, String, String, String)> {
    let (left, right) = line.split_once(" - ")?;
    let mut left = left.split_whitespace().skip(3);
    let (root, point) = (left.next()?, left.next()?);
    let mut right = right.split_whitespace();
    Some((point.replace("\\040", " "), root.to_string(), right.next()?.to_string(), right.next().unwrap_or("").to_string()))
}

/// Folders where nothing is normally mounted over single files or parts.
const PROTECTED: [&str; 7] = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/lib"];

/// Is this mount hiding something? (severity, why)
pub fn judge_mount(point: &str, root: &str, kind: &str) -> Option<(Severity, &'static str)> {
    if let Some(rest) = point.strip_prefix("/proc/") {
        let first = rest.split('/').next().unwrap_or("");
        if !first.is_empty() && first.chars().all(|c| c.is_ascii_digit()) {
            return Some((Severity::Critical, "covers a process folder, which hides that process from ps and top"));
        }
        let usual = ["binfmt_misc", "nfsd", "autofs", "fuse.lxcfs"].contains(&kind);
        return (!usual).then_some((Severity::Medium, "is mounted over part of /proc"));
    }
    let inside = PROTECTED.iter().any(|d| point == *d || point.starts_with(&format!("{d}/")));
    if !inside || kind == "autofs" {
        return None;
    }
    // a whole disk partition for /usr or /etc is ordinary; a part of one, or memory, is not
    let part = root != "/";
    let memory = ["tmpfs", "ramfs", "overlay"].contains(&kind);
    (part || memory).then_some((Severity::High, "is mounted over system files, which replaces what programs see there"))
}

pub(crate) fn check_mounts(ctx: &ScanCtx, col: &mut Collector) {
    // the first process shows the machine's own view, also from inside a sandboxed service
    let Some((source, text)) = ["/proc/1/mountinfo", "/proc/self/mountinfo"].iter().find_map(|p| Some((*p, ctx.sys.read_string(p).ok()?))) else { return };
    for line in text.lines() {
        let Some((point, root, kind, from)) = parse_mount(line) else { continue };
        let Some((severity, why)) = judge_mount(&point, &root, &kind) else { continue };
        col.push(
            Finding::new(severity, MODULE, "PROC-HIDDEN-MOUNT", format!("Something is mounted over {point}"))
                .evidence(format!("{source}: {}", clip(line, 300)))
                .description(format!("A mount from {from} ({kind}, part {root}) {why}. This needs root and is a way to hide or swap files without a rootkit."))
                .verify(format!("findmnt {}", shq(&point)))
                .verify(format!("grep -F -- {} /proc/1/mountinfo", shq(&point))),
        );
    }
}
