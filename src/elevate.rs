//! Restart the program with sudo.
//!
//! Flow:
//! 1. `sudo -v` asks for the password – in the terminal if there is one, otherwise in a
//!    small password window of our own (the program then acts as sudo's SUDO_ASKPASS).
//! 2. The root version is started as a *child* of this process:
//!    `sudo -n -- env DISPLAY=… <program> <same flags> --no-sudo`.
//!    (Without a terminal sudo ties the cached password to the parent process, so
//!    the process must not be replaced with exec – then sudo would ask again.)
//!    If sudo still does not accept the cached password, it asks once more.
//! 3. This process waits and exits with the root version's exit code. If the root
//!    version does not start (e.g. the window cannot open as root), the program continues
//!    without root and shows why, instead of just disappearing.

use std::ffi::OsString;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Environment variable that says the process is sudo's password prompt.
pub const ASKPASS_ENV: &str = "SCANNER_ASKPASS";

pub enum Outcome {
    /// The root version finished; exit with this exit code.
    Ran(u8),
    /// It did not work – continue without root and show the message.
    Declined(String),
}

const NO_SUDO: &str = "sudo is not installed – run the program as root (apt install sudo).";
const NOT_AUTH: &str = "No valid sudo password – the scanner runs without root and does not see everything.";
const CANNOT_ASK: &str = "Could not ask for the sudo password (no terminal or screen) – running without root.";

/// Debian's sudo. Never looked up in PATH: a program of the user could put a fake one there and
/// collect the password.
const SUDO: &str = "/usr/bin/sudo";

fn sudo_path() -> Result<PathBuf, String> {
    let sudo = Path::new(SUDO);
    if !sudo.exists() {
        return Err(NO_SUDO.into());
    }
    match scanner::trust::sudo_problem(sudo) {
        Some(why) => Err(format!("The password was not asked for: {why}. Check your sudo installation – running without root.")),
        None => Ok(sudo.to_path_buf()),
    }
}

/// This program, if only root can change it: it is what gets root rights.
fn self_exe() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|_| CANNOT_ASK.to_string())?;
    match scanner::trust::changeable_by_others(&exe) {
        Some(why) => Err(format!(
            "Root rights were not asked for: {why}, so another program could replace the scanner and run as root. Install the .deb package (it puts the scanner in /usr/bin) – running without root."
        )),
        None => Ok(exe),
    }
}

fn has_display() -> bool {
    std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
}

/// The display variables the root process needs to draw the window.
fn display_env() -> Vec<String> {
    let mut out = Vec::new();
    for key in [
        "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP",
        "LANG", "LC_ALL", "LANGUAGE",
    ] {
        if let Ok(v) = std::env::var(key) {
            out.push(format!("{key}={v}"));
        }
    }
    let xauth = std::env::var("XAUTHORITY").ok().or_else(|| {
        let p = Path::new(&std::env::var("HOME").ok()?).join(".Xauthority");
        p.exists().then(|| p.display().to_string())
    });
    if let Some(x) = xauth {
        out.push(format!("XAUTHORITY={x}"));
    }
    out
}

/// Add the password window (askpass) to a sudo command.
fn with_askpass(cmd: &mut Command, exe: &Path) {
    cmd.arg("-A").env("SUDO_ASKPASS", exe).env(ASKPASS_ENV, "1");
}

/// Ask for the password (once). True if sudo accepted it.
fn validate(sudo: &Path, exe: &Path, askpass: bool, terminal: bool) -> bool {
    let mut v = Command::new(sudo);
    if askpass {
        with_askpass(&mut v, exe);
    }
    v.args(["-v", "-p", "Password for %p: "]);
    if !terminal {
        v.stdin(Stdio::null());
    }
    matches!(v.status(), Ok(st) if st.success())
}

/// Build the command that starts the root version. Uses the cached password if sudo
/// accepts it (`sudo -n true` succeeds), otherwise sudo asks once more.
fn root_command(sudo: &Path, exe: &Path, args: &[OsString], askpass: bool) -> Command {
    let cached = Command::new(sudo)
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let mut cmd = Command::new(sudo);
    if cached {
        cmd.arg("-n");
    } else if askpass {
        with_askpass(&mut cmd, exe);
        cmd.args(["-p", "Password for %p: "]);
    }
    cmd.arg("--").arg("/usr/bin/env").args(display_env()).arg(exe).args(args).arg("--no-sudo");
    cmd
}

/// Ask for the password and run the root version. See the module description.
pub fn relaunch_with_sudo(args: &[OsString], gui: bool) -> Outcome {
    // both are checked before any password is typed
    let sudo = match sudo_path() {
        Ok(p) => p,
        Err(why) => return Outcome::Declined(why),
    };
    let exe = match self_exe() {
        Ok(p) => p,
        Err(why) => return Outcome::Declined(why),
    };

    let terminal = std::io::stdin().is_terminal();
    // Window mode always asks in a window; terminal mode asks in the terminal when there is one.
    let askpass = cfg!(feature = "gui") && has_display() && (gui || !terminal);
    if !askpass && !terminal {
        return Outcome::Declined(CANNOT_ASK.into());
    }
    if !validate(&sudo, &exe, askpass, terminal) {
        return Outcome::Declined(NOT_AUTH.into());
    }

    let mut cmd = root_command(&sudo, &exe, args, askpass);
    if !terminal {
        cmd.stdin(Stdio::null());
    }
    cmd.stderr(Stdio::piped());
    let started = Instant::now();
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return Outcome::Declined(format!("Could not restart with sudo: {e} – running without root.")),
    };

    // Pass the root version's error output on and keep the last lines.
    let tail = Arc::new(Mutex::new(String::new()));
    let reader = child.stderr.take().map(|mut err| {
        let tail = tail.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = err.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let _ = std::io::stderr().write_all(&buf[..n]);
                if let Ok(mut t) = tail.lock() {
                    t.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if t.len() > 4000 {
                        let cut = t.len() - 4000;
                        let cut = (cut..t.len()).find(|i| t.is_char_boundary(*i)).unwrap_or(0);
                        t.replace_range(..cut, "");
                    }
                }
            }
        })
    });

    let status = child.wait();
    if let Some(r) = reader {
        let _ = r.join();
    }
    let code = status.ok().and_then(|s| s.code());
    let last_line = tail
        .lock()
        .ok()
        .and_then(|t| t.lines().rev().find(|l| !l.trim().is_empty()).map(|l| l.trim().to_string()))
        .unwrap_or_default();

    match code {
        Some(0) => Outcome::Ran(0),
        // Terminal mode: the exit code means something (1 = high findings, 2 = critical) – pass it on.
        Some(c) if !gui => Outcome::Ran(c.clamp(0, 255) as u8),
        // Window mode: the root version did not start or crashed at once – open without root instead.
        _ if gui && started.elapsed() < Duration::from_secs(20) => Outcome::Declined(format!(
            "The root version could not start{} – the scanner runs without root.",
            if last_line.is_empty() { String::new() } else { format!(" ({last_line})") }
        )),
        Some(c) => Outcome::Ran(c.clamp(0, 255) as u8),
        None => Outcome::Ran(3),
    }
}

/// Start a new root instance in the background (the button in the window).
#[cfg(feature = "gui")]
pub fn spawn_with_sudo(args: &[OsString]) -> Result<(), String> {
    let sudo = sudo_path()?;
    let exe = self_exe()?;
    if !validate(&sudo, &exe, true, false) {
        return Err(NOT_AUTH.into());
    }
    let mut child = root_command(&sudo, &exe, args, true)
        .stdin(Stdio::null())
        .spawn()
        .map_err(|_| "Could not restart with sudo.".to_string())?;
    // If the root version dies at once, this window stays open.
    std::thread::sleep(Duration::from_secs(3));
    match child.try_wait() {
        Ok(Some(st)) if !st.success() => Err("The root version could not start – this window keeps running without root.".into()),
        _ => Ok(()),
    }
}
