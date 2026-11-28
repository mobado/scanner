//! Who asks the password wallet (part of `proc_audit`, full scan): listens on the user's D-Bus
//! session for a short while for requests to the Secret Service (GNOME Keyring, KWallet,
//! KeePassXC) and to KWallet. `dbus-monitor --profile` prints only who asked for what, so
//! passwords never pass through the scanner.

use super::common::{clip, risky_home_place};
use super::proc_audit::MODULE;
use super::secrets::{foreign_note, without_exception};
use super::{Collector, ScanCtx};
use crate::config::Config;
use crate::external_tools::{find_binary, run_capture};
use crate::finding::{Finding, Severity};
use crate::procinfo::{read_proc, ProcInfo};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const MATCHES: [&str; 4] = [
    "interface='org.freedesktop.Secret.Service'",
    "interface='org.freedesktop.Secret.Item'",
    "interface='org.freedesktop.Secret.Collection'",
    "interface='org.kde.KWallet'",
];

/// Programs that can send any request typed on a command line or written in a script.
const GENERAL_TOOLS: [&str; 14] = [
    "python", "python3", "perl", "ruby", "node", "bash", "sh", "dash", "secret-tool", "gdbus", "dbus-send", "busctl", "qdbus", "kwallet-query",
];

/// A line of `dbus-monitor --profile` that is a method call: (sender, interface, member).
pub fn parse_call(line: &str) -> Option<(&str, &str, &str)> {
    // type, time, serial, sender, destination, path, interface, member
    let f: Vec<&str> = line.split('\t').collect();
    (f.len() >= 8 && f[0] == "mc").then(|| (f[3], f[6], f[7]))
}

/// Does this call open the wallet or fetch from it? Questions such as "is the wallet on?" do not.
pub fn asks_for_secrets(member: &str) -> bool {
    ["GetSecrets", "GetSecret", "SearchItems", "Unlock", "OpenSession", "open", "openAsync", "openPath"].contains(&member) || member.starts_with("read") || member.ends_with("List")
}

/// How worrying it is that this program asks the wallet: (severity, why). `Low` is an installed
/// program doing so, which is normal.
pub fn judge_caller(cfg: &Config, names: &[String], exe: &str) -> (Severity, &'static str) {
    if exe.starts_with("/memfd:") || cfg.is_temp_path(exe) && !exe.starts_with("/tmp/.mount_") {
        return (Severity::Critical, "it runs from memory or a temporary folder");
    }
    if risky_home_place(exe, cfg).is_some() || exe.ends_with(" (deleted)") && !exe.starts_with("/usr/") {
        return (Severity::High, "it runs from a download, cache or hidden folder, or its file is gone");
    }
    // "python3.13" is python
    if crate::procinfo::runs_any_code(crate::procinfo::basename(exe.trim_end_matches(" (deleted)"))) || names.iter().any(|n| GENERAL_TOOLS.contains(&n.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.')) || GENERAL_TOOLS.contains(&n.as_str())) {
        return (Severity::Medium, "it is a script or command line tool, which any script can use");
    }
    let installed = ["/usr/", "/opt/", "/snap/", "/app/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
    if installed {
        (Severity::Low, "an installed program")
    } else {
        (Severity::Medium, "it was not installed in the system folders")
    }
}

/// A user's session bus: (uid, gid, address).
pub(crate) fn sessions(ctx: &ScanCtx) -> Vec<(u32, u32, String)> {
    let own: Option<u32> = ctx.sys.read_string("/proc/self/status").ok().and_then(|s| crate::procinfo::status_field(&s, "Uid").and_then(|v| v.split_whitespace().next().and_then(|u| u.parse().ok())));
    let passwd = ctx.sys.read_string("/etc/passwd").unwrap_or_default();
    passwd
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            let (uid, gid): (u32, u32) = (f.get(2)?.parse().ok()?, f.get(3)?.parse().ok()?);
            let socket = format!("/run/user/{uid}/bus");
            let mine = ctx.privileged && uid >= 1000 || own == Some(uid);
            (mine && ctx.sys.exists(&socket)).then(|| (uid, gid, format!("unix:path={socket}")))
        })
        .take(3)
        .collect()
}

/// The command that runs `program` on the user's bus: as that user when the scan runs as root,
/// because a session bus only talks to its owner.
pub(crate) fn as_user(ctx: &ScanCtx, uid: u32, gid: u32, program: PathBuf, args: Vec<String>) -> Option<(PathBuf, Vec<String>)> {
    if !ctx.privileged || uid == 0 {
        return Some((program, args));
    }
    let setpriv = find_binary("setpriv")?;
    let mut all = vec![format!("--reuid={uid}"), format!("--regid={gid}"), "--clear-groups".to_string(), program.display().to_string()];
    all.extend(args);
    Some((setpriv, all))
}

/// Can the user's session bus be asked at all? Else why not: a check that could not ask must not
/// look like one that found nothing.
pub(crate) fn reach_bus(ctx: &ScanCtx, uid: u32, gid: u32, address: &str) -> Result<(), String> {
    let busctl = find_binary("busctl").ok_or("busctl is not installed")?;
    let args = vec![format!("--address={address}"), "--auto-start=no".into(), "call".into(), "org.freedesktop.DBus".into(), "/org/freedesktop/DBus".into(), "org.freedesktop.DBus".into(), "GetId".into()];
    let (program, args) = as_user(ctx, uid, gid, busctl, args).ok_or("setpriv is not installed")?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    crate::external_tools::run_checked(&program, &args, 5).map(|_| ())
}

/// The program behind a bus name, asked while it is still connected.
fn caller(ctx: &ScanCtx, uid: u32, gid: u32, address: &str, sender: &str) -> Option<ProcInfo> {
    let args = ["call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionUnixProcessID", "s", sender];
    let mut all = vec![format!("--address={address}")];
    all.extend(args.iter().map(|a| a.to_string()));
    let (program, args) = as_user(ctx, uid, gid, find_binary("busctl")?, all)?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let out = run_capture(&program, &args, 5).ok()?;
    // "u 1234"
    let pid: u32 = out.stdout.split_whitespace().nth(1)?.parse().ok()?;
    read_proc(ctx.sys, pid)
}

/// Listen on one bus for `secs` seconds: program (if still known) → the calls it made.
fn listen(ctx: &ScanCtx, uid: u32, gid: u32, address: &str, secs: u64) -> Option<Vec<(Option<ProcInfo>, BTreeSet<String>)>> {
    let mut args = vec!["--address".to_string(), address.to_string(), "--profile".to_string()];
    args.extend(MATCHES.iter().map(|m| m.to_string()));
    let (program, args) = as_user(ctx, uid, gid, find_binary("dbus-monitor")?, args)?;
    let mut child = Command::new(program).args(args).env("LC_ALL", "C").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().ok()?;
    let out = child.stdout.take()?;
    let (send, receive) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    let end = Instant::now() + Duration::from_secs(secs);
    let mut calls: BTreeMap<String, (Option<ProcInfo>, BTreeSet<String>)> = BTreeMap::new();
    // the channel closes early if the program could not listen
    let mut heard_anything = false;
    while let Some(left) = end.checked_duration_since(Instant::now()) {
        let Ok(line) = receive.recv_timeout(left) else { break };
        heard_anything = true;
        let Some((sender, interface, member)) = parse_call(&line) else { continue };
        if !asks_for_secrets(member) || calls.len() >= 50 && !calls.contains_key(sender) {
            continue;
        }
        let entry = calls.entry(sender.to_string()).or_insert_with(|| (caller(ctx, uid, gid, address, sender), BTreeSet::new()));
        entry.1.insert(format!("{interface}.{member}"));
    }
    let failed = !heard_anything && matches!(child.try_wait(), Ok(Some(_)));
    let _ = child.kill();
    let _ = child.wait();
    (!failed).then(|| calls.into_values().collect())
}

/// Names on the session bus that receive passwords or hand out files and the screen, with the
/// programs that normally provide them.
pub(crate) const OWNERS: [(&str, &[&str]); 4] = [
    ("org.freedesktop.secrets", &["gnome-keyring-daemon", "ksecretd", "kwalletd5", "kwalletd6", "keepassxc", "oo7-daemon"]),
    ("org.kde.kwalletd6", &["ksecretd", "kwalletd6"]),
    ("org.kde.kwalletd5", &["ksecretd", "kwalletd5", "kwalletd6"]),
    ("org.freedesktop.portal.Desktop", &["xdg-desktop-portal"]),
];

/// How worrying it is that this program answers to the name. `None` for the usual providers,
/// known by their program file only.
pub fn judge_owner(cfg: &Config, name: &str, exe: &str) -> Option<Severity> {
    let usual = OWNERS.iter().find(|o| o.0 == name)?.1;
    let installed = ["/usr/", "/opt/", "/app/", "/snap/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
    if installed && crate::procinfo::is_program_path(exe, usual) {
        None
    } else if !installed || cfg.is_temp_path(exe) || risky_home_place(exe, cfg).is_some() {
        Some(Severity::High)
    } else {
        Some(Severity::Medium)
    }
}

/// The finding about the program `p` holding `name`, if there is one: another program than the
/// usual ones, or a usual one that runs foreign code.
pub fn judge_holder(ctx: &ScanCtx, uid: u32, name: &str, p: &ProcInfo) -> Option<Finding> {
    let judged = judge_owner(ctx.cfg, name, p.exe_path().unwrap_or(""));
    let usual = OWNERS.iter().find(|o| o.0 == name)?.1;
    // whoever holds a name of the password wallet gets no exceptions for the code it runs
    let code = if name == "org.freedesktop.portal.Desktop" { p.foreign_code(ctx) } else { p.foreign_code_strict(ctx.sys) };
    let clean = judged.is_some() || code.as_ref().is_some_and(|c| c.is_empty()) && p.is_program(usual);
    let (severity, title, foreign) = match judged {
        // the path says nothing about what this program is
        judged if p.claimed().is_some() => (judged.unwrap_or(Severity::High).max(Severity::High), format!("A program that is not the installed one answers as {name}: {}", p.display_name()), p.mount_note()),
        _ if !clean => {
            let what = if code.is_some() { "runs foreign code" } else { "cannot be checked" };
            (without_exception(&code, Severity::High, Severity::Medium), format!("The program answering as {name} {what}: {}", p.display_name()), foreign_note(&code))
        }
        Some(severity) => (severity, format!("An unusual program answers as {name}: {}", p.display_name()), String::new()),
        None => return None,
    };
    Some(
        Finding::new(severity, MODULE, "PROC-SECRET-SERVICE", title)
            .evidence(format!("PID {} UID {} exe={}\ncmdline=\"{}\"\nholds {name} on the session bus of user {uid}{foreign}", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 300)))
            .description("Programs send passwords to whoever holds this name, or ask it for files and screen pictures. Another wallet program you chose looks like this; so does an impostor, or code slipped into the usual program.")
            .verify(format!("busctl --user status {name}"))
            .verify(format!("grep -E ' r.x. ' /proc/{}/maps", p.pid)),
    )
}

/// Who answers when a program asks for saved passwords or for the screen?
pub(crate) fn check_owners(ctx: &ScanCtx, col: &mut Collector) {
    if !ctx.sys.is_live() {
        return;
    }
    for (uid, gid, address) in sessions(ctx) {
        if let Err(why) = reach_bus(ctx, uid, gid, &address) {
            col.note(format!("Session bus of user {uid}: NOT CHECKED – it could not be asked ({why}), so who answers as the wallet and the desktop portal was not looked at"));
            continue;
        }
        let mut usual = Vec::new();
        for (name, _) in OWNERS {
            // a name nobody holds gives no answer
            let Some(p) = caller(ctx, uid, gid, &address, name) else { continue };
            if let Some(finding) = judge_holder(ctx, uid, name, &p) {
                col.push(finding);
            } else {
                usual.push(format!("{name}: {}", p.display_name()));
            }
        }
        if !usual.is_empty() {
            col.note(format!("Session bus of user {uid}: {}", usual.join(", ")));
        }
    }
}

pub(crate) fn watch(ctx: &ScanCtx, col: &mut Collector) {
    let secs = ctx.wallet_watch_secs;
    if secs == 0 || !ctx.sys.is_live() {
        return;
    }
    if find_binary("dbus-monitor").is_none() {
        col.note("Password wallet: dbus-monitor (package dbus-bin) is not installed, so requests to the wallet were not listened for");
        return;
    }
    let sessions = sessions(ctx);
    if sessions.is_empty() {
        col.note("Password wallet: no user session bus to listen on");
    }
    for (uid, gid, address) in sessions {
        let Some(calls) = listen(ctx, uid, gid, &address, secs) else {
            col.note(format!("Password wallet: could not listen on the session bus of user {uid}"));
            continue;
        };
        let mut normal = BTreeSet::new();
        for (process, asked) in calls {
            let asked = asked.into_iter().collect::<Vec<_>>().join(", ");
            let Some(p) = process else {
                col.push(
                    Finding::new(Severity::Low, MODULE, "PROC-SECRET-CALL", "A program that ended at once asked the password wallet")
                        .evidence(format!("session of user {uid}: {asked}"))
                        .description("The program was gone before it could be identified. Command line tools do this; run the full scan again and watch whether it repeats.")
                        .verify("dbus-monitor --session --profile \"interface='org.freedesktop.Secret.Service'\""),
                );
                continue;
            };
            let (mut severity, mut why) = judge_caller(ctx.cfg, &p.candidate_names(), p.exe.as_deref().unwrap_or(""));
            // being installed counts for nothing while the program runs foreign code, or when
            // its code cannot be seen
            if p.claimed().is_some() {
                (severity, why) = (Severity::High, "its program file is not the one installed at the path it shows");
            }
            if severity == Severity::Low {
                match p.foreign_code(ctx) {
                    Some(code) if !code.is_empty() => (severity, why) = (Severity::High, "an installed program that runs code from a place your programs can write to"),
                    None => (severity, why) = (Severity::Medium, "an installed program whose code could not be checked (it may have ended)"),
                    Some(_) => {}
                }
            }
            if severity == Severity::Low {
                normal.insert(p.display_name());
                continue;
            }
            col.push(
                Finding::new(severity, MODULE, "PROC-SECRET-CALL", format!("{} asked the password wallet for secrets", p.display_name()))
                    .evidence(format!("PID {} UID {} exe={}\ncmdline=\"{}\"\nasked: {}\n{why}", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 300), clip(&asked, 400)))
                    .description("While the wallet is unlocked, any program in your session can ask it for saved passwords. If you do not know this program, disconnect from the network and change your passwords from another computer.")
                    .verify(format!("ps -o pid,user,lstart,cmd -p {}", p.pid))
                    .verify(format!("pstree -asp {}", p.pid)),
            );
        }
        let who = if normal.is_empty() { "none".to_string() } else { normal.into_iter().collect::<Vec<_>>().join(", ") };
        col.note(format!("Password wallet: listened {secs} s to the session of user {uid}; installed programs that asked for secrets: {who}"));
    }
}
