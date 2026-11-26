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
