//! Reads processes from /proc. Processes can disappear at any time, so every
//! read is tolerant: missing files give empty fields, never a panic.

use crate::sys::SysRoot;
use serde::{Deserialize, Serialize};

/// Flag in /proc/<pid>/stat that marks kernel threads.
pub const PF_KTHREAD: u64 = 0x0020_0000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcInfo {
    pub pid: u32,
    pub ppid: u32,
    pub tgid: u32,
    pub uid: u32,
    pub state: char,
    pub comm: String,
    pub cmdline: Vec<String>,
    /// Target of /proc/<pid>/exe, e.g. "/usr/bin/bash" or "/tmp/x (deleted)".
    pub exe: Option<String>,
    pub cwd: Option<String>,
    pub flags: u64,
    /// (fd number, socket inode) for every open socket.
    pub socket_fds: Vec<(u32, u64)>,
    /// Value of LD_PRELOAD in the process environment, if it can be read.
    pub ld_preload: Option<String>,
    /// Could the fd directory be read? (Needs root for other users' processes.)
    pub fds_readable: bool,
}

impl ProcInfo {
    pub fn is_kernel_thread(&self) -> bool {
        if self.flags & PF_KTHREAD != 0 {
            return true;
        }
        (self.pid == 2 || self.ppid == 2) && self.exe.is_none() && self.cmdline.is_empty()
    }

    pub fn cmdline_str(&self) -> String {
        if self.cmdline.is_empty() {
            format!("[{}]", self.comm)
        } else {
            self.cmdline.join(" ")
        }
    }

    pub fn exe_deleted(&self) -> bool {
        self.exe
            .as_deref()
            .map(|e| e.ends_with(" (deleted)"))
            .unwrap_or(false)
    }

    /// The path without " (deleted)".
    pub fn exe_path(&self) -> Option<&str> {
        self.exe
            .as_deref()
            .map(|e| e.strip_suffix(" (deleted)").unwrap_or(e))
    }

    pub fn exe_basename(&self) -> Option<&str> {
        self.exe_path().map(basename)
    }

    /// Names we compare against shell/interpreter lists: exe name, comm and argv[0].
    pub fn candidate_names(&self) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(b) = self.exe_basename() {
            v.push(b.to_string());
        }
        v.push(self.comm.clone());
        if let Some(a0) = self.cmdline.first() {
            v.push(basename(a0.trim_start_matches('-')).to_string());
        }
        v.sort();
        v.dedup();
        v
    }

    pub fn display_name(&self) -> String {
        self.exe_basename()
            .map(|s| s.to_string())
            .unwrap_or_else(|| self.comm.clone())
    }
}

pub fn basename(p: &str) -> &str {
    p.rsplit('/').next().unwrap_or(p)
}

/// All numeric directories in /proc (visible PIDs).
pub fn list_pids(sys: &SysRoot) -> Vec<u32> {
    let mut pids: Vec<u32> = sys
        .dir_names("/proc")
        .into_iter()
        .filter_map(|n| n.parse::<u32>().ok())
        .collect();
    pids.sort_unstable();
    pids
}

/// Parse /proc/<pid>/stat. The command name can contain spaces and
/// parentheses, so we look for the last ')'.
pub fn parse_stat(content: &str) -> Option<(String, char, u32, u64)> {
    let open = content.find('(')?;
    let close = content.rfind(')')?;
    if close <= open {
        return None;
    }
    let comm = content[open + 1..close].to_string();
    let rest: Vec<&str> = content[close + 1..].split_whitespace().collect();
    let state = rest.first()?.chars().next()?;
    let ppid = rest.get(1)?.parse().ok()?;
    let flags = rest.get(6).and_then(|f| f.parse().ok()).unwrap_or(0);
    Some((comm, state, ppid, flags))
}

/// A field from /proc/<pid>/status, e.g. "Uid" or "Tgid".
pub fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k == key).then_some(v.trim())
    })
}

/// Read a process. `None` if it has gone or cannot be read.
pub fn read_proc(sys: &SysRoot, pid: u32) -> Option<ProcInfo> {
    let base = format!("/proc/{pid}");
    let stat = sys.read_string(format!("{base}/stat")).ok();
    let status = sys.read_string(format!("{base}/status")).ok();
    if stat.is_none() && status.is_none() {
        return None;
    }

    let mut info = ProcInfo {
        pid,
        tgid: pid,
        state: '?',
        ..Default::default()
    };

    if let Some((comm, state, ppid, flags)) = stat.as_deref().and_then(parse_stat) {
        info.comm = comm;
        info.state = state;
        info.ppid = ppid;
        info.flags = flags;
    }
    if let Some(st) = status.as_deref() {
        if info.comm.is_empty() {
            info.comm = status_field(st, "Name").unwrap_or("").to_string();
        }
        if let Some(u) = status_field(st, "Uid").and_then(|v| v.split_whitespace().next()) {
            info.uid = u.parse().unwrap_or(0);
        }
        if let Some(t) = status_field(st, "Tgid") {
            info.tgid = t.parse().unwrap_or(pid);
        }
        if info.ppid == 0 {
            if let Some(p) = status_field(st, "PPid") {
                info.ppid = p.parse().unwrap_or(0);
            }
        }
    }
    if info.comm.is_empty() {
        info.comm = sys
            .read_string(format!("{base}/comm"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
    }

    if let Ok(raw) = sys.read_bytes(format!("{base}/cmdline")) {
        info.cmdline = raw
            .split(|b| *b == 0)
            .filter(|p| !p.is_empty())
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .collect();
    }
    info.exe = sys.read_link(format!("{base}/exe"));
    info.cwd = sys.read_link(format!("{base}/cwd"));

    let fd_dir = sys.path(format!("{base}/fd"));
    if let Ok(rd) = std::fs::read_dir(&fd_dir) {
        info.fds_readable = true;
        for entry in rd.filter_map(|e| e.ok()) {
            let fd: u32 = match entry.file_name().to_string_lossy().parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            if let Ok(target) = std::fs::read_link(entry.path()) {
                if let Some(inode) = parse_socket_link(&target.to_string_lossy()) {
                    info.socket_fds.push((fd, inode));
                }
            }
        }
        info.socket_fds.sort_unstable();
    }

    if let Ok(env) = sys.read_bytes(format!("{base}/environ")) {
        for var in env.split(|b| *b == 0) {
            let var = String::from_utf8_lossy(var);
            if let Some(v) = var.strip_prefix("LD_PRELOAD=") {
                if !v.trim().is_empty() {
                    info.ld_preload = Some(v.to_string());
                }
            }
        }
    }
    Some(info)
}

/// "socket:[12345]" → 12345
pub fn parse_socket_link(target: &str) -> Option<u64> {
    target
        .strip_prefix("socket:[")?
        .strip_suffix(']')?
        .parse()
        .ok()
}

/// The scanner's own executable on the live system – its own processes
/// (including the root copy started through sudo) are not reported.
pub fn own_exe(sys: &SysRoot) -> Option<String> {
    if !sys.is_live() {
        return None;
    }
    std::env::current_exe().ok().map(|p| p.display().to_string())
}

/// All visible processes (not threads).
pub fn snapshot(sys: &SysRoot) -> Vec<ProcInfo> {
    list_pids(sys)
        .into_iter()
        .filter_map(|pid| read_proc(sys, pid))
        .collect()
}

/// Account from /etc/passwd: (name, uid, gid, home, shell).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

pub fn read_accounts(sys: &SysRoot) -> Vec<Account> {
    let text = match sys.read_string("/etc/passwd") {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            if f.len() < 7 {
                return None;
            }
            Some(Account {
                name: f[0].to_string(),
                uid: f[2].parse().ok()?,
                gid: f[3].parse().ok()?,
                home: f[5].to_string(),
                shell: f[6].to_string(),
            })
        })
        .collect()
}

pub fn user_name(accounts: &[Account], uid: u32) -> String {
    accounts
        .iter()
        .find(|a| a.uid == uid)
        .map(|a| a.name.clone())
        .unwrap_or_else(|| uid.to_string())
}
