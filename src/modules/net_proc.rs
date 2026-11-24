//! net_proc: network connections mapped to processes, reverse/bind shells,
//! hidden processes and disguised process names.
//!
//! Reads /proc/net/{tcp,tcp6,udp,udp6} directly, converts hex to IP/port and
//! maps socket inodes to /proc/<pid>/fd/* for the exact PID, UID and command line.

use super::common::{clip, shq};
use super::{Collector, ScanCtx};
use crate::error::{Result, ScanError};
use crate::finding::{Finding, Severity};
use crate::procinfo::{basename, ProcInfo};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const MODULE: &str = "net_proc";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl Proto {
    pub const ALL: [Proto; 4] = [Proto::Tcp, Proto::Tcp6, Proto::Udp, Proto::Udp6];

    pub fn proc_file(&self) -> &'static str {
        match self {
            Proto::Tcp => "/proc/net/tcp",
            Proto::Tcp6 => "/proc/net/tcp6",
            Proto::Udp => "/proc/net/udp",
            Proto::Udp6 => "/proc/net/udp6",
        }
    }

    pub fn is_v6(&self) -> bool {
        matches!(self, Proto::Tcp6 | Proto::Udp6)
    }

    pub fn is_tcp(&self) -> bool {
        matches!(self, Proto::Tcp | Proto::Tcp6)
    }

    /// "tcp" or "udp" (for the whitelist, regardless of IP version).
    pub fn family(&self) -> &'static str {
        if self.is_tcp() {
            "tcp"
        } else {
            "udp"
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Tcp6 => "tcp6",
            Proto::Udp => "udp",
            Proto::Udp6 => "udp6",
        }
    }
}

/// TCP states according to include/net/tcp_states.h.
pub fn tcp_state_name(code: u8) -> &'static str {
    match code {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        0x0C => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

/// One line from /proc/net/*.
#[derive(Debug, Clone, PartialEq)]
pub struct SocketEntry {
    pub proto: Proto,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u8,
    pub uid: u32,
    pub inode: u64,
}

impl SocketEntry {
    /// TCP in LISTEN, or UDP that is not connected (state 07 and remote address 0).
    pub fn is_listening(&self) -> bool {
        if self.proto.is_tcp() {
            self.state == 0x0A
        } else {
            self.state == 0x07 && self.remote.port() == 0
        }
    }

    pub fn is_established(&self) -> bool {
        self.state == 0x01
    }

    pub fn state_name(&self) -> &'static str {
        if self.proto.is_tcp() {
            tcp_state_name(self.state)
        } else if self.is_listening() {
            "UNCONN"
        } else if self.state == 0x01 {
            "ESTABLISHED"
        } else {
            "UNCONN"
        }
    }
}

/// Convert "0100007F:0035" (IPv4) or 32 hex characters + port (IPv6).
///
/// The kernel prints the address as 32-bit words in the host's byte order, so each
/// word is converted with `to_ne_bytes`. The port is already a normal number.
pub fn parse_hex_addr(s: &str, v6: bool) -> Result<SocketAddr> {
    let (ip_hex, port_hex) = s
        .split_once(':')
        .ok_or_else(|| ScanError::parse("/proc/net", format!("saknar ':' i adress '{s}'")))?;
    let port = u16::from_str_radix(port_hex, 16)
        .map_err(|e| ScanError::parse("/proc/net", format!("ogiltig port '{port_hex}': {e}")))?;
    let word = |chunk: &str| {
        u32::from_str_radix(chunk, 16)
            .map_err(|e| ScanError::parse("/proc/net", format!("ogiltig adress '{chunk}': {e}")))
    };
    let ip = if v6 {
        if ip_hex.len() != 32 || !ip_hex.is_ascii() {
            return Err(ScanError::parse("/proc/net", format!("wrong length of IPv6 address '{ip_hex}'")));
        }
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            let w = word(&ip_hex[i * 8..i * 8 + 8])?;
            bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
        }
        IpAddr::V6(Ipv6Addr::from(bytes))
    } else {
        if ip_hex.len() != 8 {
            return Err(ScanError::parse("/proc/net", format!("wrong length of IPv4 address '{ip_hex}'")));
        }
        IpAddr::V4(Ipv4Addr::from(word(ip_hex)?.to_ne_bytes()))
    };
    Ok(SocketAddr::new(ip, port))
}

/// The opposite of [`parse_hex_addr`] – used to build test data.
pub fn encode_hex_addr(addr: &SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(v4) => format!("{:08X}:{:04X}", u32::from_ne_bytes(v4.octets()), addr.port()),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            let mut s = String::new();
            for i in 0..4 {
                let w = u32::from_ne_bytes([o[i * 4], o[i * 4 + 1], o[i * 4 + 2], o[i * 4 + 3]]);
                s.push_str(&format!("{w:08X}"));
            }
            format!("{s}:{:04X}", addr.port())
        }
    }
}

/// Parse the contents of a /proc/net file. Broken lines are skipped and counted.
pub fn parse_proc_net(content: &str, proto: Proto) -> (Vec<SocketEntry>, usize) {
    let mut out = Vec::new();
    let mut bad = 0;
    for line in content.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }
        match parse_line(line, proto) {
            Some(e) => out.push(e),
            None => bad += 1,
        }
    }
    (out, bad)
}

fn parse_line(line: &str, proto: Proto) -> Option<SocketEntry> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 10 {
        return None;
    }
    Some(SocketEntry {
        proto,
        local: parse_hex_addr(f[1], proto.is_v6()).ok()?,
        remote: parse_hex_addr(f[2], proto.is_v6()).ok()?,
        state: u8::from_str_radix(f[3], 16).ok()?,
        uid: f[7].parse().ok()?,
        inode: f[9].parse().ok()?,
    })
}

pub fn ip_is_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().map(|m| m.is_loopback()).unwrap_or(false),
    }
}

/// A connection mapped to its process (shown in the window and in JSON).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Connection {
    pub proto: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: String,
    pub remote_port: u16,
    pub state: String,
    pub listening: bool,
    pub uid: u32,
    pub inode: u64,
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub cmdline: Option<String>,
    pub exe: Option<String>,
}

/// Read all four /proc/net files.
pub fn read_sockets(ctx: &ScanCtx, col: &mut Collector) -> Vec<SocketEntry> {
    let mut all = Vec::new();
    for proto in Proto::ALL {
        match ctx.sys.read_string(proto.proc_file()) {
            Ok(text) => {
                let (entries, bad) = parse_proc_net(&text, proto);
                if bad > 0 {
                    col.note(format!("{}: {bad} lines could not be parsed", proto.proc_file()));
                }
                all.extend(entries);
            }
            Err(e) if e.is_not_found() => {
                col.note(format!("{} does not exist (IPv6 disabled?)", proto.proc_file()))
            }
            Err(e) => col.note(e.to_string()),
        }
    }
    all
}

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    let sockets = read_sockets(ctx, col);
    let procs = ctx.processes;
    let by_pid: HashMap<u32, &ProcInfo> = procs.iter().map(|p| (p.pid, p)).collect();

    // inode → processes that have it open
    let mut owners: HashMap<u64, Vec<u32>> = HashMap::new();
    for p in procs {
        for (_, inode) in &p.socket_fds {
            owners.entry(*inode).or_default().push(p.pid);
        }
    }
    let unreadable_fds = procs.iter().filter(|p| !p.fds_readable).count();
    if unreadable_fds > 0 && !ctx.privileged {
        col.note(format!(
            "{unreadable_fds} processes' fd directories could not be read – run as root to map all sockets to processes"
        ));
    }

    let mut reported: HashSet<(String, u32)> = HashSet::new();
    let mut connections = Vec::new();

    for s in &sockets {
        let pids = owners.get(&s.inode).cloned().unwrap_or_default();
        let first = pids.first().and_then(|p| by_pid.get(p)).copied();
        connections.push(Connection {
            proto: s.proto.name().into(),
            local_addr: s.local.ip().to_string(),
            local_port: s.local.port(),
            remote_addr: s.remote.ip().to_string(),
            remote_port: s.remote.port(),
            state: s.state_name().into(),
            listening: s.is_listening(),
            uid: s.uid,
            inode: s.inode,
            pid: first.map(|p| p.pid),
            process: first.map(|p| p.display_name()),
            cmdline: first.map(|p| p.cmdline_str()),
            exe: first.and_then(|p| p.exe.clone()),
        });

        if pids.is_empty() {
            check_orphan(ctx, s, col);
            continue;
        }
        // Socket activation: both systemd (PID 1) and the service hold the socket – report the service.
        let mut pids = pids;
        pids.sort_by_key(|p| *p == 1);
        for pid in pids {
            if let Some(p) = by_pid.get(&pid) {
                check_socket_owner(ctx, s, p, col, &mut reported);
            }
        }
    }
    col.inventory.connections = connections;

    check_ss_consistency(ctx, &sockets, col);
    check_hidden_processes(ctx, col);
    check_masquerade(ctx, col);
}

fn sock_desc(s: &SocketEntry) -> String {
    if s.is_listening() {
        format!("{} listening on {}", s.proto.name(), s.local)
    } else {
        format!("{} {} → {} ({})", s.proto.name(), s.local, s.remote, s.state_name())
    }
}

fn proc_evidence(p: &ProcInfo, s: &SocketEntry) -> String {
    format!(
        "PID {} (UID {}) exe={} cmdline=\"{}\"\nsocket: {} inode {}",
        p.pid,
        p.uid,
        p.exe.as_deref().unwrap_or("?"),
        clip(&p.cmdline_str(), 300),
        sock_desc(s),
        s.inode
    )
}

fn proc_verify(p: &ProcInfo) -> Vec<String> {
    vec![
        format!("ls -l /proc/{}/exe /proc/{}/cwd", p.pid, p.pid),
        format!("tr '\\0' ' ' < /proc/{}/cmdline; echo", p.pid),
        format!("ss -tunap | grep 'pid={},'", p.pid),
        format!("ls -l /proc/{}/fd", p.pid),
        format!("pstree -asp {}", p.pid),
    ]
}

fn check_socket_owner(
    ctx: &ScanCtx,
    s: &SocketEntry,
    p: &ProcInfo,
    col: &mut Collector,
    reported: &mut HashSet<(String, u32)>,
) {
    let cfg = ctx.cfg;
    let names = p.candidate_names();
    let is_shell = names.iter().any(|n| cfg.is_shell(n));
    let is_interp = names.iter().any(|n| cfg.is_interpreter(n));
    let on_stdio = p.socket_fds.iter().any(|(fd, ino)| *fd <= 2 && *ino == s.inode);
    let remote_loop = ip_is_loopback(&s.remote.ip());
    // A listening socket is reported once, even if several processes share it.
    let first_owner_of_listener = s.is_listening() && reported.insert((format!("LISTEN:{}", s.inode), 0));
    let mut once = |rule: &str, f: Finding, col: &mut Collector| {
        if reported.insert((rule.to_string(), p.pid)) {
            col.push(f);
        }
    };

    if s.is_established() {
        if is_shell || (is_interp && on_stdio) {
            let sev = if remote_loop && !on_stdio { Severity::High } else { Severity::Critical };
            once(
                "NET-REVSHELL",
                Finding::new(sev, MODULE, "NET-REVSHELL", format!("Possible reverse shell: {} has an open network connection", p.display_name()))
                    .evidence(format!(
                        "{}{}",
                        proc_evidence(p, s),
                        if on_stdio { "\nstandard input/output (fd 0-2) is connected directly to the socket" } else { "" }
                    ))
                    .description("A shell or network tool (bash, sh, nc, socat …) with an established connection is the classic sign of a reverse shell. If fd 0–2 point to a socket, the shell is controlled over the network.")
                    .verify_all(proc_verify(p)),
                col,
            );
        } else if is_interp && !remote_loop {
            let sev = if p.uid == 0 { Severity::Medium } else { Severity::Low };
            once(
                "NET-INTERP-CONN",
                Finding::new(sev, MODULE, "NET-INTERP-CONN", format!("Script interpreter with an outgoing connection: {}", p.display_name()))
                    .evidence(proc_evidence(p, s))
                    .description("A script interpreter (python, perl, ruby …) is talking to a remote computer. Often legitimate (updates, services), but check the script and the receiver.")
                    .verify_all(proc_verify(p)),
                col,
            );
        }
        if cfg.suspicious_remote_ports.contains(&s.remote.port()) {
            once(
                "NET-SUSP-PORT",
                Finding::new(Severity::High, MODULE, "NET-SUSP-PORT", format!("Connection to a typical backdoor port {}", s.remote.port()))
                    .evidence(proc_evidence(p, s))
                    .description("The port is often used by reverse shells, IRC botnets or backdoors (4444, 1337, 31337 …).")
                    .verify_all(proc_verify(p)),
                col,
            );
        }
    }

    if s.is_listening() {
        if is_shell || is_interp {
            let sev = if is_shell { Severity::Critical } else if p.uid == 0 { Severity::High } else { Severity::Medium };
            once(
                "NET-BINDSHELL",
                Finding::new(sev, MODULE, "NET-BINDSHELL", format!("Possible bind shell: {} listens on port {}", p.display_name(), s.local.port()))
                    .evidence(proc_evidence(p, s))
                    .description("A shell, nc/socat or a script interpreter that listens on a port can receive commands from outside (bind shell).")
                    .verify_all(proc_verify(p)),
                col,
            );
        } else if first_owner_of_listener
            && !cfg.is_listen_allowed(s.proto.family(), s.local.port())
            && !cfg.is_listen_process_allowed(&p.display_name(), p.exe_path())
            && (cfg.report_loopback_listeners || !ip_is_loopback(&s.local.ip()))
        {
            let user_app = p.uid != 0 && p.exe_path().map(|e| ["/usr/", "/opt/", "/app/", "/snap/"].iter().any(|d| e.starts_with(d))).unwrap_or(false);
            col.push(
                Finding::new(if user_app { Severity::Low } else { Severity::Medium }, MODULE, "NET-LISTEN-UNKNOWN", format!("Unknown listening port {}/{} ({})", s.proto.family(), s.local.port(), p.display_name()))
                    .evidence(proc_evidence(p, s))
                    .description("The port is not in the whitelist. Check that the service is intended and otherwise add it to allowed_listen_ports.")
                    .verify(format!("ss -tulpn | grep ':{} '", s.local.port()))
                    .verify(format!("dpkg -S {}", shq(p.exe_path().unwrap_or("?"))))
                    .verify(format!("systemctl status {}", p.pid)),
            );
        }
    }

    // Processes that hold sockets and run from odd places
    if let Some(exe) = p.exe_path() {
        if cfg.is_temp_path(exe) {
            once(
                "NET-TMP-SOCKET",
                Finding::new(Severity::Critical, MODULE, "NET-TMP-SOCKET", format!("Process from a temporary directory holds a network socket: {exe}"))
                    .evidence(proc_evidence(p, s))
                    .description("Binaries in /tmp, /var/tmp, /dev/shm or /run do not belong in a service. It is a common pattern for downloaded malware.")
                    .verify_all(proc_verify(p))
                    .verify(format!("sha256sum /proc/{}/exe", p.pid)),
                col,
            );
        }
    }
    if p.exe_deleted() {
        let exe = p.exe_path().unwrap_or("?");
        let pkg_dir = ["/usr/", "/opt/", "/lib/"].iter().any(|d| exe.starts_with(d));
        let sev = if pkg_dir && !exe.starts_with("/memfd:") { Severity::Medium } else { Severity::Critical };
        once(
            "NET-DELETED-SOCKET",
            Finding::new(sev, MODULE, "NET-DELETED-SOCKET", format!("Process with a deleted binary holds a network socket: {}", p.display_name()))
                .evidence(proc_evidence(p, s))
                .description(if pkg_dir {
                    "The binary is gone from disk while the process runs. After a package upgrade that is normal (restart the service); otherwise it may be malware that removed itself."
                } else {
                    "The binary is gone from disk while the process runs and holds a network socket – typical of malware that removes itself after starting."
                })
                .verify_all(proc_verify(p))
                .verify(format!("cp /proc/{}/exe /root/pid{}-exe.bin   # keep a copy for analysis", p.pid, p.pid)),
            col,
        );
    }
}

fn check_orphan(ctx: &ScanCtx, s: &SocketEntry, col: &mut Collector) {
    if !s.is_listening() || s.inode == 0 || !ctx.privileged {
        return;
    }
    if ctx.cfg.is_listen_allowed(s.proto.family(), s.local.port()) {
        return;
    }
    // Kernel NFS services (NFSv4.0 callback, lockd) listen without any process. If their
    // kernel threads and an NFS mount exist, that is the likely explanation.
    let nfs_thread = ctx
        .processes
        .iter()
        .find(|p| p.is_kernel_thread() && (p.comm.starts_with("NFSv4 callback") || p.comm == "lockd"))
        .map(|p| p.comm.clone());
    let nfs_mount = ctx
        .sys
        .read_string("/proc/mounts")
        .ok()
        .and_then(|m| m.lines().find(|l| l.split_whitespace().nth(2).map(|t| t.starts_with("nfs")).unwrap_or(false)).map(|l| l.split_whitespace().take(3).collect::<Vec<_>>().join(" ")));
    let (sev, desc) = match (&nfs_thread, &nfs_mount, s.uid) {
        (Some(t), Some(_), 0) => (
            Severity::Low,
            format!("No process has the socket open, but the kernel thread [{t}] and an NFS mount exist. It is almost certainly the kernel NFS service (NFSv4.0 listens on a random port for callbacks from the server). Fixed port: options nfs callback_tcpport=… in /etc/modprobe.d."),
        ),
        _ => (
            if s.proto.is_tcp() { Severity::High } else { Severity::Low },
            "No visible process has the socket open. Kernel services (NFS, WireGuard, VXLAN) can cause this, but it can also be a process hidden by a rootkit.".to_string(),
        ),
    };
    col.push(
        Finding::new(sev, MODULE, "NET-ORPHAN-LISTEN", format!("Listening socket without a visible owner process: {}/{}", s.proto.family(), s.local.port()))
            .evidence(format!(
                "{} uid {} inode {}{}",
                sock_desc(s),
                s.uid,
                s.inode,
                match (&nfs_thread, &nfs_mount) {
                    (Some(t), Some(m)) => format!("\nkernel thread [{t}], mount: {m}"),
                    _ => String::new(),
                }
            ))
            .description(desc)
            .verify("cat /sys/module/nfs/parameters/callback_tcpport; grep nfs /proc/mounts; rpcinfo -p")
            .verify(format!("ss -tulpne | grep ':{} '", s.local.port()))
            .verify(format!("find /proc/[0-9]*/fd -lname 'socket:\\[{}\\]' 2>/dev/null", s.inode)),
    );
}

/// Parse `ss -H -l -n -t -u` into (protocol, port).
pub fn parse_ss_listeners(out: &str) -> BTreeSet<(String, u16)> {
    let mut set = BTreeSet::new();
    for line in out.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        let proto = if f[0].starts_with("tcp") {
            "tcp"
        } else if f[0].starts_with("udp") {
            "udp"
        } else {
            continue;
        };
        if let Some(port) = f[4].rsplit(':').next().and_then(|p| p.parse::<u16>().ok()) {
            set.insert((proto.to_string(), port));
        }
    }
    set
}

fn check_ss_consistency(ctx: &ScanCtx, sockets: &[SocketEntry], col: &mut Collector) {
    if !ctx.sys.is_live() {
        return;
    }
    let ss = match crate::external_tools::find_binary("ss") {
        Some(p) => p,
        None => {
            col.note("ss is missing – the comparison between ss and /proc/net was skipped");
            return;
        }
    };
    let out = match crate::external_tools::run_capture(&ss, &["-H", "-l", "-n", "-t", "-u"], 20) {
        Ok(o) => o,
        Err(e) => {
            col.note(format!("ss could not run: {e}"));
            return;
        }
    };
    let ss_set = parse_ss_listeners(&out.stdout);
    let proc_set: BTreeSet<(String, u16)> = sockets
        .iter()
        .filter(|s| s.is_listening())
        .map(|s| (s.proto.family().to_string(), s.local.port()))
        .collect();
    for (proto, port) in ss_set.difference(&proc_set) {
        col.push(
            Finding::new(Severity::High, MODULE, "NET-SS-MISMATCH", format!("Port {proto}/{port} is visible in ss but not in /proc/net"))
                .evidence(format!("ss (netlink) shows a listening {proto} socket on port {port} that is missing from /proc/net/{proto}*"))
                .description("ss reads through netlink while /proc/net is read as a file. A rootkit that filters /proc can hide ports that are still visible through netlink. Short-lived sockets can give occasional false alarms – run again.")
                .verify(format!("ss -tulpne | grep ':{port} '"))
                .verify(format!("grep -i ':{port:04X} ' /proc/net/{proto} /proc/net/{proto}6")),
        );
    }
}

/// PIDs from /proc/sched_debug or /sys/kernel/debug/sched/debug.
///
/// The lines under "runnable tasks:" look like
/// ` S   task-name   PID   tree-key  switches ...` where tree-key is a decimal number.
pub fn parse_sched_debug(content: &str) -> BTreeSet<u32> {
    let mut pids = BTreeSet::new();
    let mut in_tasks = false;
    for line in content.lines() {
        if line.starts_with("cpu#") {
            in_tasks = false;
            continue;
        }
        if line.contains("runnable tasks:") {
            in_tasks = true;
            continue;
        }
        if !in_tasks
            || line.trim().is_empty()
            || line.trim_start().starts_with('-')
            || line.contains("tree-key")
        {
            continue;
        }
        let t: Vec<&str> = line.split_whitespace().collect();
        for i in 1..t.len().saturating_sub(1) {
            if let Ok(pid) = t[i].parse::<u32>() {
                if t[i + 1].contains('.') && t[i + 1].parse::<f64>().is_ok() {
                    pids.insert(pid);
                    break;
                }
            }
        }
    }
    pids
}

fn is_thread_of_other(ctx: &ScanCtx, pid: u32) -> Option<bool> {
    let st = ctx.sys.read_string(format!("/proc/{pid}/status")).ok()?;
    let tgid: u32 = crate::procinfo::status_field(&st, "Tgid")?.parse().ok()?;
    Some(tgid != pid)
}

fn check_hidden_processes(ctx: &ScanCtx, col: &mut Collector) {
    let visible: HashSet<u32> = crate::procinfo::list_pids(ctx.sys).into_iter().collect();
    let sched_sources = ["/proc/sched_debug", "/sys/kernel/debug/sched/debug"];
    let mut sched_pids: Option<BTreeSet<u32>> = None;
    let mut used = "";
    for src in sched_sources {
        if let Ok(text) = ctx.sys.read_string(src) {
            let p = parse_sched_debug(&text);
            if !p.is_empty() {
                sched_pids = Some(p);
                used = src;
                break;
            }
        }
    }

    let mut hidden: BTreeSet<u32> = BTreeSet::new();
    match &sched_pids {
        Some(sp) => {
            for pid in sp {
                if *pid == 0 || visible.contains(pid) {
                    continue;
                }
                match is_thread_of_other(ctx, *pid) {
                    Some(true) => continue, // thread – not in the listing but normal
                    _ => {
                        hidden.insert(*pid);
                    }
                }
            }
            // On a live system: confirm once more so short-lived processes do not raise an alarm.
            if ctx.sys.is_live() && !hidden.is_empty() {
                let again: HashSet<u32> = crate::procinfo::list_pids(ctx.sys).into_iter().collect();
                let sched_again = ctx.sys.read_string(used).map(|t| parse_sched_debug(&t)).unwrap_or_default();
                hidden.retain(|p| !again.contains(p) && sched_again.contains(p));
            }
        }
        None => col.note("/proc/sched_debug and /sys/kernel/debug/sched/debug could not be read (needs root and debugfs) – the scheduler comparison was skipped"),
    }

    if ctx.deep_pid_scan {
        let max: u32 = ctx
            .sys
            .read_string("/proc/sys/kernel/pid_max")
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(4_194_304)
            .min(4_194_304);
        for pid in 1..=max {
            if visible.contains(&pid) || hidden.contains(&pid) {
                continue;
            }
            if ctx.sys.exists(format!("/proc/{pid}/status")) && is_thread_of_other(ctx, pid) == Some(false) {
                let again = crate::procinfo::list_pids(ctx.sys);
                if !again.contains(&pid) {
                    hidden.insert(pid);
                }
            }
        }
    }

    for pid in hidden {
        let info = crate::procinfo::read_proc(ctx.sys, pid);
        let evidence = match &info {
            Some(p) => format!("PID {pid} can be read directly (/proc/{pid}/status) but is missing from the /proc directory\nexe={} cmdline=\"{}\"", p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 300)),
            None => format!("PID {pid} is in the scheduler ({used}) but not in /proc"),
        };
        col.push(
            Finding::new(Severity::High, MODULE, "NET-HIDDEN-PID", format!("Dold process: PID {pid}"))
                .evidence(evidence)
                .description("The process is visible to the kernel scheduler but not in the /proc listing. That is a typical sign of a rootkit filtering readdir() on /proc.")
                .verify(format!("cat /proc/{pid}/status"))
                .verify(format!("ls -l /proc/{pid}/exe"))
                .verify("ps -eLf | wc -l; ls -d /proc/[0-9]* | wc -l")
                .verify("unhide proc   # if the unhide package is installed"),
        );
    }
}

fn names_match(a0: &str, exe_b: &str) -> bool {
    if a0.is_empty() || exe_b.is_empty() {
        return true;
    }
    a0 == exe_b || exe_b.starts_with(a0) || a0.starts_with(exe_b) || exe_b.ends_with(&format!("-{a0}"))
}

/// Resolves argv[0] to a real file (through PATH directories and symlinks).
fn resolve_argv0(ctx: &ScanCtx, argv0: &str) -> Option<String> {
    let candidates: Vec<String> = if argv0.starts_with('/') {
        vec![argv0.to_string()]
    } else {
        ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]
            .iter()
            .map(|d| format!("{d}/{argv0}"))
            .collect()
    };
    for c in candidates {
        if let Ok(real) = std::fs::canonicalize(ctx.sys.path(&c)) {
            return Some(ctx.sys.display(&real));
        }
    }
    None
}

fn check_masquerade(ctx: &ScanCtx, col: &mut Collector) {
    let cfg = ctx.cfg;
    let own = crate::procinfo::own_exe(ctx.sys);
    for p in ctx.processes {
        if p.state == 'Z' || (own.is_some() && p.exe_path() == own.as_deref()) {
            continue;
        }
        let kthread_like = |n: &str| cfg.kernel_thread_prefixes.iter().any(|k| n.starts_with(k.as_str()));
        if p.is_kernel_thread() {
            if !kthread_like(&p.comm) {
                col.push(
                    Finding::new(Severity::Low, MODULE, "NET-KTHREAD-NAME", format!("Unusual kernel thread name: [{}]", p.comm))
                        .evidence(format!("PID {} PPID {} namn [{}]", p.pid, p.ppid, p.comm))
                        .description("The kernel thread has a name that is not among the known prefixes. Often a driver missing from the list, but rootkit modules can start their own threads.")
                        .verify(format!("cat /proc/{}/stack", p.pid))
                        .verify("lsmod; dmesg | tail -50"),
                );
            }
            continue;
        }

        let argv0 = p.cmdline.first().map(|s| s.as_str()).unwrap_or("");
        let looks_bracketed = argv0.starts_with('[') && argv0.trim_end().ends_with(']');
        let disguise = |n: &str| KTHREAD_DISGUISES.iter().any(|k| n.starts_with(k));
        let fake_kthread_name = p.exe.is_some() && (disguise(&p.comm) || disguise(basename(argv0)));
        if looks_bracketed || fake_kthread_name {
            col.push(
                Finding::new(Severity::Critical, MODULE, "NET-KTHREAD-FAKE", format!("User process disguised as a kernel thread: {}", if looks_bracketed { argv0.to_string() } else { p.comm.clone() }))
                    .evidence(format!("PID {} UID {} exe={} cmdline=\"{}\" comm={}", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 200), p.comm))
                    .description("Real kernel threads have no executable and no command line. A normal process calling itself [kworker/…] or similar is trying to hide in the ps list.")
                    .verify_all(proc_verify_basic(p.pid)),
            );
            continue;
        }

        let (Some(exe_b), false) = (p.exe_basename(), argv0.is_empty()) else { continue };
        if p.exe_deleted() {
            continue;
        }
        let a0_clean = argv0.trim_start_matches('-');
        // The whole argv[0] is the exe path (even with spaces in directory names) – nothing disguised.
        if Some(a0_clean) == p.exe_path() || basename(a0_clean) == exe_b {
            continue;
        }
        let a0_name = basename(a0_clean.split([':', ' ']).next().unwrap_or(a0_clean));
        let allowed = |n: &str| cfg.allowed_argv0_mismatch.iter().any(|a| a == n);
        if allowed(exe_b) || allowed(a0_name) || allowed(&p.comm) || names_match(a0_name, exe_b) {
            continue;
        }
        // Versioned installs: ~/.local/share/<name>/versions/1.2.3
        if p.exe_path().map(|e| e.contains(&format!("/{a0_name}/")) || e.contains(&format!("/{a0_name}-"))).unwrap_or(false) {
            continue;
        }
        // Interpreters run scripts: argv[0] can be the script name
        if cfg.is_interpreter(exe_b) || cfg.is_shell(exe_b) {
            continue;
        }
        if let Some(resolved) = resolve_argv0(ctx, a0_clean.split(' ').next().unwrap_or(a0_clean)) {
            if Some(resolved.as_str()) == p.exe_path() || resolved.ends_with(&format!("/{exe_b}")) {
                continue;
            }
        }
        let sev = if p.uid == 0 || !p.socket_fds.is_empty() { Severity::High } else { Severity::Medium };
        col.push(
            Finding::new(sev, MODULE, "NET-ARGV0-MASK", format!("Disguised process name: \"{a0_name}\" actually runs {exe_b}"))
                .evidence(format!("PID {} UID {} argv[0]=\"{}\" exe={}", p.pid, p.uid, clip(argv0, 120), p.exe.as_deref().unwrap_or("?")))
                .description("The name in the command line does not match the binary in /proc/<pid>/exe. Many services change their title on purpose (add them to allowed_argv0_mismatch), but malware does it to look like system processes.")
                .verify_all(proc_verify_basic(p.pid)),
        );
    }
}

/// Names that only real kernel threads have – a normal process with these names is trying to hide.
const KTHREAD_DISGUISES: [&str; 18] = [
    "kworker/", "ksoftirqd/", "migration/", "kthreadd", "rcu_sched", "rcu_preempt", "rcu_gp", "kswapd",
    "watchdog/", "cpuhp/", "khugepaged", "kdevtmpfs", "jbd2/", "irq/", "kauditd", "kcompactd", "kblockd", "kintegrityd",
];

fn proc_verify_basic(pid: u32) -> Vec<String> {
    vec![
        format!("ls -l /proc/{pid}/exe"),
        format!("tr '\\0' ' ' < /proc/{pid}/cmdline; echo"),
        format!("cat /proc/{pid}/status | head -12"),
        format!("dpkg -S \"$(readlink -f /proc/{pid}/exe)\""),
    ]
}
