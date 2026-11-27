//! A gaming desktop: Steam's runtime containers, helpers and ports, NVIDIA's kernel thread and
//! the SSH settings file that keeps its package's date. Made-up files in a temporary directory;
//! nothing on the real system is read or changed.

use scanner::config::Config;
use scanner::finding::Finding;
use scanner::report::Report;
use scanner::{run_scan, ModuleId, ScanOptions, Severity, SysRoot};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn write(root: &Path, abs: &str, content: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(p, content).expect("write");
}

fn link(root: &Path, abs: &str, target: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    symlink(target, p).expect("link");
}

/// A process of user 1000 in the namespaces (user, net, mnt).
fn process(root: &Path, pid: u32, ppid: u32, exe: &str, cmdline: &str, spaces: (u32, u32, u32)) {
    let name = exe.rsplit('/').next().unwrap_or("p");
    let uid = if pid == 1 { 0 } else { 1000 };
    write(root, &format!("/proc/{pid}/stat"), &format!("{pid} ({name}) S {ppid} 1 1 0 -1 4194560 0 0\n"));
    write(root, &format!("/proc/{pid}/status"), &format!("Name:\t{name}\nPPid:\t{ppid}\nUid:\t{uid} {uid} {uid} {uid}\n"));
    write(root, &format!("/proc/{pid}/cmdline"), &cmdline.replace(' ', "\0"));
    link(root, &format!("/proc/{pid}/exe"), exe);
    for (kind, id) in [("user", spaces.0), ("net", spaces.1), ("mnt", spaces.2)] {
        link(root, &format!("/proc/{pid}/ns/{kind}"), &format!("{kind}:[{id}]"));
    }
}

fn scan(root: &Path, modules: &[ModuleId]) -> Report {
    let opts = ScanOptions { modules: modules.to_vec(), ..ScanOptions::default() };
    run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {})
}

fn of<'a>(report: &'a Report, rule: &str) -> Vec<&'a Finding> {
    report.findings.iter().filter(|f| f.rule == rule).collect()
}

const STEAM: &str = "/home/anna/.steam/debian-installation";

#[test]
fn steam_and_its_runtime_are_not_alarms() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let host = (1, 2, 3);
    let runtime = (11, 2, 12);
    let sandbox = (682, 26, 12);
    process(root, 1, 0, "/usr/lib/systemd/systemd", "init", host);
    process(root, 3998, 1, &format!("{STEAM}/steamapps/common/SteamLinuxRuntime_sniper/pressure-vessel/libexec/steam-runtime-tools-0/srt-bwrap"), "srt-bwrap --args 11", host);
    process(root, 4068, 3998, "/usr/lib/pressure-vessel/from-host/libexec/steam-runtime-tools-0/pv-adverb", "pv-adverb --generate-locales", runtime);
    process(root, 4109, 4068, &format!("{STEAM}/steamrt64/steam"), &format!("{STEAM}/steamrt64/steam -nominidumps"), runtime);
    let helper = format!("{STEAM}/steamrt64/steamwebhelper");
    process(root, 4134, 4109, &helper, "./steamwebhelper -nocrashdialog", runtime);
    process(root, 4142, 4134, &helper, &format!("{helper} --type=zygote"), sandbox);
    process(root, 4196, 4134, &helper, "/proc/self/exe --type=utility", runtime);
    link(root, "/proc/4196/fd/5", "socket:[900]");
    // Steam listens for Remote Play and talks to a game server
    link(root, "/proc/4109/fd/7", "socket:[801]");
    link(root, "/proc/4109/fd/8", "socket:[802]");
    let line = |n: u32, local: &str, remote: &str, state: &str, inode: u32| format!("   {n}: {local} {remote} {state} 00000000:00000000 00:00000000 00000000  1000        0 {inode} 1 0 100 0 0 10 0\n");
    // 0.0.0.0:27036 listening, and 192.168.1.20:55467 → 198.51.100.68:27021
    let tcp = format!("header\n{}{}", line(0, "00000000:699C", "00000000:0000", "0A", 801), line(1, "1401A8C0:D8AB", "446433C6:698D", "01", 802));
    write(root, "/proc/net/tcp", &tcp);
    let report = scan(root, &[ModuleId::NetProc, ModuleId::ProcAudit]);
    assert!(of(&report, "NET-ARGV0-MASK").is_empty(), "{:?}", of(&report, "NET-ARGV0-MASK"));
    assert!(of(&report, "PROC-NAMESPACE").is_empty(), "{:?}", of(&report, "PROC-NAMESPACE"));
    for rule in ["NET-LISTEN-UNKNOWN", "NET-OUTBOUND-UNUSUAL"] {
        let found = of(&report, rule);
        assert_eq!(found.iter().map(|f| f.severity).collect::<Vec<_>>(), vec![Severity::Info], "{rule}: {found:?}");
    }
}

#[test]
fn look_alikes_are_still_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    process(root, 1, 0, "/usr/lib/systemd/systemd", "init", (1, 2, 3));
    // named like Steam's parts, but not in Steam's folders
    process(root, 50, 1, "/home/anna/.cache/x/pv-adverb", "pv-adverb", (50, 51, 52));
    // a disguise is still a disguise
    process(root, 60, 1, "/home/anna/.cache/x/miner", "/usr/sbin/sshd", (1, 2, 3));
    // a program elsewhere on Steam's port
    link(root, "/proc/60/fd/7", "socket:[700]");
    write(root, "/proc/net/tcp", "header\n   0: 00000000:699C 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 700 1 0 100 0 0 10 0\n");
    let report = scan(root, &[ModuleId::NetProc, ModuleId::ProcAudit]);
    assert_eq!(of(&report, "PROC-NAMESPACE").len(), 1);
    assert_eq!(of(&report, "NET-ARGV0-MASK").len(), 0, "sshd is allowed to retitle itself");
    assert!(of(&report, "NET-LISTEN-UNKNOWN").iter().all(|f| f.severity == Severity::Medium));
}

#[test]
fn nvidias_thread_is_known_with_its_driver() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/6535/stat", "6535 (vidmem lazy free) S 2 0 0 0 -1 2129984 0 0\n");
    write(root, "/proc/6535/status", "Name:\tvidmem lazy free\nPPid:\t2\nUid:\t0 0 0 0\n");
    assert_eq!(of(&scan(root, &[ModuleId::NetProc]), "NET-KTHREAD-NAME").len(), 1);
    write(root, "/proc/modules", "nvidia 123 0 - Live 0x0 (POE)\n");
    assert!(of(&scan(root, &[ModuleId::NetProc]), "NET-KTHREAD-NAME").is_empty());
}

#[test]
fn a_settings_file_that_keeps_its_packages_date_is_no_timestomping() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/var/lib/dpkg/info/x.list", "/usr\n");
    let content = "PermitRootLogin prohibit-password\n";
    write(root, "/etc/ssh/sshd_config", content);
    // dated long before it was put here, in whole seconds
    let old = UNIX_EPOCH + Duration::from_secs(SystemTime::now().duration_since(UNIX_EPOCH).expect("time").as_secs() - 200 * 86_400);
    let date = |abs: &str| fs::File::options().write(true).open(root.join(abs.trim_start_matches('/'))).and_then(|f| f.set_modified(old)).expect("date");
    date("/etc/ssh/sshd_config");
    let flagged = || of(&scan(root, &[ModuleId::FsPerms]), "FS-TIMESTAMP").iter().any(|f| f.evidence.contains("sshd_config"));
    assert!(flagged());
    // ucf recorded exactly this content
    use md5::{Digest, Md5};
    let sum: String = Md5::digest(content.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    write(root, "/var/lib/ucf/hashfile", &format!("{sum}  /etc/ssh/sshd_config\n"));
    assert!(!flagged());
    // changed and set back to the old date: reported again
    write(root, "/etc/ssh/sshd_config", "PermitRootLogin yes\n");
    date("/etc/ssh/sshd_config");
    assert!(flagged());
}
