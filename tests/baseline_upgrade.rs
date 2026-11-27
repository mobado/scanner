//! A baseline made by an older version, compared by a newer one that watches more kinds of
//! files (the case of a real root report: 4 high and 19 medium false alarms). Made-up files in
//! a temporary directory; nothing on the real system is read or changed.

use scanner::autobaseline::auto_save_to;
use scanner::baseline::{self, newly_tracked, Baseline};
use scanner::config::Config;
use scanner::finding::Finding;
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

fn md5(text: &str) -> String {
    use md5::{Digest, Md5};
    Md5::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn of<'a>(report: &'a Report, rule: &str) -> Vec<&'a Finding> {
    report.findings.iter().filter(|f| f.rule == rule).collect()
}

/// Every kind of file that version 0.12.0 started to record.
const NEW_KINDS: [&str; 16] = [
    "/home/anna/.mozilla/firefox/x.default/pkcs11.txt",
    "/home/anna/.pki/nssdb/pkcs11.txt",
    "/home/anna/.thunderbird/y.default/pkcs11.txt",
    "/usr/share/p11-kit/modules/trust.module",
    "/etc/pkcs11/modules/own.module",
    "/home/anna/.config/pkcs11/modules/mine.module",
    "/home/anna/.gnupg/gpg.conf",
    "/home/anna/.local/share/applications/x.desktop",
    "/home/anna/.config/pipewire/pipewire.conf",
    "/home/anna/.config/containers/systemd/web.container",
    "/var/lib/systemd/linger/anna",
    "/var/lib/dpkg/diversions",
    "/usr/share/keyrings/other.asc",
    "/etc/kernel/postinst.d/own",
    "/boot/efi/EFI/Linux/debian.efi",
    "/home/anna/.local/share/kwin/effects/e/metadata.json",
];

#[test]
fn every_new_kind_of_file_counts_as_newly_tracked() {
    for path in NEW_KINDS {
        assert!(newly_tracked(path), "{path}");
    }
}

#[test]
fn an_older_baseline_gives_one_quiet_line_instead_of_alarms() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/usr/share/wayland-sessions/plasma.desktop", "");
    let modules = vec![ModuleId::Persistence, ModuleId::DesktopSession, ModuleId::FsPerms];
    let opts = ScanOptions { modules: modules.clone(), ..ScanOptions::default() };
    let sys = SysRoot::new(root);
    let before = run_scan(&sys, &Config::default(), &opts, &|_| {});

    // files that already exist when the old baseline is made, but that it does not record
    for path in NEW_KINDS {
        write(root, path, "# nothing\n");
    }
    // packaged: a hook, a keyring and the link a package ships beside it, an edited conffile
    let hook = "#!/bin/sh\ntrue\n";
    write(root, "/etc/kernel/postinst.d/packaged", hook);
    write(root, "/usr/share/keyrings/debian.pgp", "key");
    symlink("debian.pgp", root.join("usr/share/keyrings/debian.gpg")).expect("link");
    // a packaged link turned towards a file of no package
    symlink("other.asc", root.join("usr/share/keyrings/turned.gpg")).expect("link");
    write(root, "/etc/kernel/postinst.d/edited", "#!/bin/sh\nchanged\n");
    write(root, "/var/lib/dpkg/info/keys.list", "/usr/share/keyrings/debian.pgp\n/usr/share/keyrings/debian.gpg\n/usr/share/keyrings/turned.gpg\n");
    write(root, "/var/lib/dpkg/info/keys.md5sums", &format!("{}  usr/share/keyrings/debian.pgp\n", md5("key")));
    write(root, "/var/lib/dpkg/info/hooks.list", "/etc/kernel/postinst.d/packaged\n/etc/kernel/postinst.d/edited\n");
    write(root, "/var/lib/dpkg/info/hooks.md5sums", &format!("{}  etc/kernel/postinst.d/packaged\n{}  etc/kernel/postinst.d/edited\n", md5(hook), md5("#!/bin/sh\nshipped\n")));
    fs::set_permissions(root.join("etc/kernel/postinst.d/packaged"), fs::Permissions::from_mode(0o755)).expect("chmod");

    // the old baseline: made now, by an older version, without any of these
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let mut base = Baseline::from_report(&before);
    base.scanner_version = "0.9.0".into();
    base.created_at = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z").to_string();
    let file = dir.path().join("baseline.json");
    base.save(&file).expect("save");
    // one file appears after the baseline
    std::thread::sleep(std::time::Duration::from_millis(1100));
    write(root, "/home/anna/.local/share/applications/later.desktop", "[Desktop Entry]\nExec=/usr/bin/true\n");

    let opts = ScanOptions { modules, baseline_compare: Some(file), ..ScanOptions::default() };
    let report = run_scan(&sys, &Config::default(), &opts, &|_| {});
    let fresh = of(&report, "BASE-PERSIST-NEW");
    let titles: Vec<(Severity, &str)> = fresh.iter().map(|f| (f.severity, f.title.rsplit('/').next().unwrap_or(""))).collect();
    // only the later file, the edited packaged file and nothing louder
    assert_eq!(titles, vec![(Severity::Medium, "edited"), (Severity::Low, "later.desktop")], "{titles:?}");
    let watched = of(&report, "BASE-PERSIST-WATCHED");
    assert_eq!(watched.len(), 1);
    assert_eq!(watched[0].severity, Severity::Info);
    for path in NEW_KINDS {
        assert!(watched[0].evidence.contains(path), "{path}\n{}", watched[0].evidence);
    }
    assert!(watched[0].evidence.contains("turned.gpg") && !watched[0].evidence.contains("debian.gpg"));
    assert!(report.upgraded_files.iter().any(|f| f.ends_with("debian.gpg")) && report.upgraded_files.iter().any(|f| f.ends_with("postinst.d/packaged")));
    let loud: Vec<(&str, &str)> = report.findings.iter().filter(|f| f.severity >= Severity::High).map(|f| (f.rule.as_str(), f.title.as_str())).collect();
    assert!(loud.iter().all(|f| !f.0.starts_with("BASE-")), "{loud:?}");
    assert!(report.findings.iter().all(|f| f.module != "baseline" || f.severity <= Severity::Medium));
}

#[test]
fn leaving_a_module_out_does_not_make_watched_files_look_new() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    for path in ["/var/lib/dpkg/diversions", "/etc/modprobe.d/own.conf", "/etc/ufw/ufw.conf", "/etc/modules"] {
        write(root, path, "# x\n");
    }
    let sys = SysRoot::new(root);
    let run = |modules: &[ModuleId]| run_scan(&sys, &Config::default(), &ScanOptions { modules: modules.to_vec(), ..ScanOptions::default() }, &|_| {});
    // the window's ordinary scan leaves out the file permissions
    let usual = run(&[ModuleId::NetProc, ModuleId::Persistence, ModuleId::DesktopSession, ModuleId::Kernel]);
    for path in ["/var/lib/dpkg/diversions", "/etc/modprobe.d/own.conf", "/etc/ufw/ufw.conf", "/etc/modules"] {
        assert!(usual.inventory.persistence_files.contains_key(path), "{path}");
    }
    // the other modules record no files that persistence does not
    let others = run(&[ModuleId::NetProc, ModuleId::FsPerms, ModuleId::Kernel]);
    assert!(others.inventory.persistence_files.is_empty(), "{:?}", others.inventory.persistence_files.keys());
    let everything = run(&ModuleId::ALL);
    let (changes, _) = baseline::compare(&Baseline::from_report(&usual), &everything.inventory, &everything.modules);
    assert!(!changes.iter().any(|f| f.rule == "BASE-PERSIST-NEW" || f.rule == "BASE-PERSIST-REMOVED"), "{changes:?}");

    // an old baseline moves to the new version only after a scan that records every file
    let file = dir.path().join("auto.json");
    let mut old = Baseline::from_report(&usual);
    old.scanner_version = "0.9.0".into();
    old.persistence_files.remove("/var/lib/dpkg/diversions");
    old.save(&file).expect("save");
    let as_root = |mut report: Report| {
        report.scan_root = "/".into();
        report.running_as_root = true;
        report.findings.clear();
        report.summary = Default::default();
        report
    };
    auto_save_to(&as_root(run(&[ModuleId::Persistence])), &file);
    let partial = Baseline::load(&file).expect("load");
    assert_eq!(partial.scanner_version, "0.9.0");
    assert!(partial.persistence_files.contains_key("/var/lib/dpkg/diversions"));
    auto_save_to(&as_root(run(&[ModuleId::Persistence, ModuleId::DesktopSession])), &file);
    assert_eq!(Baseline::load(&file).expect("load").scanner_version, env!("CARGO_PKG_VERSION"));
}

#[test]
fn package_accounts_and_nfs_sockets_are_ordinary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(
        root,
        "/var/log/auth.log",
        "2026-11-13T17:24:55+01:00 host useradd[1]: new user: name=tcpdump, UID=117, GID=122, home=/nonexistent, shell=/usr/sbin/nologin, from=/dev/pts/5\n2026-11-13T17:25:55+01:00 host useradd[2]: new user: name=eve, UID=1004, GID=1004, home=/home/eve, shell=/bin/bash, from=/dev/pts/5\n",
    );
    let opts = ScanOptions { modules: vec![ModuleId::AuthLogs], ..ScanOptions::default() };
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {});
    let level = |name: &str| of(&report, "AUTH-NEW-USER").iter().find(|f| f.title.ends_with(name)).map(|f| f.severity);
    assert_eq!(level("tcpdump"), Some(Severity::Info));
    assert_eq!(level("eve"), Some(Severity::Low));
}
