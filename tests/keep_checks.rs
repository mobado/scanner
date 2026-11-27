//! That packages stay protected after apt updates them, that Python's own folders and files are
//! judged by who can write to them (also through access lists), that only real caches are skipped
//! and that debconf scripts count. Made-up files in a temporary directory; nothing on the real
//! system is read or changed.

use scanner::autobaseline::refresh_upgraded;
use scanner::baseline::{self, Baseline};
use scanner::config::Config;
use scanner::finding::Finding;
use scanner::modules::homeindex;
use scanner::modules::persistence::packages::{aptitude_runs, history_runs, sums_differ};
use scanner::modules::persistence::python::parse_acl;
use scanner::modules::ScanCtx;
use scanner::report::Report;
use scanner::{run_scan, ModuleId, ScanOptions, Severity, SysRoot};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

fn write(root: &Path, abs: &str, content: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(p, content).expect("write");
}

/// The same rights everywhere, whatever the umask of whoever runs the tests.
fn tidy_rights(dir: &Path) {
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).expect("chmod");
    for entry in fs::read_dir(dir).expect("read").flatten() {
        match entry.file_type() {
            Ok(t) if t.is_dir() => tidy_rights(&entry.path()),
            Ok(t) if t.is_file() => fs::set_permissions(entry.path(), fs::Permissions::from_mode(0o644)).expect("chmod"),
            _ => {}
        }
    }
}

fn of<'a>(report: &'a Report, rule: &str) -> Vec<&'a Finding> {
    report.findings.iter().filter(|f| f.rule == rule).collect()
}

const LISTS: &str = "/var/lib/apt/lists/deb.debian.org_dists_trixie_main_binary-amd64_Packages";

/// Install these (name, version) pairs the way dpkg records them.
fn install(root: &Path, packages: &[(&str, &str)]) {
    let status: String = packages.iter().map(|(n, v)| format!("Package: {n}\nStatus: install ok installed\nVersion: {v}\n\n")).collect();
    write(root, "/var/lib/dpkg/status", &status);
}

fn files_of(root: &Path, name: &str, version: &str) {
    write(root, &format!("/var/lib/dpkg/info/{name}.md5sums"), &format!("{version}  usr/bin/{name}\n"));
}

fn history(root: &Path, when: &str, command: &str, line: &str) {
    write(root, "/var/log/apt/history.log", &format!("Start-Date: {when}  10:00:00\nCommandline: {command}\n{line}\nEnd-Date: {when}  10:00:09\n"));
}

#[test]
fn an_apt_upgrade_moves_the_baseline_along() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let all = [("dpkg", "1"), ("sudo", "1"), ("old", "1")];
    install(root, &all);
    for (name, version) in all {
        files_of(root, name, version);
    }
    write(root, LISTS, "Package: dpkg\nVersion: 1\n\nPackage: sudo\nVersion: 2\n\nPackage: old\nVersion: 1\n\nPackage: fresh\nVersion: 1\n");
    let opts = ScanOptions { modules: vec![ModuleId::Persistence], ..ScanOptions::default() };
    let first = run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {});
    let path = root.join("baseline.json");
    Baseline::from_report(&first).save(&path).expect("save");
    let compare = || {
        let opts = ScanOptions { baseline_compare: Some(path.clone()), ..opts.clone() };
        run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {})
    };

    // apt upgrades sudo, installs a package and removes another
    install(root, &[("dpkg", "1"), ("sudo", "2"), ("fresh", "1")]);
    files_of(root, "sudo", "2");
    files_of(root, "fresh", "1");
    fs::rename(root.join("var/lib/dpkg/info/old.md5sums"), root.join("old.md5sums")).expect("move");
    history(root, "2099-01-01", "apt upgrade", "Upgrade: sudo:amd64 (1, 2)\nInstall: fresh:amd64 (1)");
    let upgraded = compare();
    assert!(of(&upgraded, "BASE-PACKAGE-CHANGED").is_empty(), "{:?}", of(&upgraded, "BASE-PACKAGE-CHANGED"));
    assert_eq!(upgraded.updated_packages, vec!["fresh", "sudo"]);
    assert_eq!(refresh_upgraded(&upgraded, &path).expect("refresh"), 2);
    let base = Baseline::load(&path).expect("load");
    let installed = base.installed_packages.clone().expect("installed");
    assert!(installed.contains(&"sudo 2".to_string()) && installed.contains(&"fresh 1".to_string()));
    assert!(!installed.iter().any(|p| p.starts_with("old ") || p == "sudo 1"));
    assert!(!base.package_sums.as_ref().expect("sums").contains_key("old"));

    // the new version is protected now: another build under the same number is seen
    write(root, "/var/lib/dpkg/info/sudo.md5sums", "evil  usr/bin/sudo\n");
    let swapped = compare();
    assert_eq!(of(&swapped, "BASE-PACKAGE-REPLACED").len(), 1);
    assert!(of(&swapped, "BASE-PACKAGE-CHANGED").is_empty());
    assert!(swapped.updated_packages.is_empty());
}

#[test]
fn what_apt_does_not_explain_stays_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    install(root, &[("dpkg", "1"), ("sudo", "1")]);
    files_of(root, "sudo", "1");
    write(root, LISTS, "Package: dpkg\nVersion: 1\n\nPackage: sudo\nVersion: 2\n");
    let opts = ScanOptions { modules: vec![ModuleId::Persistence], ..ScanOptions::default() };
    let first = run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {});
    let mut base = Baseline::from_report(&first);
    base.created_at = "1999-01-01 00:00:00 +0000".into();
    let path = root.join("baseline.json");
    base.save(&path).expect("save");
    install(root, &[("dpkg", "1"), ("sudo", "2")]);
    files_of(root, "sudo", "2");
    let reported = |why: &str| {
        let opts = ScanOptions { baseline_compare: Some(path.clone()), ..opts.clone() };
        let report = run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {});
        let found = of(&report, "BASE-PACKAGE-CHANGED");
        assert_eq!(found.len(), 1, "{why}");
        assert!(found[0].severity == Severity::Medium && found[0].evidence.contains("sudo: before: 1  now: 2"), "{}", found[0].evidence);
        assert!(report.updated_packages.is_empty(), "{why}");
    };
    reported("dpkg -i: no history at all");
    history(root, "2099-01-01", "apt install ./sudo_2.deb", "Upgrade: sudo:amd64 (1, 2)");
    reported("a file handed to apt");
    history(root, "2099-01-01", "packagekit role='install-files'", "Upgrade: sudo:amd64 (1, 2)");
    reported("a file handed to the software centre");
    history(root, "2099-01-01", "apt upgrade", "Upgrade: sudo:amd64 (1, 3)");
    reported("another version");
    history(root, "1998-01-01", "apt upgrade", "Upgrade: sudo:amd64 (1, 2)");
    reported("before the baseline");
    // apt did install it, but dpkg's files were written again after that run ended
    history(root, "2001-01-01", "apt upgrade", "Upgrade: sudo:amd64 (1, 2)");
    reported("rewritten after apt");
    // a package no source offers is never taken in
    write(root, LISTS, "Package: dpkg\nVersion: 1\n");
    history(root, "2099-01-01", "apt upgrade", "Upgrade: sudo:amd64 (1, 2)");
    let opts = ScanOptions { baseline_compare: Some(path.clone()), ..opts.clone() };
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {});
    assert!(report.updated_packages.is_empty());
}

#[test]
fn history_and_aptitude_runs_carry_their_times() {
    let runs = history_runs("Start-Date: 2026-01-02  10:00:00\nInstall: a:amd64 (1)\nEnd-Date: 2026-01-02  10:00:05\n");
    assert!(runs[0].began.is_some() && runs[0].ended > runs[0].began);
    let runs = aptitude_runs("Aptitude 0.8.13: log report\nFri, Jan  2 2026 10:00:00 +0100\n\n[INSTALL] a:amd64 1\n");
    assert!(runs[0].began.is_some() && runs[0].installed == vec![("a".to_string(), "1".to_string())]);
}

#[test]
fn the_debconf_script_and_triggers_are_fingerprinted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    install(root, &[("dpkg", "1"), ("tool", "1")]);
    files_of(root, "tool", "1");
    write(root, LISTS, "Package: dpkg\nVersion: 1\n");
    let opts = ScanOptions { modules: vec![ModuleId::Persistence], ..ScanOptions::default() };
    let scan = || run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {});
    let before = scan();
    let base = Baseline::from_report(&before);
    let replaced = |base: &Baseline, now: &Report| baseline::compare(base, &now.inventory, &now.modules).0.iter().filter(|f| f.rule == "BASE-PACKAGE-REPLACED").count();
    write(root, "/var/lib/dpkg/info/tool.config", "#!/bin/sh\n");
    let with_config = scan();
    assert_eq!(replaced(&base, &with_config), 1);
    write(root, "/var/lib/dpkg/info/tool.triggers", "interest /usr/share/x\n");
    assert_eq!(replaced(&Baseline::from_report(&with_config), &scan()), 1);
    // a fingerprint from the last version holds only the first part: no false alarm
    let mut older = base.clone();
    for sum in older.package_sums.as_mut().expect("sums").values_mut() {
        *sum = sum.split('+').next().unwrap_or("").to_string();
    }
    assert_eq!(replaced(&older, &scan()), 0);
    assert!(!sums_differ("a", "a+b") && sums_differ("a", "c+b") && sums_differ("a+b", "a+c"));
}

#[test]
fn python_folders_and_files_others_can_write_to() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let me = fs::metadata(root).expect("meta").uid();
    let site = "/usr/local/lib/python3.13/dist-packages";
    write(root, &format!("{site}/a.pth"), "");
    write(root, "/usr/lib/python3.13/sitecustomize.py", "import sys\n");
    write(root, "/etc/passwd", &format!("anna:x:{me}:{me}::/home/anna:/bin/sh\n"));
    write(root, "/home/anna/.local/lib/python3.13/site-packages/b.pth", "");
    tidy_rights(root);
    let opts = ScanOptions { modules: vec![ModuleId::Persistence], ..ScanOptions::default() };
    let scan = || run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {});
    assert!(of(&scan(), "PERS-PYTHON-WRITABLE").is_empty(), "{:?}", of(&scan(), "PERS-PYTHON-WRITABLE"));
    let mode = |abs: &str, mode: u32| fs::set_permissions(root.join(abs.trim_start_matches('/')), fs::Permissions::from_mode(mode)).expect("chmod");
    let evidence = || {
        let report = scan();
        let found = of(&report, "PERS-PYTHON-WRITABLE");
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].severity, Severity::High);
        found[0].evidence.clone()
    };
    // like after "sudo chmod -R 777"
    mode(site, 0o777);
    assert!(evidence().contains(&format!("everyone can write to {site}")));
    mode(site, 0o755);
    mode(&format!("{site}/a.pth"), 0o666);
    assert!(evidence().contains(&format!("everyone can write to {site}/a.pth")));
    mode(&format!("{site}/a.pth"), 0o644);
    mode("/usr/lib/python3.13/sitecustomize.py", 0o646);
    assert!(evidence().contains("sitecustomize.py"));
}

/// An access list as the kernel stores it: owner, one named user, group, mask and others.
fn acl(user: u32, mask: u16) -> Vec<u8> {
    let mut data = 2u32.to_le_bytes().to_vec();
    for (tag, rights, id) in [(0x01u16, 7u16, u32::MAX), (0x02, 7, user), (0x04, 5, u32::MAX), (0x10, mask, u32::MAX), (0x20, 5, u32::MAX)] {
        data.extend(tag.to_le_bytes());
        data.extend(rights.to_le_bytes());
        data.extend(id.to_le_bytes());
    }
    data
}

#[test]
fn access_lists_are_read() {
    assert_eq!(parse_acl(&acl(1234, 7)).map(|e| (e.len(), e[1])), Some((5, (0x02, 7, 1234))));
    assert!(parse_acl(&[1, 0, 0, 0]).is_none() && parse_acl(&[2, 0, 0, 0, 1]).is_none());

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let me = fs::metadata(root).expect("meta").uid();
    let site = "/usr/local/lib/python3.13/dist-packages";
    write(root, &format!("{site}/a.pth"), "");
    write(root, "/etc/passwd", &format!("bo:x:{}:{}::/nonexistent:/bin/sh\n", me + 1, me + 1));
    tidy_rights(root);
    let folder = root.join(site.trim_start_matches('/'));
    let set = |mask: u16| rustix::fs::setxattr(&folder, "system.posix_acl_access", &acl(me + 1, mask), rustix::fs::XattrFlags::empty());
    if set(7).is_err() {
        eprintln!("this file system has no access lists; the live part is skipped");
        return;
    }
    let opts = ScanOptions { modules: vec![ModuleId::Persistence], ..ScanOptions::default() };
    let scan = || run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {});
    let report = scan();
    let found = of(&report, "PERS-PYTHON-WRITABLE");
    assert!(found.len() == 1 && found[0].evidence.contains(&format!("an access list lets bo write to {site}")), "{found:?}");
    // the mask takes the right away again, although the entry still names it
    set(5).expect("acl");
    assert!(of(&scan(), "PERS-PYTHON-WRITABLE").is_empty());
}

#[test]
fn only_caches_in_their_usual_place_are_skipped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let home = "/home/anna";
    for project in ["containers", "code/Steam-tools/Steam", "web/.yarn", "x/.cache", "y/Trash", "z/flatpak"] {
        write(root, &format!("{home}/{project}/.venv/lib/python3.13/site-packages/a.pth"), "");
    }
    for cache in [".cache", ".local/share/containers", ".local/share/Steam", ".local/share/Trash", ".yarn", ".local/share/flatpak"] {
        write(root, &format!("{home}/{cache}/x/site-packages/a.pth"), "");
    }
    let sys = SysRoot::new(root);
    let cfg = Config::default();
    let ctx = ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, wallet_watch_secs: 0, privileged: true, processes: &[] };
    let index = homeindex::build(&ctx, home, 10_000);
    assert_eq!(index.site_packages.len(), 6, "{:?}", index.site_packages);
    assert!(index.site_packages.iter().all(|p| p.contains("/.venv/")));
}
