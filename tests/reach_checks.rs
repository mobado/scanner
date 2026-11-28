//! That the home folder search reaches projects, that folders added by Python are judged by who
//! can write to them, that old packages are explained and swapped ones seen. Made-up files in a
//! temporary directory; nothing on the real system is read or changed.

use scanner::baseline::{self, Baseline};
use scanner::config::Config;
use scanner::finding::Finding;
use scanner::modules::common::take_cut_short;
use scanner::modules::homeindex;
use scanner::modules::persistence::packages::{AptRecords, Installed};
use scanner::modules::ScanCtx;
use scanner::report::Report;
use scanner::{run_scan, ModuleId, ScanOptions, Severity, SysRoot};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;

fn write(root: &Path, abs: &str, content: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(p, content).expect("write");
}

/// The same rights on every folder, whatever the umask of whoever runs the tests.
fn tidy_rights(dir: &Path) {
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).expect("chmod");
    for entry in fs::read_dir(dir).expect("read").flatten() {
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            tidy_rights(&entry.path());
        }
    }
}

fn rights(root: &Path, abs: &str, mode: u32) {
    fs::set_permissions(root.join(abs.trim_start_matches('/')), fs::Permissions::from_mode(mode)).expect("chmod");
}

fn scan(root: &Path, modules: &[ModuleId]) -> Report {
    let opts = ScanOptions { modules: modules.to_vec(), ..ScanOptions::default() };
    run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {})
}

fn of<'a>(report: &'a Report, rule: &str) -> Vec<&'a Finding> {
    report.findings.iter().filter(|f| f.rule == rule).collect()
}

#[test]
fn projects_come_before_caches_and_tool_folders() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let home = "/home/anna";
    // far more files in caches and hidden folders than the limit allows
    for n in 0..60 {
        for place in [".cargo/registry", ".rustup", ".npm", ".gradle", ".m2", ".conda/pkgs", "go/pkg/mod", ".aaa-tool"] {
            write(root, &format!("{home}/{place}/file{n}"), "");
        }
    }
    write(root, &format!("{home}/zz-project/.venv/lib/python3.13/site-packages/a.pth"), "");
    write(root, &format!("{home}/zz-project/.vscode/tasks.json"), "{}");
    for env in [".virtualenvs/x", ".pyenv/versions/3.12/envs/y", ".conda/envs/z"] {
        write(root, &format!("{home}/{env}/lib/python3.13/site-packages/a.pth"), "");
    }
    write(root, &format!("{home}/.cache/pypoetry/virtualenvs/p/lib/python3.13/site-packages/a.pth"), "");
    write(root, &format!("{home}/.cargo/registry/x/site-packages/a.pth"), "");
    let sys = SysRoot::new(root);
    let cfg = Config::default();
    let ctx = ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, wallet_watch_secs: 0, privileged: true, processes: &[], accounts: scanner::procinfo::read_accounts(&sys) };
    take_cut_short();
    let index = homeindex::build(&ctx, home, 40);
    for wanted in ["zz-project/.venv", ".virtualenvs/x", ".pyenv/versions/3.12/envs/y", ".conda/envs/z", ".cache/pypoetry/virtualenvs/p"] {
        assert!(index.site_packages.iter().any(|p| p.contains(wanted)), "{wanted}: {:?}", index.site_packages);
    }
    assert!(!index.site_packages.iter().any(|p| p.contains("registry")));
    assert_eq!(index.vscode_tasks, vec![format!("{home}/zz-project/.vscode/tasks.json")]);
    // the hidden tool folder came last and ran into the limit
    assert!(!take_cut_short().is_empty());
    take_cut_short();
    homeindex::build(&ctx, home, 1000);
    assert!(take_cut_short().is_empty(), "the caches are skipped, not counted");
}

#[test]
fn folders_others_can_write_to_are_seen_wherever_they_are() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let me = fs::metadata(root).expect("meta").uid();
    let group = fs::metadata(root).expect("meta").gid();
    let site = "/usr/local/lib/python3.13/dist-packages";
    for folder in ["/opt/open", "/srv/shared/lib", "/srv/team", "/opt/fine", "/opt/own-group", "/opt/sticky/lib", "/opt/loose/inner"] {
        write(root, &format!("{folder}/x.py"), "");
    }
    for (name, folder) in [("a", "/opt/open"), ("b", "/srv/shared/lib"), ("c", "/srv/team"), ("d", "/opt/fine"), ("e", "/opt/sticky/lib"), ("f", "/opt/loose/inner"), ("g", "/opt/link"), ("h", "/opt/drop/not-there-yet")] {
        write(root, &format!("{site}/{name}.pth"), &format!("{folder}\n"));
    }
    fs::create_dir_all(root.join("opt/drop")).expect("mkdir");
    tidy_rights(root);
    symlink("/opt/open", root.join("opt/link")).expect("link");
    rights(root, "/opt/open", 0o777);
    // the folder above is open to all
    rights(root, "/srv/shared", 0o777);
    // a group with another member
    rights(root, "/srv/team", 0o775);
    // a sticky folder above an existing one does not let others replace it
    rights(root, "/opt/sticky", 0o1777);
    rights(root, "/opt/loose", 0o777);
    // but a folder that is still missing can be made in it
    rights(root, "/opt/drop", 0o1777);
    let other = me + 1;
    write(root, "/etc/passwd", &format!("root:x:0:0::/root:/bin/sh\nme:x:{me}:{group}::/nonexistent:/bin/sh\nbo:x:{other}:{other}::/nonexistent:/bin/sh\n"));
    write(root, "/etc/group", &format!("staff:x:{group}:bo\n"));
    rights(root, "/etc", 0o755);
    let report = scan(root, &[ModuleId::Persistence]);
    let found = of(&report, "PERS-PYTHON-PATH");
    let flagged = |name: &str| found.iter().find(|f| f.title.ends_with(&format!("/{name}.pth"))).map(|f| f.evidence.clone());
    for (name, why) in [("a", "everyone can write to /opt/open"), ("b", "everyone can write to /srv/shared"), ("c", "group staff can write to /srv/team (bo)"), ("f", "everyone can write to /opt/loose"), ("g", "everyone can write to /opt/open"), ("h", "everyone can write to /opt/drop")] {
        assert!(flagged(name).is_some_and(|e| e.contains(why)), "{name}: {:?}", flagged(name));
    }
    assert!(flagged("d").is_none() && flagged("e").is_none(), "{found:?}");
    assert!(found.iter().all(|f| f.severity == Severity::High));
}

#[test]
fn installer_and_aptitude_records_explain_old_packages() {
    let installed = |name: &str, version: &str| Installed { name: name.into(), version: version.into(), maintainer: String::new() };
    let mut apt = AptRecords::default();
    apt.read_installer("Package: base-lib\nStatus: install ok installed\nVersion: 1.0-1\n");
    apt.read_aptitude("Aptitude 0.8.13: log report\n========\n[INSTALL, DEPENDENCIES] liba:amd64 2.0\n[UPGRADE] libb:amd64 1.0 -> 1.1\n[REMOVE] gone:amd64 3\n");
    for (name, version) in [("base-lib", "1.0-1"), ("liba", "2.0"), ("libb", "1.1")] {
        assert!(apt.installed_by_apt(&installed(name, version)), "{name}");
    }
    for (name, version) in [("base-lib", "1.0-2"), ("libb", "1.0"), ("gone", "3")] {
        assert!(!apt.installed_by_apt(&installed(name, version)), "{name}");
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let entry = |name: &str| format!("Package: {name}\nStatus: install ok installed\nMaintainer: A <a@debian.org>\nVersion: 1\n\n");
    write(root, "/var/lib/dpkg/status", &format!("Package: dpkg\nStatus: install ok installed\nVersion: 1\n\n{}{}", entry("from-installer"), entry("from-aptitude")));
    write(root, "/var/lib/apt/lists/deb.debian.org_dists_trixie_main_binary-amd64_Packages", "Package: dpkg\nVersion: 1\n");
    write(root, "/var/log/installer/status", &entry("from-installer"));
    write(root, "/var/log/aptitude", "[INSTALL] from-aptitude:amd64 1\n");
    let report = scan(root, &[ModuleId::Persistence]);
    assert!(of(&report, "PERS-LOCAL-PACKAGE").is_empty(), "{:?}", of(&report, "PERS-LOCAL-PACKAGE"));
    assert_eq!(of(&report, "PERS-RETIRED-PACKAGE").len(), 1);
}

#[test]
fn a_swapped_package_with_the_same_version_is_seen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let entry = |name: &str, version: &str| format!("Package: {name}\nStatus: install ok installed\nMaintainer: A <a@debian.org>\nVersion: {version}\n\n");
    let status = format!("{}{}{}", entry("dpkg", "1"), entry("retired", "1"), entry("offered", "1"));
    write(root, "/var/lib/dpkg/status", &status);
    write(root, "/var/lib/apt/lists/deb.debian.org_dists_trixie_main_binary-amd64_Packages", "Package: dpkg\nVersion: 1\n\nPackage: offered\nVersion: 1\n");
    write(root, "/var/lib/apt/extended_states", "Package: retired\nAuto-Installed: 1\n");
    for name in ["retired", "offered", "dpkg"] {
        write(root, &format!("/var/lib/dpkg/info/{name}.md5sums"), "aaaa  usr/bin/x\n");
    }
    let before = scan(root, &[ModuleId::Persistence]);
    let base = Baseline::from_report(&before);
    let replaced = |now: &Report| {
        let (changes, _) = baseline::compare(&base, &now.inventory, &now.modules);
        changes.into_iter().filter(|f| f.rule == "BASE-PACKAGE-REPLACED").map(|f| (f.severity, f.title.rsplit(' ').next().unwrap_or("").to_string())).collect::<Vec<_>>()
    };
    assert!(replaced(&scan(root, &[ModuleId::Persistence])).is_empty());
    // the same version, other files; and an install script that was not there
    write(root, "/var/lib/dpkg/info/retired.md5sums", "bbbb  usr/bin/x\n");
    write(root, "/var/lib/dpkg/info/offered.postinst", "#!/bin/sh\n");
    write(root, "/var/lib/dpkg/info/offered.list", "/usr/bin/x\n");
    let after = scan(root, &[ModuleId::Persistence]);
    assert_eq!(replaced(&after), vec![(Severity::Medium, "offered".to_string()), (Severity::High, "retired".to_string())]);
    // a new version is an ordinary upgrade
    write(root, "/var/lib/dpkg/status", &status.replace("Package: retired\nStatus: install ok installed\nMaintainer: A <a@debian.org>\nVersion: 1", "Package: retired\nStatus: install ok installed\nMaintainer: A <a@debian.org>\nVersion: 2"));
    assert_eq!(replaced(&scan(root, &[ModuleId::Persistence])), vec![(Severity::Medium, "offered".to_string())]);
}
