//! Ways to hide from the earlier checks (a package that claims to be Debian's, code in folders
//! that Python path files add), quiet updates of boot files and containers, and VS Code tasks.
//! Made-up files in a temporary directory; nothing on the real system is read or changed.

use scanner::autobaseline::{auto_save_to, AutoBaseline};
use scanner::baseline::{self, Baseline};
use scanner::config::Config;
use scanner::finding::Finding;
use scanner::modules::firewall::comparable_rule;
use scanner::modules::persistence::editors::allows_automatic_tasks;
use scanner::modules::persistence::packages::{AptRecords, Installed};
use scanner::modules::persistence::python::{pth_code, pth_folders};
use scanner::report::Report;
use scanner::{run_scan, ModuleId, ScanOptions, Severity, SysRoot};
use std::fs;
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

fn of<'a>(report: &'a Report, rule: &str) -> Vec<&'a Finding> {
    report.findings.iter().filter(|f| f.rule == rule).collect()
}

fn installed(name: &str, version: &str) -> Installed {
    Installed { name: name.into(), version: version.into(), maintainer: String::new() }
}

#[test]
fn only_apt_records_show_what_apt_installed() {
    let mut apt = AptRecords::default();
    apt.read_states("Package: libauto\nArchitecture: amd64\nAuto-Installed: 1\n");
    apt.read_history(
        "Start-Date: x\nCommandline: apt install foo\nInstall: foo:amd64 (1.0-1), libbar:amd64 (2:3.0, automatic)\nUpgrade: baz:amd64 (1, 2), qux:i386 (4, 5)\n\n\
         Start-Date: y\nCommandline: apt install ./evil.deb\nInstall: evil:amd64 (6.6)\n",
    );
    for (name, version) in [("libauto", "any"), ("foo", "1.0-1"), ("libbar", "2:3.0"), ("baz", "2"), ("qux", "5")] {
        assert!(apt.installed_by_apt(&installed(name, version)), "{name}");
    }
    for (name, version) in [("evil", "6.6"), ("baz", "1"), ("foo", "9"), ("planted", "1")] {
        assert!(!apt.installed_by_apt(&installed(name, version)), "{name}");
    }
}

#[test]
fn a_planted_package_that_claims_to_be_debians_is_seen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let entry = |name: &str, maintainer: &str| format!("Package: {name}\nStatus: install ok installed\nMaintainer: {maintainer}\nVersion: 1\n\n");
    let old = format!("{}{}", entry("dpkg", "D <d@debian.org>"), entry("libold", "A <a@debian.org>"));
    write(root, "/var/lib/dpkg/status", &old);
    write(root, "/var/lib/apt/lists/deb.debian.org_dists_trixie_main_binary-amd64_Packages", "Package: dpkg\nVersion: 1\n\nPackage: libold\nVersion: 1\n");
    write(root, "/var/lib/apt/extended_states", "Package: libold\nAuto-Installed: 1\n");
    let before = scan(root, &[ModuleId::Persistence]);
    let base = Baseline::from_report(&before);

    // dpkg -i of a package that says it is Debian's, and an upgrade that drops libold
    write(root, "/var/lib/dpkg/status", &format!("{old}{}{}", entry("planted", "x <x@debian.org>"), entry("linux-planted", "Debian Kernel Team <k@lists.debian.org>")));
    write(root, "/var/lib/apt/lists/deb.debian.org_dists_trixie_main_binary-amd64_Packages", "Package: dpkg\nVersion: 1\n");
    let after = scan(root, &[ModuleId::Persistence]);
    assert!(of(&after, "PERS-LOCAL-PACKAGE")[0].evidence.contains("planted "));
    assert!(of(&after, "PERS-LOCAL-PACKAGE")[0].evidence.contains("linux-planted"));
    assert_eq!(of(&after, "PERS-RETIRED-PACKAGE")[0].evidence.lines().next(), Some("libold"));
    let (changes, _) = baseline::compare(&base, &after.inventory, &after.modules);
    let titles: Vec<&str> = changes.iter().filter(|f| f.rule == "BASE-LOCAL-PACKAGE").map(|f| f.title.rsplit(' ').next().unwrap_or("")).collect();
    assert_eq!(titles, vec!["planted", "linux-planted"], "libold was installed when the baseline was made");

    // apt's records faked: a new package that looks retired is still reported
    write(root, "/var/lib/apt/extended_states", "Package: libold\nAuto-Installed: 1\n\nPackage: planted\nAuto-Installed: 1\n");
    let faked = scan(root, &[ModuleId::Persistence]);
    assert!(of(&faked, "PERS-RETIRED-PACKAGE")[0].evidence.contains("planted"));
    let (changes, _) = baseline::compare(&base, &faked.inventory, &faked.modules);
    assert!(changes.iter().any(|f| f.rule == "BASE-LOCAL-PACKAGE" && f.title.ends_with(" planted") && f.severity == Severity::Medium));

    // a baseline from the last version has no list of installed packages: still reported, and the
    // list it gets afterwards leaves the new package out, so it stays reported
    let mut older = base.clone();
    older.installed_packages = None;
    older.local_packages = Some(vec!["libold".into()]);
    let (changes, _) = baseline::compare(&older, &faked.inventory, &faked.modules);
    assert!(changes.iter().any(|f| f.title.ends_with(" planted")));
    let path = root.join("baseline.json");
    older.save(&path).expect("save");
    let mut report = faked.clone();
    report.scan_root = "/".into();
    report.running_as_root = true;
    report.summary = Default::default();
    assert!(matches!(auto_save_to(&report, &path), AutoBaseline::Completed(..)));
    let completed = Baseline::load(&path).expect("load");
    let (changes, _) = baseline::compare(&completed, &faked.inventory, &faked.modules);
    assert!(changes.iter().any(|f| f.title.ends_with(" planted")));
}

#[test]
fn folders_added_by_python_path_files() {
    assert_eq!(
        pth_folders("/usr/lib/python3/dist-packages", "\u{feff}# note\n\nimport os\n/dev/shm/x  \n../shared\n"),
        vec!["/dev/shm/x", "/usr/lib/python3/shared"]
    );
    assert_eq!(pth_code("\u{feff}import os\n"), vec!["import os"]);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "root:x:0:0::/root:/bin/bash\nanna:x:1000:1000::/home/anna:/bin/bash\nbo:x:1001:1001::/home/bo:/bin/bash\n");
    let site = "/home/anna/.local/lib/python3.13/site-packages";
    // only folders: one that others can write to, one of another user, one of her own
    write(root, &format!("{site}/a.pth"), "/dev/shm/x\n");
    write(root, "/dev/shm/x/sitecustomize.py", "import os\n");
    write(root, &format!("{site}/own.pth"), "/home/anna/src\n");
    write(root, "/home/anna/src/usercustomize/__init__.py", "import sys\n");
    write(root, "/usr/local/lib/python3.13/dist-packages/b.pth", "/home/bo/lib\n");
    write(root, &format!("{site}/plain.pth"), "/home/anna/code\n");
    write(root, "/home/bo/.keep", "");
    write(root, "/home/anna/.keep", "");
    let report = scan(root, &[ModuleId::Persistence]);
    let paths = of(&report, "PERS-PYTHON-PATH");
    assert_eq!(paths.len(), 2, "{paths:?}");
    assert!(paths.iter().all(|f| f.severity == Severity::High));
    assert!(paths.iter().any(|f| f.evidence.contains("/dev/shm/x") && f.evidence.contains("sitecustomize.py")));
    assert!(paths.iter().any(|f| f.evidence.contains("home folder of bo")));
    let startup = of(&report, "PERS-PYTHON-STARTUP");
    assert!(startup.iter().any(|f| f.title.ends_with("/dev/shm/x/sitecustomize.py") && f.severity == Severity::High && f.evidence.contains("a.pth")));
    assert!(startup.iter().any(|f| f.title.ends_with("/home/anna/src/usercustomize/__init__.py") && f.severity != Severity::High));
    for file in [format!("{site}/a.pth"), format!("{site}/plain.pth"), "/usr/local/lib/python3.13/dist-packages/b.pth".to_string(), "/dev/shm/x/sitecustomize.py".to_string()] {
        assert!(report.inventory.persistence_files.contains_key(&file), "{file}");
    }
}

#[test]
fn a_grub_update_explains_a_new_boot_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/boot/efi/EFI/debian/grubx64.efi", "built");
    let before = scan(root, &[ModuleId::Integrity]);
    write(root, "/boot/efi/EFI/debian/grubx64.efi", "built again");
    let base = root.join("baseline.json");
    Baseline::from_report(&before).save(&base).expect("save");
    let compare = || {
        let opts = ScanOptions { modules: vec![ModuleId::Integrity], baseline_compare: Some(base.clone()), ..ScanOptions::default() };
        run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {})
    };
    assert_eq!(of(&compare(), "BASE-EFI-FILE-CHANGED")[0].severity, Severity::Medium);
    // an unrelated update explains nothing
    write(root, "/var/log/dpkg.log", "2099-01-01 10:00:00 upgrade grub-customizer:amd64 1 2\n");
    assert_eq!(of(&compare(), "BASE-EFI-FILE-CHANGED")[0].severity, Severity::Medium);
    write(root, "/var/log/dpkg.log", "2099-01-01 10:00:00 upgrade grub-efi-amd64:amd64 2.12-9 2.12-10\n");
    let explained = compare();
    assert_eq!(of(&explained, "BASE-EFI-FILE-CHANGED")[0].severity, Severity::Info);
    // so that the automatic baseline takes the new file in
    assert!(explained.upgraded_files.iter().any(|f| f.ends_with("grubx64.efi")));
    scanner::autobaseline::refresh_upgraded(&explained, &base).expect("refresh");
    assert!(of(&compare(), "BASE-EFI-FILE-CHANGED").is_empty());
}

#[test]
fn a_new_container_is_not_a_new_rule() {
    let rule = |address: &str, veth: &str| format!("other ip filter DOCKER: ip daddr {address} iifname != \"br-0a1b2c3d4e5f\" oifname \"{veth}\" tcp dport 80 accept");
    assert_eq!(comparable_rule(&rule("172.17.0.2", "veth1a2")), comparable_rule(&rule("172.17.0.3", "veth9f9")));
    // a public address, another port, the user's own chain and other chains stay as they are
    assert_ne!(comparable_rule(&rule("172.17.0.2", "veth1")), comparable_rule(&rule("203.0.113.9", "veth1")));
    for kept in ["incoming ip filter DOCKER-USER: ip saddr 10.0.0.1 accept", "incoming ip filter INPUT: ip saddr 10.0.0.1 accept", "incoming ip filter DOCKER: ip saddr 0.0.0.0/0 accept"] {
        assert_eq!(comparable_rule(kept), kept);
    }
    assert_eq!(comparable_rule("other inet libvirt_network guest_input: ip daddr 192.168.122.0/24 accept"), "other inet libvirt_network guest_input: ip daddr <address>/24 accept");

    let dir = tempfile::tempdir().expect("tempdir");
    let mut report = scan(dir.path(), &[ModuleId::NetProc]);
    report.inventory.firewall_rules = Some(vec![rule("172.17.0.2", "veth1")]);
    let base = Baseline::from_report(&report);
    let mut now = report.inventory.clone();
    now.firewall_rules = Some(vec![rule("172.17.0.3", "veth2"), rule("172.17.0.4", "veth3")]);
    assert!(baseline::compare(&base, &now, &report.modules).0.iter().all(|f| f.rule != "BASE-FIREWALL-RULE"));
    now.firewall_rules = Some(vec![rule("203.0.113.9", "veth2")]);
    assert!(baseline::compare(&base, &now, &report.modules).0.iter().any(|f| f.rule == "BASE-FIREWALL-RULE"));
}

#[test]
fn vscode_tasks_that_run_without_asking() {
    assert!(allows_automatic_tasks("{\n // c\n \"task.allowAutomaticTasks\": \"on\",\n}"));
    assert!(!allows_automatic_tasks("{\"task.allowAutomaticTasks\": \"off\"}") && !allows_automatic_tasks("{}"));
    assert!(!allows_automatic_tasks("{\n // \"task.allowAutomaticTasks\": \"on\"\n}"));

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    let task = r#"{"version":"2.0.0","tasks":[{"label":"w","command":"make","runOptions":{"runOn":"folderOpen"}}]}"#;
    write(root, "/home/anna/code/p/.vscode/tasks.json", task);
    write(root, "/home/anna/.config/Code/User/tasks.json", task);
    // not looked at: an extension's own file
    write(root, "/home/anna/.vscode/extensions/x.y-1/.vscode/tasks.json", task);
    let asked = scan(root, &[ModuleId::Persistence]);
    let found = of(&asked, "PERS-VSCODE-TASK");
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found.iter().all(|f| f.severity == Severity::Medium));
    assert!(found.iter().any(|f| f.title.starts_with("Your VS Code tasks")));
    assert!(of(&asked, "PERS-VSCODE-AUTOTASKS").is_empty());

    write(root, "/home/anna/.config/Code/User/settings.json", "{\"task.allowAutomaticTasks\": \"on\"}");
    let unasked = scan(root, &[ModuleId::Persistence]);
    assert!(of(&unasked, "PERS-VSCODE-TASK").iter().all(|f| f.severity == Severity::High && f.evidence.contains("without asking")));
    assert_eq!(of(&unasked, "PERS-VSCODE-AUTOTASKS")[0].severity, Severity::Low);
}

#[test]
fn one_walk_serves_the_home_folder_checks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    for file in ["code/a/.env", "code/node_modules/b/.env", ".hidden/.env", "net/auto.pac", ".config/proxy.pac", ".cache/c.pac"] {
        write(root, &format!("/home/anna/{file}"), "FindProxyForURL");
    }
    let sys = SysRoot::new(root);
    let cfg = Config::default();
    let ctx = scanner::modules::ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, wallet_watch_secs: 0, privileged: true, processes: &[] };
    let index = scanner::modules::homeindex::of(&ctx, "/home/anna");
    assert_eq!(index.env_files, vec!["/home/anna/code/a/.env"]);
    assert_eq!(index.pac_files, vec!["/home/anna/.config/proxy.pac", "/home/anna/net/auto.pac"]);
}
