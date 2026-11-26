//! The desktop_session module as a whole: labels, servers without a desktop, grading and the
//! baseline. Made-up files in a temporary directory.

use scanner::baseline::{self, Baseline};
use scanner::config::Config;
use scanner::modules::desktop_session::{is_desktop_path, label_of};
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

const BOTH: [ModuleId; 2] = [ModuleId::Persistence, ModuleId::DesktopSession];

/// A user with an autostart entry, a session script, a window manager file and settings.
fn user_files(root: &Path) {
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/home/anna/.config/autostart/tool.desktop", "[Desktop Entry]\nExec=/home/anna/tool\n");
    write(root, "/home/anna/.xprofile", "export A=1\n");
    write(root, "/home/anna/.config/i3/config", "exec /tmp/.k\n");
    write(root, "/home/anna/.config/plasma-workspace/env/a.sh", "export B=1\n");
    write(root, "/home/anna/.local/share/dbus-1/services/x.service", "[D-BUS Service]\nName=x.y\nExec=/usr/bin/true\n");
    write(root, "/etc/X11/Xsession.d/99x", "true\n");
}

#[test]
fn desktop_findings_share_one_module_and_carry_labels() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    user_files(root);
    write(root, "/usr/share/wayland-sessions/plasma.desktop", "");
    let report = scan(root, &[ModuleId::DesktopSession]);
    assert!(!report.findings.is_empty());
    for f in &report.findings {
        assert_eq!(f.module, "desktop_session", "{}", f.title);
        assert!(f.title.starts_with('['), "{}", f.title);
    }
    let labels = |label: &str| report.findings.iter().any(|f| f.title.starts_with(&format!("[{label}] ")));
    assert!(labels("xdg") && labels("kde") && labels("wm"), "{:?}", report.findings.iter().map(|f| &f.title).collect::<Vec<_>>());
    // everything the module records is recognised as a desktop file by the baseline
    assert!(!report.inventory.persistence_files.is_empty());
    for path in report.inventory.persistence_files.keys() {
        assert!(is_desktop_path(path), "{path}");
    }
    assert_eq!(label_of("PERS-DESKTOP-COMMAND", "/home/a/.config/dconf/user\n"), "gnome");
    assert_eq!(label_of("PERS-DESKTOP-COMMAND", "/home/a/.cache/sessions/xfce4-session-x\n"), "xfce");

    // a finding hidden before the labels existed stays hidden
    let f = report.findings.iter().find(|f| f.title.starts_with("[xdg] ")).expect("xdg finding");
    let mut cfg = Config::default();
    cfg.ignore_findings.push(format!("{}|{}", f.rule, f.title.trim_start_matches("[xdg] ")));
    assert!(cfg.suppresses(f));
}

#[test]
fn a_server_skips_the_desktop_checks_and_a_new_desktop_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/home/anna/.config/autostart/tool.desktop", "[Desktop Entry]\nExec=/home/anna/tool\n");
    let server = scan(root, &BOTH);
    assert!(server.findings.iter().all(|f| f.module != "desktop_session"));
    assert_eq!(server.inventory.desktop, Some(Vec::new()));
    assert!(server.notes.iter().any(|n| n.contains("no graphical desktop")));

    let base = Baseline::from_report(&server);
    write(root, "/usr/share/xsessions/xfce.desktop", "");
    let after = scan(root, &BOTH);
    let (changes, _) = baseline::compare(&base, &after.inventory, &after.modules);
    let new = changes.iter().find(|f| f.rule == "BASE-DESKTOP-NEW").expect("new desktop");
    assert_eq!(new.severity, Severity::High);

    // a machine that already had a desktop reports nothing for the same thing
    let (changes, _) = baseline::compare(&Baseline::from_report(&after), &after.inventory, &after.modules);
    assert!(changes.is_empty(), "{changes:?}");
}

#[test]
fn desktop_changes_are_medium_for_own_files_and_high_for_system_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    user_files(root);
    write(root, "/usr/share/xsessions/x.desktop", "");
    let before = scan(root, &BOTH);
    let base = Baseline::from_report(&before);
    write(root, "/home/anna/.config/autostart/second.desktop", "[Desktop Entry]\nExec=/usr/bin/true\n");
    write(root, "/home/anna/.xprofile", "export A=2\n");
    write(root, "/etc/X11/Xsession.d/99x", "false\n");
    write(root, "/etc/cron.d/job", "0 1 * * * root /usr/bin/true\n");
    let after = scan(root, &BOTH);
    let (changes, _) = baseline::compare(&base, &after.inventory, &after.modules);
    let severity = |end: &str| changes.iter().find(|f| f.title.ends_with(end)).map(|f| f.severity);
    assert_eq!(severity("second.desktop"), Some(Severity::Medium));
    assert_eq!(severity(".xprofile"), Some(Severity::Medium));
    assert_eq!(severity("/etc/X11/Xsession.d/99x"), Some(Severity::High));
    assert_eq!(severity("/etc/cron.d/job"), Some(Severity::High));

    // scanning only persistence does not make the desktop files look removed
    let partial = scan(root, &[ModuleId::Persistence]);
    let (changes, _) = baseline::compare(&base, &partial.inventory, &partial.modules);
    assert!(!changes.iter().any(|f| f.rule == "BASE-PERSIST-REMOVED"), "{changes:?}");

    // a baseline from 0.8.0, where persistence recorded the desktop files, still compares them
    let mut old = base.clone();
    old.modules.retain(|m| m != "desktop_session");
    old.desktop = None;
    let (changes, _) = baseline::compare(&old, &after.inventory, &after.modules);
    assert!(changes.iter().any(|f| f.title.ends_with(".xprofile") && f.rule == "BASE-PERSIST-CHANGED"));
    assert!(!changes.iter().any(|f| f.rule == "BASE-DESKTOP-NEW" || f.rule == "BASE-PERSIST-REMOVED"));
}
