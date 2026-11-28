//! A process chooses its `comm` (prctl) and `argv[0]` (`exec -a`) itself, so neither may earn it
//! an exception: only its program file counts, and never an interpreter's.

use scanner::config::Config;
use scanner::modules::secrets::judge_reader;
use scanner::modules::wallet::judge_owner;
use scanner::procinfo::{is_program_path, runs_any_code, ProcInfo};
use scanner::{run_scan, ModuleId, Report, ScanOptions, Severity, SysRoot};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

fn write(root: &Path, path: &str, text: &str) {
    let full = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
    fs::write(full, text).expect("write");
}

fn link(root: &Path, path: &str, target: &str) {
    let full = root.join(path.trim_start_matches('/'));
    fs::create_dir_all(full.parent().expect("parent")).expect("mkdir");
    symlink(target, full).expect("link");
}

/// A process of anna's whose program file is `exe` but which calls itself `claims`, in `comm`
/// and `argv[0]` alike.
fn impostor(root: &Path, pid: u32, exe: &str, claims: &str, args: &str) {
    write(root, &format!("/proc/{pid}/stat"), &format!("{pid} ({claims}) S 1 1 1 0 -1 4194560 0 0\n"));
    write(root, &format!("/proc/{pid}/status"), &format!("Name:\t{claims}\nPPid:\t1\nUid:\t1000 1000 1000 1000\nCapEff:\t0000000000080000\n"));
    write(root, &format!("/proc/{pid}/cmdline"), &format!("{claims}\0{args}"));
    link(root, &format!("/proc/{pid}/exe"), exe);
}

fn scan(root: &Path, modules: &[ModuleId]) -> Report {
    let options = ScanOptions { modules: modules.to_vec(), ..ScanOptions::default() };
    run_scan(&SysRoot::new(root), &Config::default(), &options, &|_| {})
}

#[test]
fn only_the_program_file_names_a_program() {
    let named = ProcInfo { exe: Some("/usr/bin/sqlite3".into()), comm: "firefox".into(), cmdline: vec!["firefox".into()], ..ProcInfo::default() };
    assert!(!named.is_program(&["firefox"]));
    assert!(named.is_program(&["sqlite3"]));
    assert!(!ProcInfo { comm: "firefox".into(), ..ProcInfo::default() }.is_program(&["firefox"]), "no file, no name");
    assert!(is_program_path("/usr/lib/firefox-esr/firefox-esr (deleted)", &["firefox-esr"]), "upgraded while running");
    // interpreters and the loader run anything: never, whatever the list says
    for name in ["python3", "python3.13", "perl5.40.1", "ruby3.3", "node", "bash", "sh", "dash", "lua5.4", "tclsh8.6", "ld-linux-x86-64.so.2"] {
        assert!(runs_any_code(name), "{name}");
        assert!(!is_program_path(&format!("/usr/bin/{name}"), &[name]), "{name}");
    }
    for name in ["sqlite3", "gpg2", "ssh", "kwalletd6", "php-fpm8.4", "systemd"] {
        assert!(!runs_any_code(name), "{name}");
    }
    let cfg = Config::default();
    assert_eq!(judge_reader(&cfg, "browser passwords or cookies", "/usr/bin/sqlite3"), Some(Severity::High));
    assert_eq!(judge_owner(&cfg, "org.freedesktop.secrets", "/usr/bin/python3.13"), Some(Severity::Medium));
    assert!(!cfg.is_listen_process_allowed("avahi-daemon", Some("/usr/bin/python3")));
}

#[test]
fn stealing_cookies_under_a_browsers_name_is_seen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let cookies = "/home/anna/.mozilla/firefox/x.default/cookies.sqlite";
    // exec -a firefox sqlite3 …, and a Python script that renamed itself with prctl
    impostor(root, 40, "/usr/bin/sqlite3", "firefox", cookies);
    link(root, "/proc/40/fd/3", cookies);
    impostor(root, 41, "/usr/bin/python3.13", "firefox-esr", "steal.py");
    link(root, "/proc/41/fd/3", cookies);
    // the real browser
    impostor(root, 42, "/usr/lib/firefox-esr/firefox-esr", "firefox-esr", "");
    link(root, "/proc/42/fd/3", cookies);
    let report = scan(root, &[ModuleId::ProcAudit]);
    let found: Vec<&str> = report.findings.iter().filter(|f| f.rule == "PROC-SECRET-ACCESS").map(|f| f.evidence.as_str()).collect();
    assert_eq!(found.len(), 2, "{found:?}");
    assert!(found.iter().all(|e| e.contains("sqlite3") || e.contains("python3")));
}

#[test]
fn borrowed_names_explain_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let spaces = |pid: u32, id: u32| {
        for (kind, n) in [("user", id), ("net", id + 1), ("mnt", id + 2)] {
            link(root, &format!("/proc/{pid}/ns/{kind}"), &format!("{kind}:[{n}]"));
        }
    };
    impostor(root, 1, "/usr/lib/systemd/systemd", "systemd", "");
    spaces(1, 1);
    // Python calling itself a browser, with Chromium's option, holding root-like rights
    impostor(root, 50, "/usr/bin/python3.13", "firefox", "x.py\0 --type=zygote");
    spaces(50, 100);
    // an installed program that merely accepts the option, without Chromium's files
    impostor(root, 51, "/usr/bin/yes", "yes", " --type=renderer");
    spaces(51, 200);
    // a program calling itself a service that may hold rights
    impostor(root, 52, "/usr/bin/sleep", "dumpcap", "100");
    let report = scan(root, &[ModuleId::ProcAudit]);
    let evidence = |rule: &str| report.findings.iter().filter(|f| f.rule == rule).map(|f| f.evidence.clone()).collect::<Vec<_>>().join("\n");
    assert!(evidence("PROC-NAMESPACE").contains("python3.13") && evidence("PROC-NAMESPACE").contains("/usr/bin/yes"), "{}", evidence("PROC-NAMESPACE"));
    assert!(evidence("PROC-CAPABILITIES").contains("PID 52 "), "{}", evidence("PROC-CAPABILITIES"));
}

#[test]
fn argv0_cannot_borrow_a_listed_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    impostor(root, 1, "/usr/lib/systemd/systemd", "systemd", "");
    write(root, "/usr/sbin/sshd", "");
    // from the home folder, calling itself sshd – also from a folder named after it
    impostor(root, 60, "/home/anna/.cache/x/miner", "sshd", "");
    impostor(root, 61, "/home/anna/.cache/sshd/miner", "sshd", "");
    let report = scan(root, &[ModuleId::NetProc]);
    assert_eq!(report.findings.iter().filter(|f| f.rule == "NET-ARGV0-MASK").count(), 2, "{:?}", report.findings);
}
