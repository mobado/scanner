//! A process chooses its `comm` (prctl) and `argv[0]` (`exec -a`) itself, so neither may earn it
//! an exception: only its program file counts, and never an interpreter's.

use scanner::config::Config;
use scanner::modules::persistence::keys::odd_libraries;
use scanner::modules::secrets::judge_reader;
use scanner::modules::wallet::{judge_holder, judge_owner};
use scanner::modules::ScanCtx;
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

/// A `/proc/<pid>/maps` line.
fn map(rights: &str, path: &str) -> String {
    format!("7f0000000000-7f0000001000 {rights} 00000000 08:01 42                   {path}\n")
}

#[test]
fn every_executable_mapping_from_a_writable_place_counts() {
    let maps = [
        map("r-xp", "/usr/lib/x86_64-linux-gnu/libc.so.6"),
        // whatever the file is called
        map("r-xp", "/home/anna/.cache/data.bin"),
        map("rwxp", "/run/user/1000/x.so"),
        map("r-xs", "/memfd:stage2 (deleted)"),
        map("r-xp", "/dev/shm/a b.so (deleted)"),
        // data is not code
        map("r--p", "/home/anna/.local/share/fonts/x.ttf"),
        map("rw-s", "/memfd:wayland-shm (deleted)"),
        map("r-xp", "[vdso]"),
        map("r-xp", ""),
    ]
    .concat();
    assert_eq!(odd_libraries(&maps), ["/dev/shm/a b.so (deleted)", "/home/anna/.cache/data.bin", "/memfd:stage2 (deleted)", "/run/user/1000/x.so"]);
    // Qt's compiler for QML works in memory files, in programs that have Qt's QML library
    let jit = map("r-xp", "/memfd:JITCode:QtQml (deleted)");
    assert_eq!(odd_libraries(&jit).len(), 1, "without Qt the name proves nothing");
    let qt = jit.clone() + &map("r-xp", "/usr/lib/x86_64-linux-gnu/libQt6Qml.so.6.8.2");
    assert!(odd_libraries(&qt).is_empty());
    let fake = jit + &map("r-xp", "/home/anna/libQt6Qml.so.6");
    assert_eq!(odd_libraries(&fake).len(), 2);
}

#[test]
fn an_installed_program_running_foreign_code_loses_its_exception() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/usr/share/xsessions/x.desktop", "");
    let cookies = "/home/anna/.mozilla/firefox/x.default/cookies.sqlite";
    let libc = map("r-xp", "/usr/lib/x86_64-linux-gnu/libc.so.6");
    let evil = map("r-xp", "/home/anna/.cache/x/hook.so");
    let process = |pid: u32, exe: &str, name: &str, opens: &str, maps: String| {
        impostor(root, pid, exe, name, "");
        link(root, &format!("/proc/{pid}/fd/3"), opens);
        write(root, &format!("/proc/{pid}/maps"), &maps);
    };
    // the browser, a backup program and a keyboard reader, clean and with code slipped in
    process(70, "/usr/lib/firefox-esr/firefox-esr", "firefox-esr", cookies, libc.clone());
    process(71, "/usr/lib/firefox-esr/firefox-esr", "firefox-esr", cookies, libc.clone() + &evil);
    process(72, "/usr/bin/rsync", "rsync", cookies, libc.clone() + &map("r-xp", "/memfd:x (deleted)"));
    process(73, "/usr/bin/kwin_wayland", "kwin_wayland", "/dev/input/event3", libc.clone());
    process(74, "/usr/bin/kwin_wayland", "kwin_wayland", "/dev/input/event3", libc.clone() + &evil);
    process(75, "/usr/bin/keyd", "keyd", "/dev/uinput", libc.clone());
    process(76, "/usr/bin/keyd", "keyd", "/dev/uinput", libc + &evil);
    let report = scan(root, &[ModuleId::ProcAudit, ModuleId::DesktopSession]);
    let pids = |rule: &str| {
        let mut found: Vec<(u32, Severity)> = report.findings.iter().filter(|f| f.rule == rule).map(|f| (f.evidence[4..6].parse().expect("pid"), f.severity)).collect();
        found.sort();
        found
    };
    assert_eq!(pids("PROC-SECRET-ACCESS"), [(71, Severity::Critical), (72, Severity::Critical)]);
    assert_eq!(pids("PROC-INPUT-READER"), [(74, Severity::High)]);
    assert_eq!(pids("DESK-INPUT-INJECT"), [(76, Severity::High)]);
    assert!(report.findings.iter().filter(|f| f.rule == "PROC-INPUT-READER").all(|f| f.evidence.contains("/home/anna/.cache/x/hook.so")));
}

#[test]
fn a_wallet_running_foreign_code_is_reported() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/80/maps", &map("r-xp", "/usr/lib/x86_64-linux-gnu/libc.so.6"));
    write(root, "/proc/81/maps", &map("r-xp", "/run/user/1000/hook.so"));
    let (cfg, sys) = (Config::default(), SysRoot::new(root));
    let ctx = ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, wallet_watch_secs: 0, privileged: true, processes: &[] };
    let wallet = |pid: u32| ProcInfo { pid, exe: Some("/usr/bin/ksecretd".into()), ..ProcInfo::default() };
    assert!(judge_holder(&ctx, 1000, "org.freedesktop.secrets", &wallet(80)).is_none());
    let found = judge_holder(&ctx, 1000, "org.freedesktop.secrets", &wallet(81)).expect("reported");
    assert_eq!(found.severity, Severity::High);
    assert!(found.evidence.contains("/run/user/1000/hook.so"));
    assert!(!wallet(81).is_clean_program(&ctx, &["ksecretd"]) && wallet(80).is_clean_program(&ctx, &["ksecretd"]));
}

#[test]
fn programs_that_may_attach_to_each_other_are_pointed_out() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/sys/kernel/yama/ptrace_scope", "0\n");
    let found = |report: Report| report.findings.into_iter().filter(|f| f.rule == "KERN-PTRACE-SCOPE").map(|f| (f.severity, f.description)).collect::<Vec<_>>();
    let open = found(scan(root, &[ModuleId::Kernel]));
    assert_eq!(open.len(), 1);
    assert!(open[0].0 == Severity::Low && open[0].1.contains("kernel.yama.ptrace_scope = 1") && open[0].1.contains("/etc/sysctl.d/"));
    write(root, "/proc/sys/kernel/yama/ptrace_scope", "1\n");
    assert!(found(scan(root, &[ModuleId::Kernel])).is_empty());
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
