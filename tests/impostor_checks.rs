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
use std::os::unix::fs::{symlink, MetadataExt};
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
    write(root, &format!("/proc/{pid}/maps"), &map("r-xp", "/usr/lib/x86_64-linux-gnu/libc.so.6"));
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
    // the list itself makes no exceptions
    assert_eq!(odd_libraries(&map("r-xp", "/memfd:JITCode:QtQml (deleted)")).len(), 1);
}

/// A context over a made-up root, for asking about single processes.
fn context<'a>(sys: &'a SysRoot, cfg: &'a Config) -> ScanCtx<'a> {
    ScanCtx { sys, cfg, deep_pid_scan: false, wallet_watch_secs: 0, privileged: true, processes: &[], accounts: scanner::procinfo::read_accounts(sys) }
}

#[test]
fn qt_compiler_memory_is_accepted_only_where_qml_is_compiled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let jit = map("r-xp", "/memfd:JITCode:QtQml (deleted)");
    let qml = map("r-xp", "/usr/lib/x86_64-linux-gnu/libQt6Qml.so.6.8.2");
    write(root, "/proc/1/maps", &(jit.clone() + &qml));
    // the same name without Qt, and with a library of one's own by Qt's name
    write(root, "/proc/2/maps", &jit);
    write(root, "/proc/3/maps", &(jit.clone() + &map("r-xp", "/home/anna/libQt6Qml.so.6")));
    // another memory file in plasmashell
    write(root, "/proc/4/maps", &(map("r-xp", "/memfd:stage2 (deleted)") + &qml));
    let (cfg, sys) = (Config::default(), SysRoot::new(root));
    let ctx = context(&sys, &cfg);
    let code = |pid: u32, exe: &str| {
        let p = ProcInfo { pid, exe: Some(exe.into()), ..ProcInfo::default() };
        (p.foreign_code(&ctx).expect("read").len(), p.foreign_code_strict(&sys).expect("read").len())
    };
    assert_eq!(code(1, "/usr/bin/plasmashell"), (0, 1));
    assert_eq!(code(1, "/usr/bin/kwin_wayland"), (0, 1));
    // any other Qt program, a copy in a home folder, key programs and wallets
    for exe in ["/usr/bin/some-qt-app", "/home/anna/plasmashell", "/usr/bin/ksecretd", "/usr/bin/kwalletd6", "/usr/bin/ssh"] {
        assert_eq!(code(1, exe), (1, 1), "{exe}");
    }
    assert_eq!(code(2, "/usr/bin/plasmashell"), (1, 1));
    assert_eq!(code(3, "/usr/bin/plasmashell").0, 2);
    assert_eq!(code(4, "/usr/bin/plasmashell").0, 1);
}

#[test]
fn what_cannot_be_seen_does_not_count_as_clean() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/5/maps", "");
    let (cfg, sys) = (Config::default(), SysRoot::new(root));
    let ctx = context(&sys, &cfg);
    // no maps file, and an empty one (the program is ending)
    for pid in [4, 5] {
        let p = ProcInfo { pid, exe: Some("/usr/bin/ksecretd".into()), ..ProcInfo::default() };
        assert_eq!(p.foreign_code(&ctx), None);
        assert!(!p.is_clean_program(&ctx, &["ksecretd"]));
        let found = judge_holder(&ctx, 1000, "org.freedesktop.secrets", &p).expect("reported");
        assert_eq!(found.severity, Severity::Medium, "not known to be tainted either");
        assert!(found.title.contains("cannot be checked") && found.evidence.contains("could not be read"));
    }
    // in the scan: the browser holding its cookies, unseen
    let cookies = "/home/anna/.mozilla/firefox/x.default/cookies.sqlite";
    impostor(root, 90, "/usr/lib/firefox-esr/firefox-esr", "firefox-esr", "");
    fs::remove_file(root.join("proc/90/maps")).expect("remove");
    link(root, "/proc/90/fd/3", cookies);
    let report = scan(root, &[ModuleId::ProcAudit]);
    let found: Vec<Severity> = report.findings.iter().filter(|f| f.rule == "PROC-SECRET-ACCESS").map(|f| f.severity).collect();
    assert_eq!(found, [Severity::High]);
}

#[test]
fn chromes_video_module_is_accepted_only_where_chrome_puts_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\nbo:x:1001:1001::/home/bo:/bin/bash\n");
    let cookies = "/home/anna/.config/google-chrome/Default/Cookies";
    let module = "/home/anna/.config/google-chrome/WidevineCdm/4.10.2891.0/_platform_specific/linux_x64/libwidevinecdm.so";
    write(root, module, "widevine");
    let libc = map("r-xp", "/usr/lib/x86_64-linux-gnu/libc.so.6");
    let process = |pid: u32, exe: &str, library: &str| {
        impostor(root, pid, exe, "chrome", "");
        link(root, &format!("/proc/{pid}/fd/3"), cookies);
        let mut line = map("r-xp", library);
        // the process holds the module itself: its file, seen from the process's root
        if library == module {
            let held = root.join(format!("proc/{pid}/root{module}"));
            fs::create_dir_all(held.parent().expect("parent")).expect("mkdir");
            fs::hard_link(root.join(module.trim_start_matches('/')), held).expect("hard link");
            let m = fs::metadata(root.join(module.trim_start_matches('/'))).expect("metadata");
            line = format!("7f0000000000-7f0000001000 r-xp 00000000 {:02x}:{:02x} {} {library}\n", rustix::fs::major(m.dev()), rustix::fs::minor(m.dev()), m.ino());
        }
        write(root, &format!("/proc/{pid}/maps"), &(libc.clone() + &line));
    };
    let chrome = "/opt/google/chrome/chrome";
    // the real case, also after an update removed the old file
    process(10, chrome, module);
    process(11, chrome, &format!("{module} (deleted)"));
    // anything else: another file name, another folder, no version, another user's or another
    // browser's profile, and another program
    process(20, chrome, &module.replace("libwidevinecdm.so", "libevil.so"));
    process(21, chrome, "/home/anna/.cache/WidevineCdm/4.10.2891.0/_platform_specific/linux_x64/libwidevinecdm.so");
    process(22, chrome, &module.replace("4.10.2891.0", "x"));
    process(23, chrome, &module.replace("4.10.2891.0", "4.1/../../.."));
    process(24, chrome, &module.replace("/home/anna", "/home/bo"));
    process(25, chrome, &module.replace("google-chrome/", "chromium/"));
    process(26, "/usr/lib/firefox-esr/firefox-esr", module);
    let report = scan(root, &[ModuleId::ProcAudit]);
    let mut reported: Vec<u32> = report.findings.iter().filter(|f| f.rule == "PROC-SECRET-ACCESS").map(|f| f.evidence[4..6].parse().expect("pid")).collect();
    reported.sort();
    assert_eq!(reported, [20, 21, 22, 23, 24, 25, 26]);
    // and the accepted module is shown
    let shown: Vec<_> = report.findings.iter().filter(|f| f.rule == "PROC-BROWSER-MODULE").collect();
    assert_eq!(shown.len(), 2, "{shown:?}");
    assert!(shown.iter().all(|f| f.severity == Severity::Info));
    assert!(shown.iter().any(|f| f.evidence.contains("sha256 ") && f.evidence.contains("PID 10")));
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
    let ctx = ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, wallet_watch_secs: 0, privileged: true, processes: &[], accounts: scanner::procinfo::read_accounts(&sys) };
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
