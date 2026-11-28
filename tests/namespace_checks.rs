//! The paths in /proc/<pid>/exe and maps are those of the process's own mount namespace, which
//! any user can arrange with bwrap. The files are compared by what the kernel knows of them.
//! (`scripts/namespace-test.sh` tries the same with real namespaces.)

use scanner::config::Config;
use scanner::modules::secrets::judge_reader;
use scanner::modules::wallet::judge_holder;
use scanner::modules::{proc_audit, Collector, ScanCtx};
use scanner::mounts::{examine, executable_mappings, Mounts};
use scanner::procinfo::{browser_module_of, Account, ProcInfo};
use scanner::{Finding, Severity, SysRoot};
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

/// The same file under a second name, as a bind mount shows it.
fn same_file(root: &Path, from: &str, to: &str) {
    let to = root.join(to.trim_start_matches('/'));
    fs::create_dir_all(to.parent().expect("parent")).expect("mkdir");
    fs::hard_link(root.join(from.trim_start_matches('/')), to).expect("hard link");
}

/// A `/proc/<pid>/maps` line for the file at `real`, shown as `shown`.
fn map(root: &Path, real: &str, shown: &str) -> String {
    let m = fs::metadata(root.join(real.trim_start_matches('/'))).expect("metadata");
    let (major, minor) = (rustix::fs::major(m.dev()), rustix::fs::minor(m.dev()));
    format!("7f0000000000-7f0000001000 r-xp 00000000 {major:02x}:{minor:02x} {} {shown}\n", m.ino())
}

/// The namespaces of a process: its mount namespace and its user namespace.
fn spaces(root: &Path, who: &str, mount: u32, user: u32) {
    link(root, &format!("/proc/{who}/ns/mnt"), &format!("mnt:[{mount}]"));
    link(root, &format!("/proc/{who}/ns/user"), &format!("user:[{user}]"));
}

/// A process that shows some path as its program while the file at `real` runs (a test folder
/// has no magic links, so /proc/<pid>/exe is a second name of that file).
fn process(root: &Path, pid: u32, real: &str, user_namespace: u32) {
    spaces(root, &pid.to_string(), 100 + pid, user_namespace);
    same_file(root, real, &format!("/proc/{pid}/exe"));
}

fn host(root: &Path) {
    spaces(root, "self", 1, 1);
    spaces(root, "1", 1, 1);
    write(root, "/usr/bin/ssh-agent", "the real one");
    write(root, "/usr/lib/libcrypto.so.3", "the real library");
    write(root, "/home/anna/x/impostor", "another program");
}

fn judged(root: &Path, pid: u32, path: &str) -> Option<Mounts> {
    examine(&SysRoot::new(root), pid, path)
}

#[test]
fn a_program_is_the_file_that_runs_not_the_path_it_shows() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    host(root);
    let agent = "/usr/bin/ssh-agent";
    // in the host's namespace paths mean what they say
    spaces(root, "10", 1, 1);
    assert_eq!(judged(root, 10, agent), None);
    // the installed file in a namespace of one's own
    process(root, 11, agent, 9);
    let honest = judged(root, 11, agent).expect("own namespace");
    assert!(honest.user_made && honest.claimed.is_none(), "{honest:?}");
    // another file at its path, made without root and made by root
    process(root, 12, "/home/anna/x/impostor", 9);
    let posing = judged(root, 12, agent).expect("own namespace");
    assert!(posing.user_made && posing.installed_here && !posing.own_flatpak);
    assert_eq!(posing.claimed.as_deref(), Some(agent));
    process(root, 13, "/home/anna/x/impostor", 1);
    let contained = judged(root, 13, agent).expect("own namespace");
    assert!(!contained.user_made && contained.claimed.as_deref() == Some(agent));
    // a file of one's own does not turn into the installed one by being deleted
    let upgraded = judged(root, 12, &format!("{agent} (deleted)")).expect("own namespace");
    assert_eq!(upgraded.claimed.as_deref(), Some(agent));
    // a path this computer has nothing at
    process(root, 14, "/home/anna/x/impostor", 9);
    let nowhere = judged(root, 14, "/app/extra/chrome").expect("own namespace");
    assert!(!nowhere.installed_here && nowhere.claimed.is_some());
}

#[test]
fn flatpaks_of_the_system_count_and_those_of_one_person_do_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    host(root);
    let system = "/var/lib/flatpak/app/org.example.App/x86_64/stable/abc/files";
    let own = "/home/anna/.local/share/flatpak/app/org.example.App/x86_64/stable/abc/files";
    let old = "/var/lib/flatpak/.removed/abc-XYZ/files";
    write(root, &format!("{system}/bin/app"), "the app");
    write(root, &format!("{own}/bin/app"), "the app, installed for anna");
    write(root, &format!("{old}/bin/app"), "the version before the update");
    let info = |base: &str| format!("[Application]\nname=org.example.App\n[Instance]\napp-path={base}\n");
    let ask = |pid: u32, real: &str, said: &str| {
        process(root, pid, real, 9);
        write(root, &format!("/proc/{pid}/root/.flatpak-info"), &info(said));
        judged(root, pid, "/app/bin/app").expect("own namespace")
    };
    let found = ask(20, &format!("{system}/bin/app"), system);
    assert!(found.system_flatpak && found.claimed.is_none(), "{found:?}");
    // updated while it ran: its files were moved aside
    let moved = ask(21, &format!("{old}/bin/app"), system);
    assert!(moved.system_flatpak && moved.claimed.is_none(), "{moved:?}");
    let personal = ask(22, &format!("{own}/bin/app"), own);
    assert!(personal.own_flatpak && !personal.system_flatpak && personal.claimed.is_some(), "{personal:?}");
    // a sandbox that says it is the system's while another file runs, also through ".."
    for (pid, said) in [(23, system.to_string()), (24, format!("{system}/../../../../../../../../../home/anna/x"))] {
        let lie = ask(pid, "/home/anna/x/impostor", &said);
        assert!(!lie.system_flatpak && !lie.own_flatpak && lie.claimed.is_some(), "{lie:?}");
    }
    // what the sandbox writes about itself is only read when it is a plain file
    process(root, 25, &format!("{system}/bin/app"), 9);
    write(root, "/tmp/info", &info(system));
    link(root, "/proc/25/root/.flatpak-info", root.join("tmp/info").to_str().expect("path"));
    assert!(judged(root, 25, "/app/bin/app").expect("own namespace").claimed.is_some());
}

#[test]
fn libraries_in_a_namespace_must_be_the_files_their_paths_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    host(root);
    write(root, "/home/anna/x/library", "another library");
    let (agent, crypto) = ("/usr/bin/ssh-agent", "/usr/lib/libcrypto.so.3");
    // honest: the host's library shows at its path
    process(root, 30, agent, 9);
    write(root, "/proc/30/maps", &(map(root, agent, agent) + &map(root, crypto, crypto)));
    same_file(root, crypto, "/proc/30/root/usr/lib/libcrypto.so.3");
    same_file(root, agent, "/proc/30/root/usr/bin/ssh-agent");
    // another file mounted over it
    process(root, 31, agent, 9);
    write(root, "/proc/31/maps", &(map(root, agent, agent) + &map(root, "/home/anna/x/library", crypto)));
    same_file(root, "/home/anna/x/library", "/proc/31/root/usr/lib/libcrypto.so.3");
    // … and the real one mounted back on top afterwards
    process(root, 32, agent, 9);
    write(root, "/proc/32/maps", &map(root, "/home/anna/x/library", crypto));
    same_file(root, crypto, "/proc/32/root/usr/lib/libcrypto.so.3");
    // a deleted file that cannot be looked at proves nothing
    process(root, 33, agent, 9);
    write(root, "/proc/33/maps", &map(root, "/home/anna/x/library", &format!("{crypto} (deleted)")));
    // root may ask for the mapped file itself: here it is another one than the path names
    process(root, 34, agent, 9);
    write(root, "/proc/34/maps", &map(root, crypto, crypto));
    same_file(root, "/home/anna/x/library", "/proc/34/map_files/7f0000000000-7f0000001000");
    let sys = SysRoot::new(root);
    let foreign = |pid: u32| {
        let p = ProcInfo { pid, exe: Some(agent.into()), mounts: examine(&sys, pid, agent), ..ProcInfo::default() };
        p.foreign_code_strict(&sys).expect("maps")
    };
    assert_eq!(foreign(30), Vec::<String>::new());
    for pid in [31, 32, 34] {
        assert_eq!(foreign(pid), [crypto], "{pid}");
    }
    assert_eq!(foreign(33), [format!("{crypto} (deleted)")]);
    // the maps lines are read as the kernel writes them
    let lines = "7f1-7f2 r-xp 00001000 103:02 29235388   /usr/lib/a b.so (deleted)\n7f3-7f4 rw-p 00000000 103:02 5 /usr/lib/data\n7f5-7f6 r-xp 00000000 00:00 0 [vdso]\n";
    let read: Vec<_> = executable_mappings(lines).map(|m| (m.range, m.device, m.inode, m.path)).collect();
    assert_eq!(read, [("7f1-7f2", (0x103, 2), 29235388, "/usr/lib/a b.so (deleted)")]);
}

/// A process as `read_proc` gives it when its program file is not the one at `claimed`.
fn posing(pid: u32, claimed: &str, user_made: bool, own_flatpak: bool) -> ProcInfo {
    let mounts = Mounts { namespace: format!("mnt:[{}]", 100 + pid), user_made, own_flatpak, claimed: Some(claimed.into()), installed_here: !claimed.starts_with("/app/"), ..Mounts::default() };
    // made without root, the path shown is the one that reaches the real file
    let shown = if user_made { format!("/proc/{pid}/root{claimed}") } else { claimed.to_string() };
    ProcInfo { pid, ppid: 1, uid: 1000, state: 'S', exe: Some(shown), mounts: Some(mounts), ..ProcInfo::default() }
}

fn anna() -> Vec<Account> {
    vec![Account { name: "anna".into(), uid: 1000, gid: 1000, home: "/home/anna".into(), shell: "/bin/bash".into() }]
}

#[test]
fn a_posing_program_earns_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/40/maps", "7f0-7f1 r-xp 00000000 08:01 42 /usr/lib/x86_64-linux-gnu/libc.so.6\n");
    let (cfg, sys) = (Config::default(), SysRoot::new(root));
    let ctx = ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, wallet_watch_secs: 0, privileged: true, processes: &[], accounts: anna() };
    for user_made in [true, false] {
        let firefox = posing(40, "/usr/lib/firefox-esr/firefox-esr", user_made, false);
        assert!(!firefox.is_clean_program(&ctx, &["firefox-esr"]), "{user_made}");
        assert!(browser_module_of(&posing(40, "/opt/google/chrome/chrome", user_made, false), &ctx.accounts).is_none());
        let found = judge_holder(&ctx, 1000, "org.freedesktop.secrets", &posing(40, "/usr/bin/ksecretd", user_made, false)).expect("reported");
        assert_eq!(found.severity, Severity::High);
        assert!(found.title.contains("not the installed one"), "{}", found.title);
    }
    // made without root, no path or name counts at all
    let firefox = posing(40, "/usr/lib/firefox-esr/firefox-esr", true, false);
    assert!(!firefox.is_program(&["firefox-esr"]) && firefox.program_name().is_none());
    assert_ne!(judge_reader(&cfg, "browser passwords or cookies", firefox.exe_path().expect("exe")), None);
    // the real one still counts
    let chrome = ProcInfo { pid: 40, uid: 1000, exe: Some("/opt/google/chrome/chrome".into()), ..ProcInfo::default() };
    assert!(browser_module_of(&chrome, &ctx.accounts).is_some() && chrome.is_clean_program(&ctx, &["chrome"]));
}

/// Run the process checks over these processes.
fn audit(root: &Path, processes: &[ProcInfo]) -> Vec<Finding> {
    let (cfg, sys) = (Config::default(), SysRoot::new(root));
    let ctx = ScanCtx { sys: &sys, cfg: &cfg, deep_pid_scan: false, wallet_watch_secs: 0, privileged: true, processes, accounts: anna() };
    let mut col = Collector::default();
    proc_audit::run(&ctx, &mut col);
    col.findings
}

#[test]
fn posing_programs_are_reported_and_bubblewrap_does_not_explain_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    host(root);
    let cookies = "/home/anna/.mozilla/firefox/x.default/cookies.sqlite";
    let bwrap = ProcInfo { pid: 2000, ppid: 1, uid: 1000, state: 'S', exe: Some("/usr/bin/bwrap".into()), ..ProcInfo::default() };
    let under_bwrap = |mut p: ProcInfo| {
        p.ppid = 2000;
        spaces(root, &p.pid.to_string(), 100 + p.pid, 9);
        p
    };
    let processes = [
        bwrap,
        under_bwrap(posing(70, "/usr/lib/firefox-esr/firefox-esr", true, false)),
        under_bwrap(posing(71, "/usr/bin/ls", true, false)),
        // an honest installed program under bubblewrap, and one from a home folder
        under_bwrap(ProcInfo { pid: 72, uid: 1000, state: 'S', exe: Some("/usr/bin/yes".into()), ..ProcInfo::default() }),
        under_bwrap(ProcInfo { pid: 73, uid: 1000, state: 'S', exe: Some("/home/anna/x/miner".into()), ..ProcInfo::default() }),
        // a rootless container, Flatpaks of one person, and a container made by root
        posing(80, "/usr/bin/ls", true, false),
        posing(81, "/app/bin/firefox", true, true),
        posing(82, "/app/bin/some-game", true, true),
        posing(83, "/usr/bin/ssh-agent", false, false),
    ];
    write(root, "/proc/80/cgroup", "0::/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-1.scope\n");
    link(root, "/proc/70/fd/3", cookies);
    let found = audit(root, &processes);
    let of = |rule: &str, pid: u32| found.iter().find(|f| f.rule == rule && f.evidence.contains(&format!("PID {pid} "))).map(|f| f.severity);
    assert_eq!(of("PROC-FAKE-PROGRAM", 70), Some(Severity::High));
    assert_eq!(of("PROC-FAKE-PROGRAM", 71), Some(Severity::High));
    assert_eq!(of("PROC-FAKE-PROGRAM", 80), Some(Severity::Low));
    assert_eq!(of("PROC-FAKE-PROGRAM", 81), Some(Severity::Medium));
    for pid in [72, 73, 82, 83] {
        assert_eq!(of("PROC-FAKE-PROGRAM", pid), None, "{pid}");
    }
    // posing as the browser while holding its cookies weighs the most
    assert_eq!(of("PROC-SECRET-ACCESS", 70), Some(Severity::Critical));
    let spaces: String = found.iter().filter(|f| f.rule == "PROC-NAMESPACE").map(|f| f.evidence.as_str()).collect();
    for pid in [70, 71, 73] {
        assert!(spaces.contains(&format!("PID {pid} ")), "{pid}: {spaces}");
    }
    assert!(!spaces.contains("PID 72 "), "{spaces}");
}
