//! Code that handles your keys: programs GnuPG is told to run, PKCS#11 libraries that SSH,
//! browsers and VPNs load (p11-kit, NSS, SSH and OpenVPN settings), and libraries from odd
//! places inside running key programs.

use super::{record, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_command, clip, max_severity, reasons, risky_home_place, shq};
use crate::modules::{Collector, ScanCtx};
use crate::pkgverify::owned_paths;
use std::collections::BTreeSet;

type Homes = [(String, u32, String)];

/// A file that names a program or library: where it is said and what it names.
#[derive(Debug, Clone, PartialEq)]
pub struct Named {
    pub file: String,
    pub line: String,
    pub target: String,
}

fn named(file: &str, line: &str, target: &str) -> Named {
    Named { file: file.to_string(), line: line.trim().to_string(), target: target.trim().trim_matches('"').to_string() }
}

/// GnuPG options that name a program.
pub fn gpg_programs(text: &str) -> Vec<(String, String)> {
    const OPTIONS: [&str; 8] = ["pinentry-program", "scdaemon-program", "tpm2daemon-program", "dirmngr-program", "agent-program", "pcsc-driver", "exec-path", "photo-viewer"];
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let (option, value) = l.split_once(char::is_whitespace)?;
            OPTIONS.contains(&option).then(|| (option.to_string(), value.trim().trim_matches('"').to_string()))
        })
        .collect()
}

/// The `module:` and `remote:` lines of a p11-kit module file.
pub fn p11_module(text: &str) -> (Option<String>, Option<String>) {
    let value = |key: &str| text.lines().map(str::trim).filter_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_string()).find(|v| !v.is_empty());
    (value("module:"), value("remote:"))
}

/// `library=` lines of an NSS `pkcs11.txt` (Firefox, Chromium, Thunderbird).
pub fn nss_libraries(text: &str) -> Vec<String> {
    text.lines().filter_map(|l| l.trim().strip_prefix("library=")).filter(|v| !v.is_empty()).map(String::from).collect()
}

/// SSH and OpenVPN settings that load a PKCS#11 or security key library.
pub fn loaded_libraries(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#') && !l.starts_with(';'))
        .filter_map(|l| {
            let (key, value) = l.split_once([' ', '\t', '='])?;
            let key = key.to_ascii_lowercase();
            let value = value.trim_start_matches([' ', '=']).trim().trim_matches('"');
            (["pkcs11provider", "securitykeyprovider", "pkcs11-providers"].contains(&key.as_str()) && !["", "none", "internal"].contains(&value)).then(|| value.split_whitespace().next().unwrap_or(value).to_string())
        })
        .collect()
}

/// Where a library or program named without a folder is looked for.
fn full_path(ctx: &ScanCtx, target: &str, home: &str) -> String {
    let expanded = ["~/", "$HOME/", "%d/", "${HOME}/"].iter().find_map(|p| target.strip_prefix(p)).map(|r| format!("{home}/{r}"));
    let target = expanded.unwrap_or_else(|| target.to_string());
    if target.starts_with('/') {
        return target;
    }
    ["/usr/lib/x86_64-linux-gnu/pkcs11", "/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu/pkcs11", "/usr/bin"]
        .iter()
        .map(|d| format!("{d}/{target}"))
        .find(|p| ctx.sys.exists(p))
        .unwrap_or(target)
}

/// How worrying a named program or library is: (severity, why). `None` for packaged ones.
fn judge_target(ctx: &ScanCtx, path: &str, packaged: bool) -> Option<(Severity, &'static str)> {
    if ctx.cfg.is_temp_path(path) || risky_home_place(path, ctx.cfg).is_some() {
        Some((Severity::High, "it lies in a temporary, download, cache or hidden folder"))
    } else if path.starts_with("/home/") || path.starts_with("/root/") {
        Some((Severity::Medium, "it lies in a home folder, where it can be changed without root"))
    } else if !packaged && path.starts_with('/') {
        Some((Severity::Medium, "no package installed it"))
    } else {
        None
    }
}

fn report(ctx: &ScanCtx, col: &mut Collector, rule: &str, what: &str, found: Vec<(Named, String)>, text: &str) {
    let has_dpkg = !ctx.sys.dir_names("/var/lib/dpkg/info").is_empty();
    let targets: Vec<String> = found.iter().map(|f| f.1.clone()).collect();
    let owned = owned_paths(ctx.sys, &targets);
    for (n, path) in found {
        let Some((severity, why)) = judge_target(ctx, &path, !has_dpkg || owned.contains(&path)) else { continue };
        col.push(
            Finding::new(severity, MODULE, rule, format!("{what}: {}", crate::procinfo::basename(&path)))
                .evidence(format!("{}\n{}\n{path}: {why}", n.file, clip(&n.line, 300)))
                .description(text.to_string())
                .verify(format!("cat {}", shq(&n.file)))
                .verify(format!("ls -l {}; dpkg -S {}", shq(&path), shq(&path))),
        );
    }
}

fn check_gnupg(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let mut found = Vec::new();
    for (_, _, home) in homes {
        for file in ["gpg-agent.conf", "gpg.conf", "scdaemon.conf", "dirmngr.conf"] {
            let path = format!("{home}/.gnupg/{file}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            for (option, value) in gpg_programs(&text) {
                let target = full_path(ctx, value.split_whitespace().next().unwrap_or(""), home);
                found.push((named(&path, &format!("{option} {value}"), &value), target));
            }
        }
    }
    report(ctx, col, "PERS-GPG-PROGRAM", "GnuPG is set to run a program", found, "GnuPG runs this program when it asks for your passphrase or uses your keys, so it can read both. Check that you set it.");
}

fn check_modules(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let mut found = Vec::new();
    let mut dirs: Vec<(String, String)> = ["/etc/pkcs11/modules", "/usr/share/p11-kit/modules", "/usr/local/share/p11-kit/modules"].iter().map(|d| (d.to_string(), String::new())).collect();
    dirs.extend(homes.iter().map(|(_, _, h)| (format!("{h}/.config/pkcs11/modules"), h.clone())));
    for (dir, home) in dirs {
        for name in ctx.sys.dir_names(&dir).into_iter().filter(|n| n.ends_with(".module")) {
            let path = format!("{dir}/{name}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            let (module, remote) = p11_module(&text);
            if let Some(module) = module {
                let target = full_path(ctx, &module, &home);
                found.push((named(&path, &format!("module: {module}"), &module), target));
            }
            // "remote:" starts a command that provides the keys
            if let Some(command) = remote {
                let issues = analyze_command(&command, ctx.cfg);
                let severity = max_severity(&issues).unwrap_or(Severity::Medium).max(if home.is_empty() { Severity::Medium } else { Severity::High });
                col.push(
                    Finding::new(severity, MODULE, "PERS-KEY-MODULE", format!("A key module runs a command: {name}"))
                        .evidence(format!("{path}\nremote: {}\n{}", clip(&command, 300), reasons(&issues)))
                        .description("Every program that uses key modules (browsers, SSH, VPNs) starts this command.")
                        .verify(format!("cat {}", shq(&path))),
                );
            }
        }
    }
    for (_, _, home) in homes {
        let mut databases = vec![format!("{home}/.pki/nssdb/pkcs11.txt")];
        for root in [".mozilla/firefox", ".config/mozilla/firefox", ".thunderbird"] {
            databases.extend(ctx.sys.dir_names(format!("{home}/{root}")).into_iter().map(|p| format!("{home}/{root}/{p}/pkcs11.txt")));
        }
        for path in databases {
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            for library in nss_libraries(&text) {
                let target = full_path(ctx, &library, home);
                found.push((named(&path, &format!("library={library}"), &library), target));
            }
        }
    }
    let mut settings: Vec<(String, String)> = vec![("/etc/ssh/ssh_config".into(), String::new())];
    for dir in ["/etc/ssh/ssh_config.d", "/etc/openvpn", "/etc/openvpn/client", "/etc/openvpn/server"] {
        settings.extend(ctx.sys.dir_names(dir).into_iter().filter(|n| n.ends_with(".conf") || n.ends_with(".ovpn")).map(|n| (format!("{dir}/{n}"), String::new())));
    }
    settings.extend(homes.iter().map(|(_, _, h)| (format!("{h}/.ssh/config"), h.clone())));
    for (path, home) in settings {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        for library in loaded_libraries(&text) {
            let target = full_path(ctx, &library, &home);
            found.push((named(&path, &library, &library), target));
        }
    }
    report(ctx, col, "PERS-KEY-MODULE", "A key library that programs load", found, "SSH, browsers and VPN programs load this library and hand it your keys and PINs. Smart card software installs such libraries; a planted one steals what passes through.");
}

/// Programs that hold keys or ask for passwords.
const KEY_PROGRAMS: [&str; 14] = ["ssh", "ssh-agent", "ssh-add", "sshd", "gpg", "gpg2", "gpg-agent", "scdaemon", "openvpn", "sudo", "su", "gnome-keyring-daemon", "gnome-keyring-d", "ksecretd"];

/// Libraries in a `/proc/<pid>/maps` listing that come from temporary or home folders.
pub fn odd_libraries(maps: &str) -> Vec<String> {
    let mut out = BTreeSet::new();
    for line in maps.lines() {
        // address perms offset dev inode path
        let Some(at) = line.find('/') else { continue };
        let path = line[at..].trim_end_matches(" (deleted)");
        let library = path.ends_with(".so") || path.contains(".so.");
        if library && ["/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/root/"].iter().any(|p| path.starts_with(p)) && !path.starts_with("/tmp/.mount_") {
            out.insert(line[at..].to_string());
        }
    }
    out.into_iter().collect()
}

pub(crate) fn check_loaded(ctx: &ScanCtx, col: &mut Collector) {
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread()) {
        let name = p.display_name();
        // here a name picks what to look at, so every name counts: a library inside a key
        // program could rename the process to get out of sight
        if !p.candidate_names().iter().any(|n| KEY_PROGRAMS.contains(&n.as_str())) {
            continue;
        }
        let Ok(maps) = ctx.sys.read_string(format!("/proc/{}/maps", p.pid)) else { continue };
        let odd = odd_libraries(&maps);
        if !odd.is_empty() {
            col.push(
                Finding::new(Severity::High, crate::modules::proc_audit::MODULE, "PROC-KEY-LIBRARY", format!("{name} has loaded a library from an odd place"))
                    .evidence(format!("PID {} UID {} exe={}\n{}", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&odd.join("\n"), 700)))
                    .description("A program that handles keys or passwords runs code from a temporary or home folder. Unless you built it yourself, treat your keys and passwords as read.")
                    .verify(format!("grep -E '/(tmp|home|shm)/' /proc/{}/maps", p.pid)),
            );
        }
    }
}

/// GnuPG settings and key libraries (running key programs are checked by proc_audit).
pub fn check_keys(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    check_gnupg(ctx, col, homes);
    check_modules(ctx, col, homes);
}
