//! File checks beyond permissions (part of `fs_perms`): programs in temporary folders, file
//! capabilities, locked (immutable) files and system programs that differ from their package.

use super::common::{clip, mode_string, shq};
use super::fs_perms::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::pkgverify::{self, Verdict};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::SystemTime;
use walkdir::WalkDir;

// ---------------------------------------------------------------- capabilities

const CAP_NAMES: [&str; 41] = [
    "cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner", "cap_fsetid", "cap_kill",
    "cap_setgid", "cap_setuid", "cap_setpcap", "cap_linux_immutable", "cap_net_bind_service",
    "cap_net_broadcast", "cap_net_admin", "cap_net_raw", "cap_ipc_lock", "cap_ipc_owner",
    "cap_sys_module", "cap_sys_rawio", "cap_sys_chroot", "cap_sys_ptrace", "cap_sys_pacct",
    "cap_sys_admin", "cap_sys_boot", "cap_sys_nice", "cap_sys_resource", "cap_sys_time",
    "cap_sys_tty_config", "cap_mknod", "cap_lease", "cap_audit_write", "cap_audit_control",
    "cap_setfcap", "cap_mac_override", "cap_mac_admin", "cap_syslog", "cap_wake_alarm",
    "cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf", "cap_checkpoint_restore",
];

/// Capabilities that are enough to become root.
const ROOT_CAPS: [&str; 13] = [
    "cap_chown", "cap_dac_override", "cap_dac_read_search", "cap_fowner", "cap_setgid", "cap_setuid",
    "cap_setpcap", "cap_sys_module", "cap_sys_rawio", "cap_sys_ptrace", "cap_sys_admin", "cap_setfcap", "cap_bpf",
];

/// Programs that can run any command, so a root capability on them is a root shell.
const ANY_COMMAND: [&str; 24] = [
    "sh", "bash", "dash", "zsh", "ksh", "fish", "busybox", "python", "perl", "ruby", "php", "lua", "node",
    "awk", "gawk", "find", "vim", "vi", "nano", "tar", "env", "gdb", "socat", "openssl",
];

/// "python3.13" → "python", "bash" → "bash".
pub(crate) fn runs_any_command(path: &str) -> bool {
    let name = crate::procinfo::basename(path);
    let stem = name.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-');
    ANY_COMMAND.contains(&name) || ANY_COMMAND.contains(&stem)
}

/// Decode the `security.capability` attribute (struct vfs_cap_data) into capability names.
pub fn parse_capabilities(data: &[u8]) -> Vec<&'static str> {
    let word = |i: usize| -> u32 {
        data.get(i * 4..i * 4 + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0)
    };
    let revision = word(0) >> 24;
    if revision == 0 || data.len() < 12 {
        return Vec::new();
    }
    let low = word(1) | word(2); // permitted | inheritable
    let high = if revision >= 2 { word(3) | word(4) } else { 0 };
    let bits = u64::from(low) | (u64::from(high) << 32);
    CAP_NAMES.iter().enumerate().filter(|(i, _)| bits & (1u64 << i) != 0).map(|(_, n)| *n).collect()
}

fn read_capabilities(real: &Path) -> Vec<&'static str> {
    let mut buf = [0u8; 64];
    match rustix::fs::lgetxattr(real, "security.capability", &mut buf) {
        Ok(n) => parse_capabilities(&buf[..n.min(buf.len())]),
        Err(_) => Vec::new(),
    }
}

/// Assess one file that has capabilities.
pub fn judge_capabilities(ctx: &ScanCtx, path: &str, caps: &[&str], detail: &str, col: &mut Collector) {
    if caps.is_empty() {
        return;
    }
    let root_power = caps.iter().any(|c| ROOT_CAPS.contains(c));
    let risky_place = ctx.cfg.is_temp_path(path) || ["/home/", "/var/www/"].iter().any(|p| path.starts_with(p));
    let any_command = runs_any_command(path);
    let severity = if root_power && (any_command || risky_place) {
        Severity::Critical
    } else if risky_place {
        Severity::High
    } else if ctx.cfg.is_capability_allowed(path) {
        return;
    } else if root_power {
        Severity::High
    } else {
        Severity::Low
    };
    col.push(
        Finding::new(severity, MODULE, "FS-CAPABILITY", format!("File with special rights (capabilities): {path}"))
            .evidence(format!("{path} {} {detail}", caps.join(",")))
            .description(if root_power {
                "Capabilities give a program parts of root's power without SUID. These ones are enough to take over the machine, so they are a common hidden backdoor. If you do not know why the file has them, remove them with setcap -r."
            } else {
                "The program has extra rights (capabilities). Check that it comes from a package and is intended, then add it to allowed_capability_files."
            })
            .verify(format!("/usr/sbin/getcap {}   # package libcap2-bin", shq(path)))
            .verify(format!("dpkg -S {}", shq(path))),
    );
}

pub(crate) fn check_capabilities(ctx: &ScanCtx, col: &mut Collector, path: &str, real: &Path, meta: &fs::Metadata) {
    let caps = read_capabilities(real);
    if !caps.is_empty() {
        let detail = format!("mode {} owner {}:{}", mode_string(meta.mode()), meta.uid(), meta.gid());
        judge_capabilities(ctx, path, &caps, &detail, col);
    }
}

// ---------------------------------------------------------------- immutable files

const LOCK_DIRS: [&str; 7] = ["/etc", "/usr/bin", "/usr/sbin", "/usr/lib/systemd", "/usr/lib/x86_64-linux-gnu/security", "/root", "/var/spool/cron"];

/// Is this a place where a locked (immutable) file is worth knowing about?
pub fn lock_matters(path: &str) -> bool {
    path.contains("/.ssh/") || LOCK_DIRS.iter().any(|d| path.starts_with(&format!("{d}/")))
}

fn is_immutable(real: &Path) -> bool {
    use rustix::fs::{IFlags, OFlags};
    let flags = (OFlags::NOFOLLOW | OFlags::NONBLOCK).bits() as i32;
    let Ok(file) = fs::OpenOptions::new().read(true).custom_flags(flags).open(real) else { return false };
    rustix::fs::ioctl_getflags(&file).map(|f| f.contains(IFlags::IMMUTABLE)).unwrap_or(false)
}

pub fn immutable_finding(path: &str) -> Finding {
    // some people lock resolv.conf on purpose, so their DNS setting is not overwritten
    let severity = if path == "/etc/resolv.conf" { Severity::Low } else { Severity::High };
    Finding::new(severity, MODULE, "FS-IMMUTABLE", format!("Locked (immutable) file: {path}"))
        .evidence(format!("{path} has the immutable attribute (chattr +i)"))
        .description("Not even root can change or delete the file until the lock is removed. Debian does not lock files; attackers do it so their keys, jobs and programs cannot be cleaned away. If you locked it yourself, hide this finding.")
        .verify(format!("lsattr -d {}", shq(path)))
        .verify(format!("dpkg -S {}", shq(path)))
}

pub(crate) fn check_immutable(col: &mut Collector, path: &str, real: &Path) {
    if lock_matters(path) && is_immutable(real) {
        col.push(immutable_finding(path));
    }
}

// ---------------------------------------------------------------- programs in temporary folders

const TEMP_DEPTH: usize = 6;
const TEMP_LIMIT: usize = 50_000;

/// A program found in a temporary folder.
pub struct TempFile {
    pub path: String,
    pub real: std::path::PathBuf,
    pub meta: fs::Metadata,
}

/// Mount points that must not be walked (AppImages, portals, network shares).
fn foreign_mounts(ctx: &ScanCtx) -> HashSet<String> {
    ctx.sys
        .read_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace().skip(1);
            let (point, kind) = (f.next()?, f.next()?);
            (kind.starts_with("fuse") || kind.starts_with("nfs") || kind == "cifs" || kind == "squashfs").then(|| point.to_string())
        })
        .collect()
}

/// "ELF program", "script" or `None` for ordinary data.
fn program_kind(real: &Path) -> Option<&'static str> {
    let mut head = [0u8; 4];
    let n = fs::File::open(real).ok()?.read(&mut head).ok()?;
    if n == 4 && head == *b"\x7fELF" {
        Some("ELF program")
    } else if n >= 2 && head.starts_with(b"#!") {
        Some("script")
    } else {
        None
    }
}

/// Walk the temporary folders. Executable programs are reported (grouped per folder), and every
/// SUID/SGID or capability file is returned/assessed, also when /tmp is a memory file system
/// that the main walk does not visit.
pub(crate) fn check_temp_programs(ctx: &ScanCtx, col: &mut Collector) -> Vec<TempFile> {
    let skip = foreign_mounts(ctx);
    let mut special = Vec::new();
    let mut seen_roots = HashSet::new();
    let mut seen_files = 0usize;
    // top folder below a temporary directory → (severity, files)
    let mut groups: BTreeMap<String, (Severity, Vec<String>)> = BTreeMap::new();
    for root in &ctx.cfg.temp_dirs {
        let real_root = ctx.sys.path(root);
        let Ok(canonical) = fs::canonicalize(&real_root) else { continue };
        if !seen_roots.insert(canonical) {
            continue;
        }
        let walker = WalkDir::new(&real_root)
            .follow_links(false)
            .max_depth(TEMP_DEPTH)
            .into_iter()
            .filter_entry(|e| !skip.contains(&ctx.sys.display(e.path())));
        for entry in walker.filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            seen_files += 1;
            if seen_files > TEMP_LIMIT {
                col.note(format!("Only the first {TEMP_LIMIT} files in the temporary folders were checked"));
                break;
            }
            let Ok(meta) = entry.metadata() else { continue };
            let path = ctx.sys.display(entry.path());
            let executable = meta.mode() & 0o111 != 0;
            if executable {
                check_capabilities(ctx, col, &path, entry.path(), &meta);
            }
            if executable {
                if let Some(kind) = program_kind(entry.path()) {
                    let below = path.strip_prefix(&format!("{root}/")).unwrap_or(&path);
                    let hidden = below.split('/').any(|part| part.starts_with('.'));
                    let severity = if root.ends_with("/shm") || (hidden && kind == "ELF program") {
                        Severity::High
                    } else if kind == "ELF program" {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };
                    let top = format!("{root}/{}", below.split('/').next().unwrap_or(below));
                    let group = groups.entry(top).or_insert((severity, Vec::new()));
                    group.0 = group.0.max(severity);
                    group.1.push(format!("{path} ({kind}, mode {}, owner {}, {} bytes)", mode_string(meta.mode()), meta.uid(), meta.size()));
                }
            }
            if meta.mode() & 0o6000 != 0 {
                special.push(TempFile { path, real: entry.path().to_path_buf(), meta });
            }
        }
    }
    let total = groups.len();
    for (top, (severity, mut files)) in groups.into_iter().take(40) {
        files.sort();
        let count = files.len();
        let more = count.saturating_sub(10);
        files.truncate(10);
        if more > 0 {
            files.push(format!("… and {more} more"));
        }
        col.push(
            Finding::new(severity, MODULE, "FS-TMP-EXEC", format!("Program file(s) in a temporary folder: {top}"))
                .evidence(clip(&files.join("\n"), 1500))
                .description("Programs do not normally live in temporary folders. Installers and developers put them there for a short time; malware does it because everyone may write there. Check what created them (owner and time) before you delete anything.")
                .verify(format!("ls -laR {}", shq(&top)))
                .verify(format!("find {} -type f -perm /111 -exec file {{}} +", shq(&top))),
        );
    }
    if total > 40 {
        col.note(format!("{} more temporary folders with programs were not listed (limit 40)", total - 40));
    }
    special
}

// ---------------------------------------------------------------- system programs

const SYSTEM_PROGRAMS: [&str; 24] = [
    "/usr/bin/su", "/usr/bin/sudo", "/usr/bin/login", "/usr/bin/passwd", "/usr/bin/ssh", "/usr/sbin/sshd",
    "/usr/lib/openssh/sshd-session", "/usr/lib/openssh/sshd-auth", "/usr/sbin/unix_chkpwd", "/usr/bin/ps",
    "/usr/bin/top", "/usr/bin/ls", "/usr/bin/ss", "/usr/bin/netstat", "/usr/bin/lsof", "/usr/bin/find",
    "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/systemctl", "/usr/bin/journalctl", "/usr/sbin/cron",
    "/usr/bin/dpkg", "/usr/sbin/insmod", "/usr/bin/kmod",
];

/// Compare the programs an attacker likes to replace (and every PAM module) with the
/// checksums their packages ship.
pub(crate) fn check_system_programs(ctx: &ScanCtx, col: &mut Collector) {
    if ctx.sys.dir_names("/var/lib/dpkg/info").is_empty() {
        return;
    }
    let is_file = |p: &str| fs::symlink_metadata(ctx.sys.path(p)).map(|m| m.is_file()).unwrap_or(false);
    let mut paths: Vec<String> = SYSTEM_PROGRAMS.iter().map(|p| p.to_string()).filter(|p| is_file(p)).collect();
    let pam_dir = "/usr/lib/x86_64-linux-gnu/security";
    paths.extend(ctx.sys.dir_names(pam_dir).into_iter().map(|n| format!("{pam_dir}/{n}")).filter(|p| p.ends_with(".so") && is_file(p)));
    let mut verdicts: Vec<(String, Verdict)> = pkgverify::verify_paths(ctx.sys, &paths, SystemTime::UNIX_EPOCH).into_iter().collect();
    verdicts.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, verdict) in verdicts {
        match verdict {
            Verdict::Differs { package } => col.push(
                Finding::new(Severity::Critical, MODULE, "FS-SYSTEM-CHANGED", format!("System program differs from its package: {path}"))
                    .evidence(format!("{path}\npackage {package}: the content does not match the checksum the package ships"))
                    .description("This program handles logins or shows what runs on the machine, and it is not the file Debian installed. A replaced version can steal passwords or hide an attacker. Investigate, then reinstall the package.")
                    .verify(format!("dpkg --verify {}", shq(package.split(':').next().unwrap_or(&package))))
                    .verify(format!("apt-get install --reinstall {}", shq(package.split(':').next().unwrap_or(&package)))),
            ),
            Verdict::NotPackaged if path.starts_with(pam_dir) => col.push(
                Finding::new(Severity::High, MODULE, "FS-SYSTEM-UNPACKAGED", format!("PAM module that no package installed: {path}"))
                    .evidence(path.clone())
                    .description("PAM modules take part in every login. One that no package owns was copied there by hand or by a program outside apt; a malicious one can accept a secret password or record yours.")
                    .verify(format!("dpkg -S {}", shq(&path)))
                    .verify(format!("grep -rn {} /etc/pam.d", shq(crate::procinfo::basename(&path)))),
            ),
            _ => {}
        }
    }
}
