//! File checks beyond permissions (part of `fs_perms`): programs in temporary folders, file
//! capabilities, locked (immutable) files and system programs that differ from their package.

use super::common::{clip, mode_string, shq};
use super::fs_perms::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::pkgverify::{self, Verdict};
use md5::{Digest, Md5};
use std::collections::{BTreeMap, HashMap, HashSet};
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
pub(crate) fn program_kind(real: &Path) -> Option<&'static str> {
    let mut head = [0u8; 4];
    let n = crate::sys::open_plain_file(real).ok()?.read(&mut head).ok()?;
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
                // /run/user holds each desktop session's own files; scripts there are ordinary
                if let Some(kind) = program_kind(entry.path()).filter(|k| !(root == "/run/user" && *k == "script")) {
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

// ---------------------------------------------------------------- file times

const DAY: i64 = 86_400;

/// Folders in /etc where a backdated file would be hiding something.
const TIMED_ETC: [&str; 6] = ["/etc/cron", "/etc/systemd/system", "/etc/profile.d", "/etc/init.d", "/etc/ssh", "/etc/ld.so"];

/// Which package lists each wanted file: path → time the package's file list was written.
fn package_times(ctx: &ScanCtx, wanted: &HashSet<String>) -> HashMap<String, i64> {
    let mut out = HashMap::new();
    for file in ctx.sys.dir_names("/var/lib/dpkg/info") {
        if !file.ends_with(".list") {
            continue;
        }
        let list = format!("/var/lib/dpkg/info/{file}");
        let Ok(written) = fs::metadata(ctx.sys.path(&list)).map(|m| m.ctime()) else { continue };
        for line in ctx.sys.read_string(&list).unwrap_or_default().lines() {
            // before the "merged /usr" move packages listed /bin and /sbin
            let moved = ["/bin/", "/sbin/"].iter().any(|d| line.starts_with(d)).then(|| format!("/usr{line}"));
            for path in std::iter::once(line.to_string()).chain(moved) {
                if wanted.contains(&path) {
                    let time = out.entry(path).or_insert(written);
                    *time = (*time).max(written);
                }
            }
        }
    }
    out
}

/// Settings files that a package's install script copies from a template, keeping its dates.
const TEMPLATES: [(&str, &str); 1] = [("/etc/ssh/sshd_config", "/usr/share/openssh/sshd_config")];

/// A settings file that still is what the package put there: `ucf`, which manages such files,
/// recorded its checksum, or it equals the unchanged template it was copied from. An old date is
/// then the package's own.
fn kept_copy(ctx: &ScanCtx, path: &str) -> bool {
    let Ok(data) = ctx.sys.read_bytes(path) else { return false };
    let sum: String = Md5::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
    let recorded = ctx.sys.read_string("/var/lib/ucf/hashfile").is_ok_and(|t| t.lines().any(|l| l.split_once("  ").is_some_and(|(s, p)| s == sum && p.trim() == path)));
    recorded
        || TEMPLATES.iter().filter(|t| t.0 == path).any(|(_, template)| {
            let unchanged = pkgverify::verify_paths(ctx.sys, &[template.to_string()], SystemTime::UNIX_EPOCH);
            matches!(unchanged.get(*template), Some(Verdict::Upgraded { .. } | Verdict::MatchesButNoUpgrade { .. })) && ctx.sys.read_bytes(template).is_ok_and(|t| t == data)
        })
}

/// Times that do not fit. A file's change time (ctime) is set by the kernel; its modification
/// time (mtime) can be set to anything with `touch`.
pub(crate) fn check_file_times(ctx: &ScanCtx, col: &mut Collector, already: &HashSet<String>) {
    if ctx.sys.dir_names("/var/lib/dpkg/info").is_empty() {
        return;
    }
    let mut files: Vec<(String, fs::Metadata)> = Vec::new();
    for dir in ["/usr/bin", "/usr/sbin", "/etc"] {
        let depth = if dir == "/etc" { 4 } else { 1 };
        for e in WalkDir::new(ctx.sys.path(dir)).follow_links(false).max_depth(depth).into_iter().filter_map(|e| e.ok()) {
            if e.file_type().is_file() {
                if let Ok(m) = e.metadata() {
                    files.push((ctx.sys.display(e.path()), m));
                }
            }
        }
    }
    let wanted: HashSet<String> = files.iter().map(|f| f.0.clone()).collect();
    let times = package_times(ctx, &wanted);
    let mut touched = Vec::new(); // packaged programs changed after their installation
    let mut odd: Vec<(Severity, String)> = Vec::new();
    for (path, m) in &files {
        let (modified, changed) = (m.mtime(), m.ctime());
        let program = path.starts_with("/usr/");
        match times.get(path) {
            Some(installed) => {
                if program && changed > installed + DAY && !already.contains(path) {
                    touched.push(path.clone());
                }
                if program && modified > changed + DAY {
                    odd.push((Severity::Medium, format!("{path}: modification time is later than the last change of the file")));
                }
            }
            None => {
                let watched = program || TIMED_ETC.iter().any(|d| path.starts_with(d));
                // `touch -d` leaves whole seconds; so do archives, hence /etc needs both signs
                let backdated = changed - modified > 30 * DAY && (program || m.mtime_nsec() == 0);
                if modified > changed + DAY {
                    odd.push((Severity::Low, format!("{path}: modification time is later than the last change of the file")));
                } else if watched && backdated && !(!program && kept_copy(ctx, path)) {
                    let severity = if m.mode() & 0o6000 != 0 { Severity::Medium } else { Severity::Low };
                    odd.push((severity, format!("{path}: not from a package, dated {} days before the file last changed", (changed - modified) / DAY)));
                }
            }
        }
    }
    if !odd.is_empty() {
        odd.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let severity = odd[0].0;
        let count = odd.len();
        let mut lines: Vec<String> = odd.into_iter().take(20).map(|o| o.1).collect();
        if count > 20 {
            lines.push(format!("… and {} more", count - 20));
        }
        col.push(
            Finding::new(severity, MODULE, "FS-TIMESTAMP", "Files in system folders with times that do not fit")
                .evidence(lines.join("\n"))
                .description("Attackers set a file's date back so it looks old (timestomping). Copying or unpacking files with their old dates does the same, so check what each file is and when it really changed (Change: in stat).")
                .verify("stat <file>")
                .verify("dpkg -S <file>"),
        );
    }
    let mut verdicts: Vec<(String, Verdict)> = pkgverify::verify_paths(ctx.sys, &touched, SystemTime::UNIX_EPOCH).into_iter().collect();
    verdicts.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, verdict) in verdicts {
        if let Verdict::Differs { package } = verdict {
            col.push(
                Finding::new(Severity::Critical, MODULE, "FS-PACKAGE-CHANGED", format!("Program changed after installation and differs from its package: {path}"))
                    .evidence(format!("{path}\npackage {package}: the file was changed after the package was installed, and its content does not match the package's checksum"))
                    .description("A program that apt installed has been rewritten since. Investigate, then reinstall the package.")
                    .verify(format!("stat {}", shq(&path)))
                    .verify(format!("dpkg --verify {}", shq(package.split(':').next().unwrap_or(&package)))),
            );
        }
    }
}

// ---------------------------------------------------------------- system programs

const SYSTEM_PROGRAMS: [&str; 32] = [
    "/usr/lib/systemd/systemd", "/usr/lib/systemd/systemd-logind", "/usr/lib/systemd/systemd-journald",
    "/usr/lib/systemd/systemd-udevd", "/usr/lib/polkit-1/polkitd", "/usr/bin/pkexec", "/usr/bin/newgrp", "/usr/bin/mount",
    "/usr/bin/su", "/usr/bin/sudo", "/usr/bin/login", "/usr/bin/passwd", "/usr/bin/ssh", "/usr/sbin/sshd",
    "/usr/lib/openssh/sshd-session", "/usr/lib/openssh/sshd-auth", "/usr/sbin/unix_chkpwd", "/usr/bin/ps",
    "/usr/bin/top", "/usr/bin/ls", "/usr/bin/ss", "/usr/bin/netstat", "/usr/bin/lsof", "/usr/bin/find",
    "/usr/bin/bash", "/usr/bin/dash", "/usr/bin/systemctl", "/usr/bin/journalctl", "/usr/sbin/cron",
    "/usr/bin/dpkg", "/usr/sbin/insmod", "/usr/bin/kmod",
];

/// Compare the programs an attacker likes to replace (and every PAM module) with the
/// checksums their packages ship.
/// Returns the files that were compared.
pub(crate) fn check_system_programs(ctx: &ScanCtx, col: &mut Collector) -> HashSet<String> {
    if ctx.sys.dir_names("/var/lib/dpkg/info").is_empty() {
        return HashSet::new();
    }
    let is_file = |p: &str| fs::symlink_metadata(ctx.sys.path(p)).map(|m| m.is_file()).unwrap_or(false);
    let mut paths: Vec<String> = SYSTEM_PROGRAMS.iter().map(|p| p.to_string()).filter(|p| is_file(p)).collect();
    let pam_dir = "/usr/lib/x86_64-linux-gnu/security";
    paths.extend(ctx.sys.dir_names(pam_dir).into_iter().map(|n| format!("{pam_dir}/{n}")).filter(|p| p.ends_with(".so") && is_file(p)));
    // the libraries every login goes through
    let lib_dir = "/usr/lib/x86_64-linux-gnu";
    let core = |n: &String| ["libpam.so", "libpam_misc.so", "libpamc.so", "libc.so.6", "ld-linux"].iter().any(|p| n.starts_with(p));
    paths.extend(ctx.sys.dir_names(lib_dir).into_iter().filter(core).map(|n| format!("{lib_dir}/{n}")).filter(|p| is_file(p)));
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
    paths.into_iter().collect()
}
