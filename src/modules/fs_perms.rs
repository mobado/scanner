//! fs_perms: SUID/SGID files and dangerous file permissions on local file systems.
//!
//! Virtual file systems are skipped both by path (/proc, /sys, /dev, /run …)
//! and by `st_dev`: only devices of local file systems in /proc/mounts are walked.

use super::common::{mode_string, shq};
use super::{browsers, filemarks, homefiles};
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::sys::sha256_file;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use walkdir::WalkDir;

pub const MODULE: &str = "fs_perms";

pub const S_ISUID: u32 = 0o4000;
pub const S_ISGID: u32 = 0o2000;
pub const S_ISVTX: u32 = 0o1000;

const LOCAL_FS: [&str; 17] = [
    "ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "jfs", "reiserfs", "zfs", "vfat", "exfat",
    "ntfs", "ntfs3", "bcachefs", "nilfs2", "hfsplus", "ufs",
];

const SYSTEM_DIRS: [&str; 9] = ["/etc", "/usr", "/boot", "/bin", "/sbin", "/lib", "/lib64", "/root", "/var/spool/cron"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuidEntry {
    pub path: String,
    pub mode: String,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub mtime: i64,
    pub suid: bool,
    pub sgid: bool,
    pub sha256: Option<String>,
}

/// Avkoda \040 m.fl. i /proc/mounts.
fn unescape_mount(s: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 4 <= b.len() {
            if let Some(v) = s.get(i + 1..i + 4).and_then(|o| u8::from_str_radix(o, 8).ok()) {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Device numbers of all local file systems according to /proc/mounts.
fn local_devices(ctx: &ScanCtx) -> Option<HashSet<u64>> {
    let mounts = ctx.sys.read_string("/proc/mounts").ok()?;
    let mut devs = HashSet::new();
    for line in mounts.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || !LOCAL_FS.contains(&f[2]) {
            continue;
        }
        let mp = unescape_mount(f[1]);
        if let Ok(m) = std::fs::metadata(ctx.sys.path(&mp)) {
            devs.insert(m.dev());
        }
    }
    (!devs.is_empty()).then_some(devs)
}

fn in_dirs(path: &str, dirs: &[&str]) -> bool {
    dirs.iter().any(|d| path == *d || path.starts_with(&format!("{d}/")))
}

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    let cfg = ctx.cfg;
    let devs = if ctx.sys.is_live() { local_devices(ctx) } else { None };
    if ctx.sys.is_live() && devs.is_none() {
        col.note("/proc/mounts could not be parsed – file systems are filtered by path only");
    }

    let mut entries: Vec<SuidEntry> = Vec::new();
    let mut ww_count = 0usize;
    let mut ww_extra = 0usize;
    let mut errors = 0u64;
    let mut scanned = 0u64;
    let mut seen_roots = HashSet::new();

    for root in &cfg.fs_roots {
        let real_root = ctx.sys.path(root);
        if !seen_roots.insert(real_root.clone()) {
            continue;
        }
        let walker = WalkDir::new(&real_root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                let shown = ctx.sys.display(e.path());
                if cfg.is_fs_excluded(&shown) {
                    return false;
                }
                if let (Some(devs), true) = (&devs, e.file_type().is_dir()) {
                    if let Ok(m) = e.metadata() {
                        if !devs.contains(&m.dev()) {
                            return false;
                        }
                    }
                }
                true
            });

        for entry in walker {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => {
                    errors += 1;
                    continue;
                }
            };
            scanned += 1;
            let ft = entry.file_type();
            if ft.is_symlink() {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => {
                    errors += 1;
                    continue;
                }
            };
            let mode = meta.mode();
            let shown = ctx.sys.display(entry.path());
            if ft.is_file() && mode & 0o111 != 0 && !ctx.cfg.is_temp_path(&shown) {
                filemarks::check_capabilities(ctx, col, &shown, entry.path(), &meta);
            }
            if ft.is_file() || ft.is_dir() {
                filemarks::check_immutable(col, &shown, entry.path());
            }

            if ft.is_file() && mode & (S_ISUID | S_ISGID) != 0 {
                let e = suid_entry(&shown, entry.path(), &meta);
                judge_suid(ctx, &e, mode, cfg.is_suid_allowed(&shown), col);
                entries.push(e);
            }

            // World-writable files and directories in system locations
            if mode & 0o002 != 0 && in_dirs(&shown, &SYSTEM_DIRS) {
                let dir_ok = ft.is_dir() && mode & S_ISVTX != 0;
                if (ft.is_file() || ft.is_dir()) && !dir_ok {
                    if ww_count < 50 {
                        ww_count += 1;
                        col.push(
                            Finding::new(Severity::High, MODULE, "FS-WORLD-WRITABLE", format!("World-writable {} in a system location: {shown}", if ft.is_dir() { "directory" } else { "file" }))
                                .evidence(format!("{shown} mode {} owner {}:{}", mode_string(mode), meta.uid(), meta.gid()))
                                .description("Every user can change this file or directory. In system locations that can be used to replace programs or configuration and gain root.")
                                .verify(format!("stat {}", shq(&shown)))
                                .verify(format!("dpkg -S {}", shq(&shown))),
                        );
                    } else {
                        ww_extra += 1;
                    }
                }
            }
        }
    }
    if ww_extra > 0 {
        col.note(format!("{ww_extra} more world-writable files in system locations were not reported (limit 50)"));
    }
    if errors > 0 {
        col.note(format!("{errors} files/directories could not be read during the file system walk{}", if ctx.privileged { "" } else { " (run as root)" }));
    }

    // Temporary folders are often memory file systems that the walk above skips.
    for t in filemarks::check_temp_programs(ctx, col) {
        if !entries.iter().any(|e| e.path == t.path) {
            let e = suid_entry(&t.path, &t.real, &t.meta);
            judge_suid(ctx, &e, t.meta.mode(), cfg.is_suid_allowed(&t.path), col);
            entries.push(e);
        }
    }
    let compared = filemarks::check_system_programs(ctx, col);
    filemarks::check_file_times(ctx, col, &compared);
    let homes: Vec<String> = super::persistence::home_dirs(ctx, &ctx.accounts).into_iter().map(|(_, _, home)| home).collect();
    homefiles::check_home_files(ctx, col, &homes);
    browsers::check_browsers(ctx, col, &homes);
    super::secrets::check_files(ctx, col, &homes);
    super::debianfs::check(ctx, col);
    check_sensitive_files(ctx, col);
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    col.inventory.suid = entries;
    col.inventory.fs_files_scanned = scanned;
}

fn suid_entry(shown: &str, real: &std::path::Path, meta: &std::fs::Metadata) -> SuidEntry {
    let mode = meta.mode();
    SuidEntry {
        path: shown.to_string(),
        mode: mode_string(mode),
        uid: meta.uid(),
        gid: meta.gid(),
        size: meta.size(),
        mtime: meta.mtime(),
        suid: mode & S_ISUID != 0,
        sgid: mode & S_ISGID != 0,
        sha256: sha256_file(real, 256 * 1024 * 1024),
    }
}

fn judge_suid(ctx: &ScanCtx, e: &SuidEntry, mode: u32, whitelisted: bool, col: &mut Collector) {
    let kind = match (e.suid, e.sgid) {
        (true, true) => "SUID+SGID",
        (true, false) => "SUID",
        _ => "SGID",
    };
    let ev = format!(
        "{} {kind} mode {} owner {}:{} size {} sha256 {}",
        e.path,
        e.mode,
        e.uid,
        e.gid,
        e.size,
        e.sha256.as_deref().unwrap_or("?")
    );
    let verify = vec![
        format!("stat {}", shq(&e.path)),
        format!("dpkg -S {}", shq(&e.path)),
        format!("debsums -s \"$(dpkg -S {} | cut -d: -f1)\"", shq(&e.path)),
        format!("sha256sum {}", shq(&e.path)),
    ];

    if mode & 0o002 != 0 {
        col.push(
            Finding::new(Severity::Critical, MODULE, "FS-SUID-WRITABLE", format!("World-writable {kind} file: {}", e.path))
                .evidence(ev)
                .description("Anyone can overwrite a file that runs with elevated privileges – a direct path to root.")
                .verify_all(verify),
        );
        return;
    }
    let risky_place = ctx.cfg.is_temp_path(&e.path) || e.path.starts_with("/home/") || e.path.starts_with("/var/www/");
    if risky_place {
        col.push(
            Finding::new(Severity::Critical, MODULE, "FS-SUID-TEMP", format!("{kind} file in a suspicious location: {}", e.path))
                .evidence(ev)
                .description("SUID/SGID programs in /tmp, /dev/shm, home directories or web directories are a classic way for an attacker to keep root access.")
                .verify_all(verify),
        );
        return;
    }
    if whitelisted {
        return;
    }
    if e.suid && e.uid == 0 && filemarks::runs_any_command(&e.path) {
        col.push(
            Finding::new(Severity::Critical, MODULE, "FS-SUID-SHELL", format!("SUID shell or interpreter: {}", e.path))
                .evidence(ev)
                .description("This program can run any command, and with SUID root it does so as root for every user. Debian never installs it that way; it is one of the most common backdoors. Remove the bit with chmod u-s and find out who set it.")
                .verify_all(verify),
        );
        return;
    }
    if e.suid && e.uid != 0 {
        col.push(
            Finding::new(Severity::High, MODULE, "FS-SUID-NONROOT", format!("SUID file owned by someone other than root: {}", e.path))
                .evidence(ev)
                .description("The program runs with another user's privileges. Check that it belongs to a package and is intended.")
                .verify_all(verify),
        );
        return;
    }
    let sev = if e.suid { Severity::Medium } else { Severity::Low };
    col.push(
        Finding::new(sev, MODULE, "FS-SUID-UNKNOWN", format!("{kind} file not in the whitelist: {}", e.path))
            .evidence(ev)
            .description("The file has SUID/SGID but is not among the known Debian default files. Check that it comes from an installed package (dpkg -S) and otherwise add it to allowed_suid.")
            .verify_all(verify),
    );
}

fn check_sensitive_files(ctx: &ScanCtx, col: &mut Collector) {
    let checks: [(&str, u32, Severity, &str); 5] = [
        ("/etc/passwd", 0o022, Severity::Critical, "is writable by others than root"),
        ("/etc/group", 0o022, Severity::Critical, "is writable by others than root"),
        ("/etc/shadow", 0o007, Severity::High, "is readable or writable by everyone"),
        ("/etc/gshadow", 0o007, Severity::High, "is readable or writable by everyone"),
        ("/etc/sudoers", 0o022, Severity::Critical, "is writable by others than root"),
    ];
    for (path, mask, sev, what) in checks {
        if let Ok(m) = std::fs::symlink_metadata(ctx.sys.path(path)) {
            let bad_owner = m.uid() != 0;
            if m.mode() & mask != 0 || bad_owner {
                col.push(
                    Finding::new(if bad_owner { Severity::Critical } else { sev }, MODULE, "FS-SENSITIVE-PERMS", format!("Wrong permissions on {path}"))
                        .evidence(format!("{path} mode {} owner {}:{}", mode_string(m.mode()), m.uid(), m.gid()))
                        .description(format!("The file {what}{}. The Debian default is root-owned and 0644 (passwd/group), 0640 (shadow/gshadow) or 0440 (sudoers).", if bad_owner { " and is not owned by root" } else { "" }))
                        .verify(format!("stat {path}"))
                        .verify("dpkg --verify passwd sudo"),
                );
            }
        }
    }
    for name in ctx.sys.dir_names("/etc/sudoers.d") {
        let p = format!("/etc/sudoers.d/{name}");
        if let Ok(m) = std::fs::symlink_metadata(ctx.sys.path(&p)) {
            if m.mode() & 0o022 != 0 || m.uid() != 0 {
                col.push(
                    Finding::new(Severity::Critical, MODULE, "FS-SENSITIVE-PERMS", format!("Wrong permissions on {p}"))
                        .evidence(format!("{p} mode {} owner {}:{}", mode_string(m.mode()), m.uid(), m.gid()))
                        .description("A sudoers file that others than root can change gives full root access.")
                        .verify(format!("stat {p}"))
                        .verify("visudo -c"),
                );
            }
        }
    }
}
