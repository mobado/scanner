//! Saving files when the scanner runs as root.
//!
//! In a folder that someone else can change, any name may be a link: root writing a report to
//! `~/scanner-report.json` would overwrite whatever it points to, such as `/etc/passwd`, and
//! `fs.protected_symlinks` only covers shared folders like `/tmp`. So root writes only where root
//! alone can change the whole path. Everything else is written by a child process that has given
//! up root first (`setgroups`, `setgid`, `setuid`), so the kernel's ordinary permissions apply
//! and nothing has to be given away afterwards with `chown`.

use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// The group of nobody, for a writer whose folder belongs to the root group.
const NOGROUP: u32 = 65534;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
}

/// Who started the scanner through sudo, from `SUDO_UID` and `SUDO_GID`. Never root.
pub fn invoking_user(uid: Option<&str>, gid: Option<&str>) -> Option<User> {
    let user = User { uid: uid?.parse().ok()?, gid: gid?.parse().ok()? };
    (user.uid != 0).then_some(user)
}

/// Whose the place is: the owner of the first folder or file on the way that is not root's. Used
/// when root was not entered through sudo.
pub fn owner_of(path: &Path) -> Option<User> {
    let places: Vec<&Path> = path.ancestors().collect();
    places.iter().rev().find_map(|place| {
        let meta = std::fs::symlink_metadata(place).ok()?;
        (meta.uid() != 0).then(|| User { uid: meta.uid(), gid: if meta.gid() == 0 { NOGROUP } else { meta.gid() } })
    })
}

/// Who has to write `path` instead of this process. `None`: this process may, because it is not
/// root, or because only root can change the place.
pub fn writer(path: &Path) -> io::Result<Option<User>> {
    if !crate::sys::is_root() {
        return Ok(None);
    }
    let full = std::path::absolute(path)?;
    // a device such as /dev/null, lying directly in /dev, which only root can change
    if full.parent() == Some(Path::new("/dev")) && std::fs::symlink_metadata(&full).is_ok_and(|m| m.file_type().is_char_device()) {
        return Ok(None);
    }
    let Err(why) = crate::trust::follow(&full) else { return Ok(None) };
    let var = |name: &str| std::env::var(name).ok();
    invoking_user(var("SUDO_UID").as_deref(), var("SUDO_GID").as_deref())
        .or_else(|| owner_of(&full))
        .map(Some)
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, format!("not written as root, because {why}; choose a folder only root can change, such as /var/log/scanner")))
}

/// Write a file (and make the folders it needs) as whoever may write there.
pub fn save(path: &Path, data: &[u8]) -> io::Result<()> {
    // "--output /dev/stdout" is a link to wherever our own output goes
    if matches!(path.to_str(), Some("/dev/stdout" | "/dev/fd/1" | "/proc/self/fd/1")) {
        let mut out = io::stdout();
        out.write_all(data)?;
        return out.flush();
    }
    match writer(path)? {
        Some(user) => save_as(user, path, data),
        None => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, data)
        }
    }
}

/// Make the folders and write the file in child processes that run as `user`: the privileges are
/// dropped before `mkdir` and `tee` start.
pub fn save_as(user: User, path: &Path, data: &[u8]) -> io::Result<()> {
    let full = std::path::absolute(path)?;
    if let Some(parent) = full.parent() {
        run_as(user, "/usr/bin/mkdir", &["-p"], parent, None)?;
    }
    run_as(user, "/usr/bin/tee", &[], &full, Some(data))
}

fn run_as(user: User, program: &str, options: &[&str], path: &Path, data: Option<&[u8]>) -> io::Result<()> {
    let mut child = Command::new(program)
        .args(options)
        .arg("--")
        .arg(path)
        // the standard library also drops root's other groups (setgroups) before setuid
        .gid(user.gid)
        .uid(user.uid)
        .current_dir("/")
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(if data.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;
    // the pipe is closed when it goes out of scope, which ends the input
    let sent = match (data, child.stdin.take()) {
        (Some(data), Some(mut input)) => input.write_all(data),
        _ => Ok(()),
    };
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let said = String::from_utf8_lossy(&out.stderr);
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("written as user id {}, not as root: {}", user.uid, said.trim())));
    }
    sent
}
