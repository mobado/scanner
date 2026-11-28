//! Access to the system's files through a selectable root.
//!
//! On a real system the root is `/`. In tests and the self-test the root points to
//! a temporary directory with made-up `/proc`, `/etc` and systemd files.

use crate::error::{Result, ScanError};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SysRoot {
    root: PathBuf,
}

impl Default for SysRoot {
    fn default() -> Self {
        SysRoot::live()
    }
}

impl SysRoot {
    /// The real system.
    pub fn live() -> Self {
        SysRoot {
            root: PathBuf::from("/"),
        }
    }

    /// Another root (e.g. a mounted disk or a test directory).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        SysRoot { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// True when scanning the running system (then external tools and `ss` can be
    /// used, and processes can disappear in the middle of the scan).
    pub fn is_live(&self) -> bool {
        self.root == Path::new("/")
    }

    /// Translate an absolute system path (`/proc/net/tcp`) to a real path under the root.
    pub fn path(&self, abs: impl AsRef<Path>) -> PathBuf {
        let abs = abs.as_ref();
        let rel = abs.strip_prefix("/").unwrap_or(abs);
        if rel.as_os_str().is_empty() {
            self.root.clone()
        } else {
            self.root.join(rel)
        }
    }

    /// Reverse translation: real path → system path for the report.
    pub fn display(&self, real: &Path) -> String {
        if self.is_live() {
            return real.display().to_string();
        }
        match real.strip_prefix(&self.root) {
            Ok(rel) => format!("/{}", rel.display()),
            Err(_) => real.display().to_string(),
        }
    }

    pub fn read_string(&self, abs: impl AsRef<Path>) -> Result<String> {
        let bytes = self.read_bytes(abs)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// The contents of a plain file (see [`open_plain_file`]); `/dev/null`, which people link
    /// files to, reads as empty.
    pub fn read_bytes(&self, abs: impl AsRef<Path>) -> Result<Vec<u8>> {
        let p = self.path(abs);
        let read = || -> io::Result<Vec<u8>> {
            let found = find_file(&p)?;
            if is_dev_null(&found.metadata()?) {
                return Ok(Vec::new());
            }
            let mut data = Vec::new();
            read_found(&found)?.read_to_end(&mut data)?;
            Ok(data)
        };
        read().map_err(|e| ScanError::io(&p, e))
    }

    /// Read a symbolic link target as text (e.g. `/proc/<pid>/exe`).
    pub fn read_link(&self, abs: impl AsRef<Path>) -> Option<String> {
        fs::read_link(self.path(abs))
            .ok()
            .map(|t| t.to_string_lossy().into_owned())
    }

    pub fn exists(&self, abs: impl AsRef<Path>) -> bool {
        fs::symlink_metadata(self.path(abs)).is_ok()
    }

    /// Names in a directory, sorted. Errors (missing/denied) give an empty list.
    pub fn dir_names(&self, abs: impl AsRef<Path>) -> Vec<String> {
        let mut names: Vec<String> = match fs::read_dir(self.path(abs)) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }

    /// Follow a symbolic link inside the root: absolute targets are relative to the root.
    pub fn resolve_link_target(&self, link_abs: &str, target: &str) -> String {
        if target.starts_with('/') {
            target.to_string()
        } else {
            let parent = Path::new(link_abs)
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("/"));
            parent.join(target).display().to_string()
        }
    }
}

// Files the scanner reads may be anyone's, and whoever owns one can put something else in its
// place at any moment: a pipe, which makes a reader wait for ever, or a link to a device, where
// merely opening it can have an effect. So a file is first only found (`O_PATH`, which opens
// nothing), looked at through that handle, and then that very file is opened.

/// A handle on what lies at `path`, for looking at it. Links are followed.
pub fn find_file(path: &Path) -> io::Result<fs::File> {
    use rustix::fs::{Mode, OFlags};
    Ok(fs::File::from(rustix::fs::open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())?))
}

/// Open what `found` (from [`find_file`] or the like) points at for reading, if that is a plain
/// file.
pub fn read_found(found: &fs::File) -> io::Result<fs::File> {
    use rustix::fs::{Mode, OFlags};
    use std::os::fd::AsRawFd;
    if !found.metadata()?.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a plain file"));
    }
    // the kernel's own way back to exactly the file the handle is on
    let same = format!("/proc/self/fd/{}", found.as_raw_fd());
    Ok(fs::File::from(rustix::fs::open(same, OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty())?))
}

/// Open a file to read it, if it is a plain file.
pub fn open_plain_file(path: &Path) -> io::Result<fs::File> {
    read_found(&find_file(path)?)
}

/// Is this the null device (character device 1:3)?
fn is_dev_null(meta: &fs::Metadata) -> bool {
    meta.file_type().is_char_device() && meta.rdev() == rustix::fs::makedev(1, 3)
}

/// SHA-256 of a plain file (up to `max_bytes`), as hex. `None` if it cannot be read.
pub fn sha256_file(path: &Path, max_bytes: u64) -> Option<String> {
    sha256_reader(open_plain_file(path).ok()?, max_bytes)
}

/// SHA-256 of what an open file holds (up to `max_bytes`), as hex.
pub fn sha256_reader(file: fs::File, max_bytes: u64) -> Option<String> {
    let mut reader = file.take(max_bytes);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Some(hex(&hasher.finalize()))
}

pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Effective user id of this process (read from /proc/self/status,
/// so no `unsafe` is needed). `None` if it cannot be determined.
pub fn current_euid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

pub fn is_root() -> bool {
    current_euid() == Some(0)
}

/// Host name, kernel version and OS name for the report header.
pub fn host_facts(sys: &SysRoot) -> (String, String, String) {
    let hostname = sys
        .read_string("/proc/sys/kernel/hostname")
        .or_else(|_| sys.read_string("/etc/hostname"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let kernel = sys
        .read_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let os = sys
        .read_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim_matches('"').to_string())
        })
        .unwrap_or_else(|| "unknown".into());
    (hostname, kernel, os)
}
