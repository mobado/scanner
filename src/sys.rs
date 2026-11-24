//! Access to the system's files through a selectable root.
//!
//! On a real system the root is `/`. In tests and the self-test the root points to
//! a temporary directory with made-up `/proc`, `/etc` and systemd files.

use crate::error::{Result, ScanError};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
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
        let p = self.path(abs);
        let bytes = fs::read(&p).map_err(|e| ScanError::io(&p, e))?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn read_bytes(&self, abs: impl AsRef<Path>) -> Result<Vec<u8>> {
        let p = self.path(abs);
        fs::read(&p).map_err(|e| ScanError::io(&p, e))
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

/// SHA-256 of a file (up to `max_bytes`), as hex. `None` if it cannot be read.
pub fn sha256_file(path: &Path, max_bytes: u64) -> Option<String> {
    let f = fs::File::open(path).ok()?;
    let mut reader = f.take(max_bytes);
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
