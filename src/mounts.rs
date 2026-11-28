//! Do a process's paths mean what they say?
//!
//! `/proc/<pid>/exe` and `/proc/<pid>/maps` show paths as the process's own mount namespace has
//! them. On Debian any user may make a user namespace (`bwrap`, which Flatpak brings to most
//! desktops) and mount a program of their own at `/usr/bin/ssh-agent` inside it, so that every
//! path looks installed. The kernel still knows the real files: `stat` of `/proc/<pid>/exe`
//! follows to the file that runs, and every mapping carries its device and inode. For processes
//! outside the host's mount namespace these are compared with the files at the same paths on
//! this system. A Flatpak's files lie elsewhere; they count when they are those of a Flatpak
//! installed for the whole system, which only root can change.

use crate::sys::SysRoot;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Where Flatpaks installed for the whole system live.
const SYSTEM_FLATPAK: &str = "/var/lib/flatpak";

/// Where Flatpak puts a version that was updated while it ran.
const REMOVED_FLATPAKS: &str = "/var/lib/flatpak/.removed";

/// The `statfs` type of btrfs, whose files show another device in `maps` than in `stat`.
const BTRFS: u32 = 0x9123_683E;

/// A file as the kernel knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub mode: u32,
}

impl FileId {
    pub fn of(path: &Path) -> Option<FileId> {
        std::fs::metadata(path).ok().map(|m| FileId { dev: m.dev(), ino: m.ino(), uid: m.uid(), mode: m.mode() })
    }

    pub fn same(self, other: FileId) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    /// Only root can change it.
    pub fn only_roots(self) -> bool {
        self.uid == 0 && self.mode & 0o022 == 0
    }

    /// Is this the device `maps` names as (major, minor)?
    fn on_device(self, device: (u32, u32)) -> bool {
        (rustix::fs::major(self.dev), rustix::fs::minor(self.dev)) == device
    }
}

/// A process that has a mount namespace of its own.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Mounts {
    /// Which mount namespace, as the kernel names it.
    pub namespace: String,
    /// Made in a user namespace: whoever runs the process chose what lies at each path.
    pub user_made: bool,
    /// The program is that of a Flatpak installed for the whole system.
    pub system_flatpak: bool,
    /// The program is the one its sandbox says it is, from a Flatpak installed for one person,
    /// whose files that person's programs can change.
    pub own_flatpak: bool,
    /// The program file is not shown to be the one its path names: that path.
    pub claimed: Option<String>,
    /// This system has a file of its own at that path, which the process's file poses as.
    pub installed_here: bool,
}

/// One executable mapping of a `/proc/<pid>/maps` listing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Mapping<'a> {
    /// The address range, which names the entry in `/proc/<pid>/map_files`.
    pub range: &'a str,
    /// (major, minor) of the device the file lies on.
    pub device: (u32, u32),
    pub inode: u64,
    pub path: &'a str,
}

/// The executable mappings of files in a `/proc/<pid>/maps` listing.
pub fn executable_mappings(maps: &str) -> impl Iterator<Item = Mapping<'_>> {
    maps.lines().filter_map(|line| {
        // address perms offset dev inode path
        let mut fields = line.split_whitespace();
        let (range, rights, _, device, inode) = (fields.next()?, fields.next()?, fields.next()?, fields.next()?, fields.next()?);
        let (major, minor) = device.split_once(':')?;
        let device = (u32::from_str_radix(major, 16).ok()?, u32::from_str_radix(minor, 16).ok()?);
        let inode: u64 = inode.parse().ok().filter(|i| *i != 0)?;
        let path = &line[line.find('/')?..];
        rights.contains('x').then_some(Mapping { range, device, inode, path })
    })
}

/// Compare what the process `pid` shows as its program (`exe`) with the real files. `None` when
/// it sees the same files as the host, which is nearly every process.
pub fn examine(sys: &SysRoot, pid: u32, exe: &str) -> Option<Mounts> {
    let link = |who: &str, kind: &str| sys.read_link(format!("/proc/{who}/ns/{kind}"));
    // without our own namespace to compare with (a test folder, a mounted disk) there is
    // nothing to tell apart
    let own = link("self", "mnt")?;
    let namespace = link(&pid.to_string(), "mnt").unwrap_or_default();
    // the scanner itself may run in a sandbox of systemd's, so the first process counts too
    if namespace == own || link("1", "mnt").is_some_and(|host| host == namespace) {
        return None;
    }
    // a namespace that cannot be read counts as the person's
    let user_made = link(&pid.to_string(), "user") != link("1", "user").or_else(|| link("self", "user"));
    let mut mounts = Mounts { namespace, user_made, ..Default::default() };
    judge_program(sys, pid, exe, &mut mounts);
    Some(mounts)
}

/// Fill in what the program file of a process with its own mount namespace really is.
pub fn judge_program(sys: &SysRoot, pid: u32, exe: &str, mounts: &mut Mounts) {
    let (path, deleted) = match exe.strip_suffix(" (deleted)") {
        Some(path) => (path, true),
        None => (exe, false),
    };
    let real = FileId::of(&sys.path(format!("/proc/{pid}/exe")));
    let here = FileId::of(&sys.path(path));
    mounts.installed_here = here.is_some();
    if real.zip(here).is_some_and(|(a, b)| a.same(b)) {
        return;
    }
    // still running the file an upgrade replaced: a file of root's, which only a root-made
    // namespace or the disk the installed one lies on vouches for
    let upgraded = deleted && real.is_some_and(|r| r.uid == 0 && (!mounts.user_made || r.only_roots() && here.is_some_and(|h| h.dev == r.dev)));
    if upgraded {
        return;
    }
    let flatpak = real.and_then(|real| flatpak_file(sys, pid, path, real));
    match flatpak {
        Some(file) if file.starts_with(&format!("{SYSTEM_FLATPAK}/")) => mounts.system_flatpak = true,
        file => {
            mounts.own_flatpak = file.is_some_and(|f| f.contains("/.local/share/flatpak/"));
            mounts.claimed = Some(path.to_string());
        }
    }
}

/// A small file the sandbox wrote about itself. Only a plain file is read: the process chooses
/// what lies there, and a link or a pipe must not lead the scanner elsewhere or make it wait.
fn read_small_file(path: &Path) -> Option<String> {
    use rustix::fs::{Mode, OFlags};
    let file = std::fs::File::from(rustix::fs::open(path, OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty()).ok()?);
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut text = String::new();
    file.take(64 * 1024).read_to_string(&mut text).ok()?;
    Some(text)
}

/// Where on this system lies the file a Flatpak shows at `path`, going by what the sandbox says
/// about itself? Only an answer that is the very file that runs is given.
fn flatpak_file(sys: &SysRoot, pid: u32, path: &str, real: FileId) -> Option<String> {
    let info = read_small_file(&sys.path(format!("/proc/{pid}/root/.flatpak-info")))?;
    let (key, rest) = match path.strip_prefix("/app/") {
        Some(rest) => ("app-path=", rest),
        None => ("runtime-path=", path.strip_prefix("/usr/")?),
    };
    let base = info.lines().skip_while(|l| l.trim() != "[Instance]").find_map(|l| l.strip_prefix(key))?;
    let mut places = vec![format!("{}/{rest}", base.trim_end_matches('/'))];
    // an update moves the version that is running out of the way
    if base.starts_with(SYSTEM_FLATPAK) {
        places.extend(sys.dir_names(REMOVED_FLATPAKS).into_iter().map(|old| format!("{REMOVED_FLATPAKS}/{old}/files/{rest}")));
    }
    places.into_iter().find_map(|place| {
        // the real place, so that links or ".." cannot make a folder of one's own look like the
        // system's
        let place = std::fs::canonicalize(sys.path(place)).ok()?;
        FileId::of(&place).filter(|found| found.same(real)).map(|_| sys.display(&place))
    })
}

impl Mounts {
    /// Is the mapped file `m` of process `pid` the one its path names?
    pub fn maps_true(&self, sys: &SysRoot, pid: u32, m: &Mapping) -> bool {
        let (path, deleted) = match m.path.strip_suffix(" (deleted)") {
            Some(path) => (path, true),
            None => (m.path, false),
        };
        // root may ask for the mapped file itself
        if let Some(mapped) = FileId::of(&sys.path(format!("/proc/{pid}/map_files/{}", m.range))) {
            return self.rightly_at(sys, path, mapped, deleted);
        }
        if deleted {
            return false;
        }
        let here = FileId::of(&sys.path(path));
        if here.is_some_and(|f| f.ino == m.inode && f.on_device(m.device)) {
            return true;
        }
        // the file the process sees at that path, if that is the mapped one
        let seen_at = sys.path(format!("/proc/{pid}/root{path}"));
        let Some(seen) = FileId::of(&seen_at).filter(|f| f.ino == m.inode) else { return false };
        let btrfs = || rustix::fs::statfs(&seen_at).is_ok_and(|s| s.f_type as u32 == BTRFS);
        (seen.on_device(m.device) || btrfs()) && self.rightly_at(sys, path, seen, false)
    }

    /// May this file be the one at `path` for this process?
    fn rightly_at(&self, sys: &SysRoot, path: &str, file: FileId, deleted: bool) -> bool {
        let on_disk_of = |folder: &str| FileId::of(&sys.path(folder)).is_some_and(|f| f.dev == file.dev);
        FileId::of(&sys.path(path)).is_some_and(|here| here.same(file))
            // a Flatpak's own files, which only root can change
            || self.system_flatpak && file.only_roots() && on_disk_of(SYSTEM_FLATPAK)
            // replaced by an upgrade while the program ran
            || deleted && file.only_roots() && (on_disk_of("/usr") || on_disk_of(SYSTEM_FLATPAK))
    }
}
