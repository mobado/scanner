//! What the scanner runs with root rights, or obeys as root, must be something only root can
//! change: `sudo` itself, the program that is started through it and the whitelist. Otherwise any
//! program of the user could put its own code in their place and get root the next time the
//! scanner asks for it. The same test decides who writes a file (see [`crate::saving`]).

use crate::modules::persistence::python::{parse_acl, AclEntry};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

/// Does a group have anyone besides root: a listed member, an account with it as main group, or
/// this process? A group that isn't in `/etc/group` counts as having others. Debian lets the
/// `staff` group write in `/usr/local`, and nobody is in it unless the administrator adds them.
pub fn group_has_others(gid: u32, group: &str, passwd: &str, own_groups: &[u32]) -> bool {
    if gid == 0 {
        return false;
    }
    let field = |line: &str, n: usize| line.split(':').nth(n).map(str::to_string);
    let Some(line) = group.lines().find(|l| field(l, 2).and_then(|v| v.parse().ok()) == Some(gid)) else { return true };
    let listed = field(line, 3).unwrap_or_default().split(',').any(|m| !m.trim().is_empty() && m.trim() != "root");
    let main = passwd.lines().any(|l| field(l, 3).and_then(|v| v.parse().ok()) == Some(gid) && field(l, 2).as_deref() != Some("0"));
    listed || main || own_groups.contains(&gid)
}

/// The group ids of this process.
fn own_groups() -> Vec<u32> {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status.lines().filter_map(|l| l.strip_prefix("Groups:").or_else(|| l.strip_prefix("Gid:"))).flat_map(|v| v.split_whitespace()).filter_map(|v| v.parse().ok()).collect()
}

/// Why someone other than root can change one file or folder, from its owner, mode, access list
/// and whether its group has anyone in it (`others_in_group`).
pub fn judge(place: &str, uid: u32, gid: u32, mode: u32, acl: &[AclEntry], others_in_group: bool) -> Option<String> {
    const USER: u16 = 0x02;
    const GROUP: u16 = 0x08;
    const MASK: u16 = 0x10;
    if uid != 0 {
        return Some(format!("{place} belongs to user id {uid}"));
    }
    if mode & 0o002 != 0 {
        return Some(format!("everyone can write to {place}"));
    }
    if mode & 0o020 != 0 && gid != 0 && others_in_group {
        return Some(format!("group id {gid} can write to {place}"));
    }
    let mask = acl.iter().find(|e| e.0 == MASK).map(|e| e.1).unwrap_or(7);
    acl.iter()
        .filter(|(kind, rights, id)| (*kind == USER || *kind == GROUP) && *id != 0 && rights & mask & 2 != 0)
        .map(|(kind, _, id)| format!("an access list lets {} id {id} write to {place}", if *kind == USER { "user" } else { "group" }))
        .next()
}

/// The names in a path, with `..` kept.
fn parts(path: &Path) -> impl DoubleEndedIterator<Item = OsString> + '_ {
    let kept: Vec<OsString> = path.components().filter(|c| matches!(c, Component::Normal(_) | Component::ParentDir)).map(|c| c.as_os_str().to_os_string()).collect();
    kept.into_iter()
}

/// Follows `path` the way the kernel does, through every link, and judges `/`, each folder and
/// the file it ends in. `Ok(true)`: all of it exists and only root can change it. `Ok(false)`:
/// the same up to a part that does not exist yet, which therefore only root can create.
/// `Err`: why someone else can change where the path leads or what is there.
pub fn follow(path: &Path) -> Result<bool, String> {
    let shown = path.display();
    if !path.is_absolute() {
        return Err(format!("{shown} is not a full path"));
    }
    let group = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let own = own_groups();
    let check = |place: &Path| -> Result<(), String> {
        let name = place.display().to_string();
        let meta = std::fs::symlink_metadata(place).map_err(|_| format!("{name} cannot be checked"))?;
        let mut value = [0u8; 4096];
        let acl = rustix::fs::getxattr(place, "system.posix_acl_access", &mut value[..])
            .ok()
            .and_then(|length| parse_acl(value.get(..length)?))
            .unwrap_or_default();
        let others = group_has_others(meta.gid(), &group, &passwd, &own);
        judge(&name, meta.uid(), meta.gid(), meta.mode(), &acl, others).map_or(Ok(()), Err)
    };
    let mut here = PathBuf::from("/");
    check(&here)?;
    let mut rest: VecDeque<OsString> = parts(path).collect();
    let mut links = 0;
    while let Some(part) = rest.pop_front() {
        if part == ".." {
            here.pop();
            continue;
        }
        let next = here.join(&part);
        match std::fs::symlink_metadata(&next) {
            // a link is as safe as the folder it lies in, which has been judged; where it leads
            // is followed
            Ok(meta) if meta.file_type().is_symlink() => {
                links += 1;
                let target = std::fs::read_link(&next).ok().filter(|_| links <= 40).ok_or_else(|| format!("{shown} cannot be checked"))?;
                if target.is_absolute() {
                    here = PathBuf::from("/");
                }
                for part in parts(&target).rev() {
                    rest.push_front(part);
                }
            }
            Ok(_) => {
                check(&next)?;
                here = next;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if rest.iter().any(|p| p == "..") {
                    return Err(format!("{shown} goes back out of a folder that does not exist"));
                }
                return Ok(false);
            }
            Err(_) => return Err(format!("{} cannot be checked", next.display())),
        }
    }
    Ok(true)
}

/// The first reason why someone other than root could change `path`: the file itself or any
/// folder above it, also along the links it goes through.
pub fn changeable_by_others(path: &Path) -> Option<String> {
    match follow(path) {
        Ok(true) => None,
        Ok(false) => Some(format!("{} cannot be checked", path.display())),
        Err(why) => Some(why),
    }
}

/// Why this `sudo` must not be used: it has to be root's own set-uid program.
pub fn sudo_problem(sudo: &Path) -> Option<String> {
    if let Some(why) = changeable_by_others(sudo) {
        return Some(why);
    }
    match std::fs::metadata(sudo) {
        Ok(meta) if !meta.is_file() => Some(format!("{} is not a program", sudo.display())),
        Ok(meta) if meta.mode() & 0o4000 == 0 => Some(format!("{} does not have the set-uid bit that sudo needs", sudo.display())),
        Ok(_) => None,
        Err(e) => Some(format!("{}: {e}", sudo.display())),
    }
}
