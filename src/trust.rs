//! What the scanner runs with root rights must be something only root can change: `sudo` itself
//! and the program that is started through it. Otherwise any program of the user could put its
//! own code in their place and get root the next time the scanner asks for it.

use crate::modules::persistence::python::{parse_acl, AclEntry};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

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

/// The first reason why someone other than root could change `path`: the file itself or any
/// folder above it, also along the links it goes through.
pub fn changeable_by_others(path: &Path) -> Option<String> {
    if !path.is_absolute() {
        return Some(format!("{} is not a full path", path.display()));
    }
    let Ok(real) = std::fs::canonicalize(path) else { return Some(format!("{} cannot be checked", path.display())) };
    let group = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let own = own_groups();
    // the folders as written (a link in a folder others can write to can be swapped) and the
    // real ones
    for place in path.ancestors().skip(1).chain(real.ancestors()) {
        let shown = place.display().to_string();
        let Ok(meta) = std::fs::metadata(place) else { return Some(format!("{shown} cannot be checked")) };
        let mut value = [0u8; 4096];
        let acl = rustix::fs::getxattr(place, "system.posix_acl_access", &mut value[..])
            .ok()
            .and_then(|length| parse_acl(value.get(..length)?))
            .unwrap_or_default();
        let others = group_has_others(meta.gid(), &group, &passwd, &own);
        if let Some(why) = judge(&shown, meta.uid(), meta.gid(), meta.mode(), &acl, others) {
            return Some(why);
        }
    }
    None
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
