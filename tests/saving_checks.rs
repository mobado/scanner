//! Root must not write through a link another program planted, nor obey a whitelist it can edit.
//! These tests run as an ordinary user and only touch their own temporary folders.

use scanner::config::{distrust, untrusted, SYSTEM_WHITELIST};
use scanner::saving::{invoking_user, owner_of, save, save_as, writer, User};
use scanner::trust::follow;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::Path;

fn me(dir: &Path) -> User {
    let meta = fs::metadata(dir).expect("metadata");
    User { uid: meta.uid(), gid: meta.gid() }
}

#[test]
fn links_are_followed_to_find_who_can_change_a_place() {
    // only root can change these, whether or not the last part exists
    assert_eq!(follow(Path::new("/usr/bin/true")), Ok(true));
    assert_eq!(follow(Path::new("/usr/bin/scanner-is-not-here/report.json")), Ok(false));
    assert!(follow(Path::new("/usr/not-here/../bin/true")).is_err(), "back out of a missing folder");
    assert!(follow(Path::new("report.json")).is_err(), "not a full path");
    // a home folder, with or without the file
    let dir = tempfile::tempdir().expect("tempdir");
    assert!(follow(&dir.path().join("report.json")).is_err());
    // a link there is the attack: the place is judged as changeable, wherever it points
    let link = dir.path().join("scanner-report.json");
    symlink("/etc/passwd", &link).expect("link");
    assert!(follow(&link).is_err());
}

#[test]
fn the_person_who_used_sudo_writes_the_file() {
    assert_eq!(invoking_user(Some("1000"), Some("1000")), Some(User { uid: 1000, gid: 1000 }));
    assert_eq!(invoking_user(Some("0"), Some("0")), None, "root through sudo is nobody else");
    assert_eq!(invoking_user(None, Some("1000")), None);
    assert_eq!(invoking_user(Some("x"), Some("1000")), None);
    // without sudo it is whoever owns the first folder that is not root's
    let dir = tempfile::tempdir().expect("tempdir");
    if me(dir.path()).uid != 0 {
        assert_eq!(owner_of(&dir.path().join("a/report.json")).map(|u| u.uid), Some(me(dir.path()).uid));
    }
    assert_eq!(owner_of(Path::new("/usr/bin/true")), None);
}

#[test]
fn a_child_process_writes_with_the_kernels_ordinary_permissions() {
    let dir = tempfile::tempdir().expect("tempdir");
    let user = me(dir.path());
    // folders are made, content arrives whole, an older file is replaced
    let path = dir.path().join("new/deeper/-report with spaces.json");
    let big = vec![b'x'; 3_000_000];
    save_as(user, &path, &big).expect("write");
    assert_eq!(fs::read(&path).expect("read"), big);
    save_as(user, &path, b"short").expect("write again");
    assert_eq!(fs::read(&path).expect("read"), b"short");
    assert_eq!(fs::metadata(&path).expect("metadata").uid(), user.uid);
    // what the user may not write stays as it is, also through a link
    if user.uid != 0 {
        let locked = dir.path().join("locked");
        fs::write(&locked, "root:x:0:0").expect("write");
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o444)).expect("chmod");
        let link = dir.path().join("report.json");
        symlink(&locked, &link).expect("link");
        let refused = save_as(user, &link, b"evil").expect_err("must be refused");
        assert!(refused.to_string().contains("not as root"), "{refused}");
        assert_eq!(fs::read(&locked).expect("read"), b"root:x:0:0");
    }
}

#[test]
fn without_root_files_are_written_directly() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("a/b.txt");
    if me(dir.path()).uid != 0 {
        assert_eq!(writer(&path).expect("writer"), None);
    }
    save(&path, b"report").expect("save");
    assert_eq!(fs::read(&path).expect("read"), b"report");
}

#[test]
fn a_whitelist_others_can_change_is_not_for_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let own = dir.path().join("whitelist.toml");
    fs::write(&own, "ignore_rules = [\"NET-REVSHELL\"]\n").expect("write");
    let why = untrusted(&own).expect("changeable");
    assert!(why.contains("was not used") && why.contains(SYSTEM_WHITELIST), "{why}");
    // also one that is not there yet, in a folder where it could appear at any moment
    assert!(untrusted(&dir.path().join("missing.toml")).is_some());
    assert_eq!(untrusted(Path::new("/usr/bin/true")), None);
    // without root the person's own whitelist is used as before
    if me(dir.path()).uid != 0 {
        assert_eq!(distrust(&own), None);
        assert!(scanner::config::load_whitelist(&own).is_ok());
    }
}
