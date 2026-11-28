//! What gets root rights, or is trusted to describe the system, must not come from places the
//! user's programs can write to.

use scanner::external_tools::{find_binary, run_capture, system_path};
use scanner::trust::{changeable_by_others, group_has_others, judge, sudo_problem};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

#[test]
fn only_root_may_change_what_runs_as_root() {
    assert_eq!(judge("/usr/bin/scanner", 0, 0, 0o100755, &[], false), None);
    assert_eq!(judge("/usr/bin/sudo", 0, 0, 0o104755, &[], false), None);
    assert!(judge("/home/anna", 1000, 1000, 0o40755, &[], true).is_some_and(|w| w.contains("belongs to user id 1000")));
    assert!(judge("/opt/x", 0, 0, 0o40757, &[], false).is_some_and(|w| w.contains("everyone")));
    // a sticky folder such as /tmp is no place for it either
    assert!(judge("/tmp", 0, 0, 0o41777, &[], false).is_some());
    assert_eq!(judge("/opt/x", 0, 0, 0o40775, &[], false), None, "the root group");
    assert!(judge("/usr/local/bin", 0, 50, 0o42775, &[], true).is_some_and(|w| w.contains("group id 50")));
    // an empty staff group changes nothing; a member, a main group or this process does
    let passwd = "root:x:0:0::/root:/bin/sh\nanna:x:1000:1000::/home/anna:/bin/sh\n";
    assert!(!group_has_others(50, "staff:x:50:\n", passwd, &[1000]));
    assert!(!group_has_others(50, "staff:x:50:root\n", passwd, &[1000]));
    assert!(group_has_others(50, "staff:x:50:anna\n", passwd, &[]));
    assert!(group_has_others(1000, "anna:x:1000:\n", passwd, &[]));
    assert!(group_has_others(50, "staff:x:50:\n", passwd, &[1000, 50]));
    assert!(group_has_others(4242, "staff:x:50:\n", passwd, &[]), "unknown group");
    // an access list that lets a user write, and the same entry taken away by the mask
    let acl = |mask: u16| [(0x01, 7, u32::MAX), (0x02, 7, 1000), (0x04, 5, u32::MAX), (0x10, mask, u32::MAX)];
    assert!(judge("/opt/x", 0, 0, 0o40755, &acl(7), false).is_some_and(|w| w.contains("user id 1000")));
    assert_eq!(judge("/opt/x", 0, 0, 0o40755, &acl(5), false), None);

    assert_eq!(changeable_by_others(Path::new("/usr/bin/true")), None);
    assert!(changeable_by_others(Path::new("scanner")).is_some());
    let dir = tempfile::tempdir().expect("tempdir");
    let own = dir.path().join("scanner");
    fs::write(&own, "").expect("write");
    fs::set_permissions(&own, fs::Permissions::from_mode(0o755)).expect("chmod");
    assert!(changeable_by_others(&own).is_some(), "a build or download folder");
}

#[test]
fn only_the_real_sudo_is_used() {
    // an ordinary program is not sudo
    assert!(sudo_problem(Path::new("/usr/bin/true")).is_some_and(|w| w.contains("set-uid")));
    let dir = tempfile::tempdir().expect("tempdir");
    let fake = dir.path().join("sudo");
    fs::write(&fake, "#!/bin/sh\n").expect("write");
    fs::set_permissions(&fake, fs::Permissions::from_mode(0o4755)).expect("chmod");
    assert!(sudo_problem(&fake).is_some());
    if Path::new("/usr/bin/sudo").exists() {
        assert_eq!(sudo_problem(Path::new("/usr/bin/sudo")), None);
    }
}

#[test]
fn tools_come_from_the_system_folders_whatever_path_says() {
    let dir = tempfile::tempdir().expect("tempdir");
    for name in ["env", "sh", "scanner-only-here"] {
        let fake = dir.path().join(name);
        fs::write(&fake, "#!/bin/sh\necho fake\n").expect("write");
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    // the only test in this program that depends on PATH
    std::env::set_var("PATH", format!("{}:/usr/bin", dir.path().display()));
    let env = find_binary("env").expect("env");
    assert!(!env.starts_with(dir.path()), "{}", env.display());
    assert!(find_binary("scanner-only-here").is_none());
    assert!(find_binary(&dir.path().join("env").display().to_string()).is_none());
    // and what the tools start by name comes from there too
    let out = run_capture(&env, &[], 10).expect("run");
    assert!(out.stdout.lines().any(|l| l == format!("PATH={}", system_path())), "{}", out.stdout);
}
