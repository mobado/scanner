//! False alarms from a real root report: a failed apt check, journal leftovers, the lock
//! screen's cancelled password box, systemd's own eBPF filter and AppArmor profiles shipped in
//! complain mode. Made-up files in a temporary directory; nothing on the real system is read or
//! changed.

use scanner::config::Config;
use scanner::external_tools::parse_lynis;
use scanner::modules::auth_logs::closed_password_boxes;
use scanner::modules::integrity::journal_finding;
use scanner::modules::kernelstate::complain_profiles;
use scanner::second_look::explain_apt_check;
use scanner::{run_scan, ModuleId, ScanOptions, Severity, SysRoot};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

fn write(root: &Path, abs: &str, content: &str) {
    let p = root.join(abs.trim_start_matches('/'));
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(p, content).expect("write");
}

fn md5(text: &str) -> String {
    use md5::{Digest, Md5};
    Md5::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn a_failed_apt_check_is_tried_again() {
    let report = "warning[]=PKGS-7390|apt-get check returned a non successful exit code.|-|-|\n";
    let mut fine = parse_lynis("", report);
    explain_apt_check(&mut fine, || Some((true, String::new())));
    assert_eq!(fine[0].severity, Severity::Low);
    let mut broken = parse_lynis("", report);
    explain_apt_check(&mut broken, || Some((false, "E: Unmet dependencies".into())));
    assert_eq!(broken[0].severity, Severity::Medium);
    assert!(broken[0].evidence.contains("Unmet dependencies"));
}

#[test]
fn journal_leftovers_are_low() {
    let leftover = "FAIL: /var/log/journal/ec94/system@00065c-1d50.journal~ (Bad message)";
    assert_eq!(journal_finding(&[leftover]).severity, Severity::Low);
    assert_eq!(journal_finding(&[leftover, "FAIL: /var/log/journal/ec94/system.journal (Bad message)"]).severity, Severity::Medium);
}

#[test]
fn the_password_box_closing_after_a_fingerprint_is_not_a_failed_login() {
    let line = |time: &str, pid: u32, text: &str| format!("2026-11-26T{time}+01:00 Laptop kscreenlocker_greet[{pid}]: {text}");
    let failure = "pam_unix(kde:auth): authentication failure; logname=anna uid=1000 euid=1000 tty= ruser= rhost=  user=anna";
    let lines = vec![
        line("02:09:46", 10, "pam_kwallet5(kde-fingerprint:setcred): pam_kwallet5: pam_sm_setcred"),
        line("02:09:46", 10, failure),
        // a wrong password: no other unlock
        line("03:00:00", 11, "pam_kwallet5(kde-fingerprint:auth): pam_kwallet5: pam_sm_authenticate"),
        line("03:00:02", 11, failure),
        // wrong password first, the finger much later
        line("04:00:00", 12, failure),
        line("04:00:30", 12, "pam_kwallet5(kde-fingerprint:setcred): pam_kwallet5: pam_sm_setcred"),
        // another process unlocked at the same moment
        line("05:00:00", 13, failure),
        line("05:00:00", 14, "pam_kwallet5(kde-fingerprint:setcred): pam_kwallet5: pam_sm_setcred"),
    ];
    assert_eq!(closed_password_boxes(&lines).into_iter().collect::<Vec<_>>(), vec![1]);
}

#[test]
fn systemds_own_filter_and_profiles_shipped_in_complain_mode() {
    assert_eq!(complain_profiles("profile sbuild /usr/bin/sbuild flags=(complain,attach_disconnected) {\n  profile child flags=(complain) {\n"), vec!["sbuild", "child"]);
    assert!(complain_profiles("/usr/bin/man {\n# profile x flags=(complain) {\nprofile y flags=(attach_disconnected) {\n").is_empty());

    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let shipped = "profile plasmashell /usr/bin/plasmashell flags=(complain) {\n}\n";
    write(root, "/etc/apparmor.d/plasmashell", shipped);
    write(root, "/etc/apparmor.d/usr.bin.thing", "/usr/bin/thing flags=(complain) {\n}\n");
    write(root, "/var/lib/dpkg/status", &format!("Package: apparmor\nConffiles:\n /etc/apparmor.d/plasmashell {}\n /etc/apparmor.d/usr.bin.thing {}\n\n", md5(shipped), md5("the shipped version")));
    write(root, "/sys/module/apparmor/parameters/enabled", "Y\n");
    write(root, "/sys/kernel/security/apparmor/profiles", "a (enforce)\nplasmashell (complain)\nplasmashell//QtWebEngineProcess (complain)\n/usr/bin/thing (complain)\n");
    write(root, "/proc/1/stat", "1 (systemd) S 0 1 1 0 -1 4194560 0 0\n");
    write(root, "/proc/1/status", "Name:\tsystemd\nUid:\t0 0 0 0\n");
    symlink("/usr/lib/systemd/systemd", root.join("proc/1/exe")).expect("link");
    write(root, "/proc/1/fdinfo/9", "prog_type:\t29\nprog_id:\t21\n");
    fs::create_dir_all(root.join("proc/1/fd")).expect("mkdir");
    symlink("anon_inode:bpf-prog", root.join("proc/1/fd/9")).expect("link");
    let opts = ScanOptions { modules: vec![ModuleId::Kernel], ..ScanOptions::default() };
    let report = run_scan(&SysRoot::new(root), &Config::default(), &opts, &|_| {});
    assert!(!report.findings.iter().any(|f| f.rule == "KERN-EBPF"));
    let profiles = report.findings.iter().find(|f| f.rule == "KERN-APPARMOR-PROFILES").expect("changed profile");
    assert!(profiles.evidence.contains("/usr/bin/thing") && !profiles.evidence.contains("plasmashell"));
    assert!(report.notes.iter().any(|n| n.contains("2 profile(s)")));
}
