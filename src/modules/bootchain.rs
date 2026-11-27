//! The boot chain and disk health (part of `integrity`): start options of the running and the
//! configured kernel, GRUB scripts, the kernel file against its package, and disk errors that
//! look like damaged files.

use super::common::{analyze_command, clip, max_severity, reasons, shq};
use super::integrity::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::pkgverify::{owned_paths, verify_paths, Verdict};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::time::SystemTime;

/// Kernel options that weaken the system or take over the start.
pub fn weakening_options(line: &str) -> Vec<(Severity, String)> {
    line.split_whitespace()
        .filter_map(|word| {
            let word = word.trim_matches(|c| c == '"' || c == '\'');
            let (key, value) = word.split_once('=').unwrap_or((word, ""));
            let judged = match (key, value) {
                // the kernel starts this instead of systemd
                ("init", v) if !["/sbin/init", "/usr/sbin/init", "/lib/systemd/systemd", "/usr/lib/systemd/systemd"].contains(&v) => (Severity::High, "starts another program instead of systemd"),
                ("rdinit", _) => (Severity::High, "starts another program from the boot image"),
                ("apparmor", "0") | ("security", "none") => (Severity::High, "switches off AppArmor"),
                ("selinux", "0") => (Severity::Medium, "switches off SELinux"),
                ("module.sig_enforce", "0") => (Severity::Medium, "accepts unsigned kernel modules"),
                ("lockdown", "none") => (Severity::Medium, "switches off the kernel lockdown"),
                ("nokaslr", _) => (Severity::Medium, "switches off address randomisation"),
                ("mitigations", "off") => (Severity::Medium, "switches off protection against processor flaws"),
                ("audit", "0") => (Severity::Low, "switches off the kernel's audit log"),
                _ => return None,
            };
            Some((judged.0, format!("{word}: {}", judged.1)))
        })
        .collect()
}

fn check_boot_options(ctx: &ScanCtx, col: &mut Collector) {
    // option → where it appears
    let mut found: BTreeMap<String, (Severity, Vec<&str>)> = BTreeMap::new();
    let mut add = |place: &'static str, line: &str| {
        for (severity, what) in weakening_options(line) {
            let entry = found.entry(what).or_insert((severity, Vec::new()));
            if !entry.1.contains(&place) {
                entry.1.push(place);
            }
        }
    };
    if let Ok(text) = ctx.sys.read_string("/proc/cmdline") {
        add("the running kernel (/proc/cmdline)", &text);
    }
    if let Ok(text) = ctx.sys.read_string("/etc/default/grub") {
        for line in text.lines().map(str::trim).filter(|l| l.starts_with("GRUB_CMDLINE_LINUX")) {
            add("/etc/default/grub", line.split_once('=').map(|(_, v)| v).unwrap_or(""));
        }
    }
    match ctx.sys.read_string("/boot/grub/grub.cfg") {
        Ok(text) => {
            for line in text.lines().map(str::trim).filter(|l| l.starts_with("linux ") || l.starts_with("linux\t")) {
                add("/boot/grub/grub.cfg", line);
            }
        }
        Err(e) if e.is_permission_denied() => col.note("integrity: /boot/grub/grub.cfg can only be read as root"),
        Err(_) => {}
    }
    let Some(severity) = found.values().map(|f| f.0).max() else { return };
    let lines: Vec<String> = found.into_iter().map(|(what, (_, places))| format!("{what}\n  in {}", places.join(", "))).collect();
    col.push(
        Finding::new(severity, MODULE, "INT-BOOT-OPTIONS", "Kernel start options weaken the system")
            .evidence(clip(&lines.join("\n"), 900))
            .description("Options on the kernel's command line switch protections off or change what starts. People set some for speed or hardware problems; an attacker uses them to get in at the next start.")
            .verify("cat /proc/cmdline")
            .verify("grep CMDLINE /etc/default/grub; grep -n '^\\s*linux' /boot/grub/grub.cfg"),
    );
}

fn check_grub_scripts(ctx: &ScanCtx, col: &mut Collector) {
    // update-grub runs only the executable files in grub.d; notes and backups there do nothing
    let mut files: Vec<String> = ctx
        .sys
        .dir_names("/etc/grub.d")
        .into_iter()
        .map(|n| format!("/etc/grub.d/{n}"))
        .filter(|p| std::fs::metadata(ctx.sys.path(p)).map(|m| m.is_file() && m.mode() & 0o111 != 0).unwrap_or(false))
        .collect();
    files.push("/boot/grub/custom.cfg".into());
    let has_dpkg = !ctx.sys.dir_names("/var/lib/dpkg/info").is_empty();
    let owned = owned_paths(ctx.sys, &files);
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        if owned.contains(&path) {
            continue;
        }
        let issues: Vec<_> = text.lines().map(str::trim).filter(|l| !l.starts_with('#')).flat_map(|l| analyze_command(l, ctx.cfg)).filter(|i| i.severity >= Severity::High).collect();
        let severity = match max_severity(&issues) {
            Some(s) => s,
            None if has_dpkg && path.starts_with("/etc/grub.d/") => Severity::Medium,
            None => continue,
        };
        let why = if issues.is_empty() { String::new() } else { format!(" Suspicious: {}.", reasons(&issues)) };
        col.push(
            Finding::new(severity, MODULE, "INT-GRUB-SCRIPT", format!("Boot menu script that no package installed: {path}"))
                .evidence(path.clone())
                .description(format!("GRUB runs these scripts as root when the boot menu is rebuilt and puts their output in the menu.{why}"))
                .verify(format!("cat {}", shq(&path))),
        );
    }
}

/// The installed kernel files against the checksums of their packages.
fn check_kernel_files(ctx: &ScanCtx, col: &mut Collector) {
    if ctx.sys.dir_names("/var/lib/dpkg/info").is_empty() {
        return;
    }
    let kernels: Vec<String> = ctx.sys.dir_names("/boot").into_iter().filter(|n| n.starts_with("vmlinuz-") || n.starts_with("System.map-")).map(|n| format!("/boot/{n}")).filter(|p| ctx.sys.read_bytes(p).is_ok()).collect();
    let mut verdicts: Vec<(String, Verdict)> = verify_paths(ctx.sys, &kernels, SystemTime::UNIX_EPOCH).into_iter().collect();
    verdicts.sort_by(|a, b| a.0.cmp(&b.0));
    for (path, verdict) in verdicts {
        let (severity, title, text) = match &verdict {
            Verdict::Differs { package } => (Severity::Critical, format!("Kernel file differs from its package: {path}"), format!("package {package}: the content does not match")),
            Verdict::NotPackaged if path.contains("/vmlinuz-") => (Severity::Low, format!("Kernel that no package installed: {path}"), "no package owns this kernel".to_string()),
            _ => continue,
        };
        col.push(
            Finding::new(severity, MODULE, "INT-KERNEL-FILE", title)
                .evidence(format!("{path}\n{text}"))
                .description("The kernel controls everything on the machine. A changed one can hide anything; a kernel you built yourself also shows up here.")
                .verify(format!("dpkg -S {}", shq(&path)))
                .verify("dpkg --verify $(dpkg -S /boot/vmlinuz-* | cut -d: -f1)"),
        );
    }
}

/// Kernel messages that mean the disk or file system is failing.
pub fn disk_error_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    const SIGNS: [&str; 7] = ["I/O error", "EXT4-fs error", "BTRFS error", "XFS (", "Medium Error", "critical medium error", "Buffer I/O error"];
    lines
        .filter(|l| SIGNS.iter().any(|s| l.contains(s)))
        // XFS also reports normal mounts
        .filter(|l| !l.contains("XFS (") || l.to_lowercase().contains("error") || l.to_lowercase().contains("corrupt"))
        .collect()
}

fn check_disk_errors(ctx: &ScanCtx, col: &mut Collector) {
    let mut evidence = Vec::new();
    for device in ctx.sys.dir_names("/sys/fs/ext4") {
        let count: u64 = ctx.sys.read_string(format!("/sys/fs/ext4/{device}/errors_count")).ok().and_then(|v| v.trim().parse().ok()).unwrap_or(0);
        if count > 0 {
            evidence.push(format!("ext4 on {device}: {count} recorded error(s)"));
        }
    }
    if ctx.sys.is_live() {
        if let Some(journalctl) = crate::external_tools::find_binary("journalctl") {
            let since = format!("--since=-{}days", ctx.cfg.log_days.max(1));
            let args = ["--no-pager", "-q", "-o", "short-iso", "-k", "-p", "err", "-n", "20000", since.as_str()];
            if let Ok(o) = crate::external_tools::run_capture(&journalctl, &args, 60) {
                let lines = disk_error_lines(o.stdout.lines());
                let more = lines.len().saturating_sub(8);
                evidence.extend(lines.iter().skip(more).map(|l| clip(l, 200)));
                if more > 0 {
                    evidence.push(format!("… and {more} earlier line(s)"));
                }
            }
        }
    }
    if evidence.is_empty() {
        return;
    }
    col.push(
        Finding::new(Severity::Low, MODULE, "INT-DISK-ERRORS", "The disk or file system reported errors")
            .evidence(evidence.join("\n"))
            .description("Failing hardware damages files and logs, which can look like tampering. Check the disk (SMART) before you blame an intruder, and keep a backup.")
            .verify("journalctl -k -p err --since=-28days")
            .verify("smartctl -H /dev/<disk>   # package smartmontools"),
    );
}

// ---------------------------------------------------------------- shim and GRUB on the EFI partition

/// The package files that a boot file on the EFI partition may be a copy of.
fn efi_originals(name: &str) -> Vec<String> {
    // "shimx64.efi" → shim, x64
    let Some(stem) = name.strip_suffix(".efi") else { return Vec::new() };
    let Some((program, arch)) = ["x64", "aa64", "ia32"].iter().find_map(|a| stem.strip_suffix(a).map(|p| (p, *a))) else { return Vec::new() };
    let platform = match arch {
        "aa64" => "arm64-efi",
        "ia32" => "i386-efi",
        _ => "x86_64-efi",
    };
    let shim = |n: &str| vec![format!("/usr/lib/shim/{n}{arch}.efi.signed"), format!("/usr/lib/shim/{n}{arch}.efi")];
    let grub = |n: &str| vec![format!("/usr/lib/grub/{platform}-signed/{n}{arch}.efi.signed"), format!("/usr/lib/grub/{platform}/monolithic/{n}{arch}.efi")];
    match program {
        "shim" | "mm" | "fb" => shim(program),
        "grub" => [grub("grub"), grub("gcd"), grub("grubnet")].concat(),
        "fwupd" => vec![format!("/usr/lib/fwupd/efi/fwupd{arch}.efi.signed"), format!("/usr/lib/fwupd/efi/fwupd{arch}.efi")],
        // the name the firmware starts when no entry says otherwise
        "boot" => [shim("shim"), grub("grub"), shim("fb")].concat(),
        _ => Vec::new(),
    }
}

/// Compare Debian's boot files on the EFI partition with the copies the packages installed.
fn check_efi_files(ctx: &ScanCtx, col: &mut Collector) {
    let Some(esp) = ["/boot/efi/EFI", "/efi/EFI", "/boot/EFI"].into_iter().find(|d| !ctx.sys.dir_names(d).is_empty()) else {
        if ctx.sys.exists("/sys/firmware/efi") && !ctx.privileged {
            col.note("integrity: the EFI partition can only be read as root");
        }
        return;
    };
    let mut files = Vec::new();
    for vendor in ctx.sys.dir_names(esp).into_iter().filter(|v| v.eq_ignore_ascii_case("debian") || v.eq_ignore_ascii_case("boot")) {
        for name in ctx.sys.dir_names(format!("{esp}/{vendor}")) {
            if name.to_ascii_lowercase().ends_with(".efi") {
                files.push((vendor.eq_ignore_ascii_case("boot"), name.to_ascii_lowercase(), format!("{esp}/{vendor}/{name}")));
            }
        }
    }
    let (mut changed, mut older, mut fallback, mut unknown) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for (removable, name, path) in files {
        let Ok(data) = ctx.sys.read_bytes(&path) else { continue };
        let originals: Vec<String> = efi_originals(&name).into_iter().filter(|o| ctx.sys.exists(o)).collect();
        // Windows keeps its own loader under the standard name too
        if originals.is_empty() {
            if !removable {
                unknown.push(format!("{path}: no package on this system has a copy to compare with"));
            }
            continue;
        }
        if originals.iter().any(|o| ctx.sys.read_bytes(o).map(|d| d == data).unwrap_or(false)) {
            continue;
        }
        let written = |p: &str| std::fs::metadata(ctx.sys.path(p)).ok().and_then(|m| m.modified().ok());
        // a file from before the package's newest copy was simply not written again
        let newest = originals.iter().filter_map(|o| written(o)).max();
        let line = format!("{path} differs from {}", originals[0]);
        if removable {
            fallback.push(line);
        } else if written(&path).zip(newest).is_some_and(|(esp, package)| esp < package) {
            older.push(line);
        } else {
            changed.push(line);
        }
    }
    // the originals themselves must be what their packages ship
    let originals: Vec<String> = ["shimx64", "mmx64", "fbx64"].iter().map(|n| format!("/usr/lib/shim/{n}.efi.signed")).chain(["/usr/lib/grub/x86_64-efi-signed/grubx64.efi.signed".to_string()]).filter(|p| ctx.sys.exists(p)).collect();
    for (path, verdict) in verify_paths(ctx.sys, &originals, SystemTime::UNIX_EPOCH) {
        if let Verdict::Differs { package } = verdict {
            changed.push(format!("{path} differs from what package {package} ships"));
        }
    }
    for (severity, mut lines, title, text) in [
        (Severity::High, changed, "A boot file does not match its package", "These start before the operating system. A changed one can take over everything. Compare, then restore with: sudo apt install --reinstall shim-signed grub-efi-amd64-signed && sudo grub-install."),
        (Severity::Medium, older, "A boot file is older than the installed package", "The package was updated but the file on the EFI partition was not written again; sudo grub-install does that."),
        (Severity::Low, fallback, "The fallback boot file differs from the installed packages", "EFI/BOOT is started when no other entry works. It is often an old copy from the installation; grub-install --force-extra-removable refreshes it."),
        (Severity::Info, unknown, "Boot files without a package copy to compare with", "Firmware updaters and other tools put their own files here."),
    ] {
        if lines.is_empty() {
            continue;
        }
        lines.sort();
        col.push(
            Finding::new(severity, MODULE, "INT-EFI-FILE", title)
                .evidence(lines.join("\n"))
                .description(text)
                .verify(format!("sha256sum {esp}/debian/*.efi /usr/lib/shim/*.signed /usr/lib/grub/*-signed/*.signed"))
                .verify(format!("ls -l --time-style=full-iso {esp}/debian {esp}/BOOT")),
        );
    }
}

pub(crate) fn run(ctx: &ScanCtx, col: &mut Collector) {
    check_efi_files(ctx, col);
    check_boot_options(ctx, col);
    check_grub_scripts(ctx, col);
    check_kernel_files(ctx, col);
    check_disk_errors(ctx, col);
}
