//! kernel: loaded and hidden modules, module taint, dangerous kernel settings and
//! modprobe commands – places rootkits and container escapes use.

use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_command, max_severity, reasons, shq};
use std::collections::BTreeMap;

pub const MODULE: &str = "kernel";

/// name → taint letters from /proc/modules ("nvidia 123 0 - Live 0x0 (POE)").
pub fn parse_modules(text: &str) -> BTreeMap<String, String> {
    text.lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let name = f.first()?.to_string();
            let taint = f.iter().skip(5).find(|t| t.starts_with('(')).map(|t| t.trim_matches(|c| c == '(' || c == ')' || c == '+' || c == '-').to_string()).unwrap_or_default();
            Some((name, taint))
        })
        .collect()
}

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    check_modules(ctx, col);
    check_sysctl(ctx, col);
    check_modprobe_config(ctx, col);
    super::kernelstate::run(ctx, col);
}

fn check_modules(ctx: &ScanCtx, col: &mut Collector) {
    let Ok(text) = ctx.sys.read_string("/proc/modules") else {
        col.note("kernel: /proc/modules could not be read – module checks skipped");
        return;
    };
    let loaded = parse_modules(&text);
    // Loadable modules have an "initstate" file; built-in ones don't.
    let mut in_sys = Vec::new();
    for name in ctx.sys.dir_names("/sys/module") {
        if let Ok(state) = ctx.sys.read_string(format!("/sys/module/{name}/initstate")) {
            if state.trim() == "live" {
                in_sys.push(name);
            }
        }
    }
    let mut hidden: Vec<String> = in_sys.iter().filter(|m| !loaded.contains_key(*m)).cloned().collect();
    // A module being loaded or removed right now would appear on one side only: look again.
    if !hidden.is_empty() && ctx.sys.is_live() {
        std::thread::sleep(std::time::Duration::from_millis(300));
        let again = ctx.sys.read_string("/proc/modules").map(|t| parse_modules(&t)).unwrap_or_default();
        hidden.retain(|m| !again.contains_key(m) && ctx.sys.exists(format!("/sys/module/{m}/initstate")));
    }
    for m in hidden {
        col.push(
            Finding::new(Severity::High, MODULE, "KERN-MODULE-HIDDEN", format!("Kernel module hidden from the module list: {m}"))
                .evidence(format!("/sys/module/{m} says the module is loaded, but /proc/modules (lsmod) does not list it"))
                .description("Kernel rootkits remove themselves from the module list to hide. Check this module; if it is unknown, treat the machine as compromised and investigate from trusted boot media.")
                .verify(format!("ls /sys/module/{}", shq(&m)))
                .verify(format!("modinfo {}", shq(&m)))
                .verify("lsmod"),
        );
    }
    let mut untrusted = Vec::new();
    for (name, taint) in &loaded {
        let lower = name.to_lowercase();
        if ctx.cfg.known_rootkit_modules.iter().any(|r| lower == r.to_lowercase()) {
            col.push(
                Finding::new(Severity::Critical, MODULE, "KERN-ROOTKIT-NAME", format!("Known rootkit kernel module loaded: {name}"))
                    .evidence(format!("/proc/modules: {name} ({taint})"))
                    .description("The name matches a known kernel rootkit. Do not trust anything this system reports; investigate from trusted boot media.")
                    .verify(format!("modinfo {}", shq(name))),
            );
        }
        // O = built outside the kernel, E = not signed, F = forced
        if taint.chars().any(|c| matches!(c, 'O' | 'E' | 'F')) && !ctx.cfg.allowed_out_of_tree_modules.iter().any(|p| lower.starts_with(&p.to_lowercase())) {
            untrusted.push(format!("{name} ({taint})"));
        }
    }
    if !untrusted.is_empty() {
        col.push(
            Finding::new(Severity::Medium, MODULE, "KERN-MODULE-UNTRUSTED", "Kernel modules from outside the Debian kernel")
                .evidence(untrusted.join("\n"))
                .description("These modules were built outside the kernel (O), are unsigned (E) or were forced in (F). Drivers installed with DKMS look like this; rootkits too. Add the ones you know to allowed_out_of_tree_modules.")
                .verify("lsmod")
                .verify("dkms status 2>/dev/null")
                .verify("modinfo <module>"),
        );
    }
}

fn sysctl(ctx: &ScanCtx, key: &str) -> Option<String> {
    ctx.sys.read_string(format!("/proc/sys/{}", key.replace('.', "/"))).ok().map(|s| s.trim().to_string())
}

fn check_sysctl(ctx: &ScanCtx, col: &mut Collector) {
    let mut report = |sev: Severity, key: &str, value: &str, text: &str| {
        col.findings.push(
            Finding::new(sev, MODULE, "KERN-SYSCTL", format!("Dangerous kernel setting: {key}"))
                .evidence(format!("{key} = {value}"))
                .description(text)
                .verify(format!("sysctl {key}"))
                .verify(format!("grep -rn {} /etc/sysctl.d /etc/sysctl.conf /usr/lib/sysctl.d 2>/dev/null", shq(key))),
        );
    };
    if let Some(v) = sysctl(ctx, "kernel.modprobe") {
        if !["/sbin/modprobe", "/usr/sbin/modprobe", "/bin/false", "/usr/bin/false", ""].contains(&v.as_str()) {
            report(Severity::Critical, "kernel.modprobe", &v, "The kernel runs this program as root whenever it needs a module. Changing it is a classic root backdoor and container escape.");
        }
    }
    if let Some(v) = sysctl(ctx, "kernel.core_pattern") {
        if let Some(program) = v.strip_prefix('|') {
            let known = ["/usr/lib/systemd/systemd-coredump", "/lib/systemd/systemd-coredump", "/usr/share/apport/apport", "/usr/libexec/abrt-hook-ccpp", "/usr/lib/systemd/systemd", "/usr/bin/false"];
            let path = program.split_whitespace().next().unwrap_or("");
            if !known.contains(&path) {
                let sev = if ctx.cfg.is_temp_path(path) || path.starts_with("/home/") || path.starts_with("/proc/") { Severity::Critical } else { Severity::High };
                report(sev, "kernel.core_pattern", &v, "When any program crashes, the kernel runs this command as root. Container escapes and backdoors set it to their own program.");
            }
        }
    }
    if let Some(v) = sysctl(ctx, "kernel.hotplug") {
        if !v.is_empty() && v != "/bin/false" {
            report(Severity::High, "kernel.hotplug", &v, "A hotplug helper runs as root on device events; Debian leaves it empty.");
        }
    }
    for (key, bad, sev, text) in [
        ("kernel.randomize_va_space", "0", Severity::Medium, "Address space randomisation is off, which makes exploits much easier. Debian's default is 2."),
        ("fs.protected_symlinks", "0", Severity::Medium, "Symlink protection is off, allowing attacks through /tmp. Debian's default is 1."),
        ("fs.protected_hardlinks", "0", Severity::Medium, "Hardlink protection is off. Debian's default is 1."),
        ("kernel.dmesg_restrict", "0", Severity::Low, "Every user can read kernel messages, which helps attackers. Debian's default is 1."),
        ("fs.suid_dumpable", "1", Severity::Low, "Memory dumps of privileged programs are readable, which can leak secrets."),
        ("kernel.unprivileged_bpf_disabled", "0", Severity::Low, "Every user may load eBPF programs; eBPF is used by modern rootkits and exploits. Debian's default is 2."),
    ] {
        if sysctl(ctx, key).as_deref() == Some(bad) {
            report(sev, key, bad, text);
        }
    }
}

fn check_modprobe_config(ctx: &ScanCtx, col: &mut Collector) {
    for dir in ["/etc/modprobe.d", "/run/modprobe.d"] {
        for name in ctx.sys.dir_names(dir) {
            let path = format!("{dir}/{name}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            crate::modules::persistence::record(ctx, col, &path);
            for (i, line) in text.lines().enumerate() {
                let t = line.trim();
                let Some(rest) = t.strip_prefix("install ").or_else(|| t.strip_prefix("remove ")) else { continue };
                let command = rest.split_once(char::is_whitespace).map(|(_, c)| c).unwrap_or("");
                let issues = analyze_command(command, ctx.cfg);
                if let Some(sev) = max_severity(&issues).filter(|s| *s >= Severity::High) {
                    col.push(
                        Finding::new(sev, MODULE, "KERN-MODPROBE-CMD", format!("Suspicious modprobe command in {path}"))
                            .evidence(format!("{path}:{}: {t}", i + 1))
                            .description(format!("modprobe runs this command as root when the module is loaded. Suspicious: {}.", reasons(&issues)))
                            .verify(format!("cat {}", shq(&path))),
                    );
                }
            }
        }
    }
    for path in ["/etc/modules"] {
        crate::modules::persistence::record(ctx, col, path);
    }
    for name in ctx.sys.dir_names("/etc/modules-load.d") {
        crate::modules::persistence::record(ctx, col, &format!("/etc/modules-load.d/{name}"));
    }
}
