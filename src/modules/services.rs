//! services: web shells in web folders, and risky container setups.

use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, mode_string, shq};
use crate::modules::net_proc::{parse_proc_net, Proto};
use crate::procinfo::status_field;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use walkdir::WalkDir;

pub const MODULE: &str = "services";

const MAX_FILES: usize = 40_000;
const MAX_BYTES: u64 = 1024 * 1024;

/// Code that runs whatever a web visitor sends (spaces removed, lower case).
const SHELL_PATTERNS: [&str; 17] = [
    "eval($_post", "eval($_get", "eval($_request", "eval($_cookie", "assert($_", "system($_", "exec($_", "passthru($_", "shell_exec($_",
    "popen($_", "proc_open($_", "eval(base64_decode(", "eval(gzinflate(", "eval(str_rot13(", "eval(gzuncompress(",
    "runtime.getruntime().exec(request", "preg_replace(\"/.*/e\"",
];

pub fn webshell_pattern(content: &str) -> Option<&'static str> {
    let squeezed: String = content.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_lowercase();
    SHELL_PATTERNS.iter().copied().find(|p| squeezed.contains(p))
}

pub fn run(ctx: &ScanCtx, col: &mut Collector) {
    check_web_roots(ctx, col);
    check_docker(ctx, col);
    check_containers(ctx, col);
}

fn check_web_roots(ctx: &ScanCtx, col: &mut Collector) {
    let mut seen = 0usize;
    let mut found = 0usize;
    for root in &ctx.cfg.web_roots {
        let real = ctx.sys.path(root);
        if !real.is_dir() {
            continue;
        }
        for entry in WalkDir::new(&real).max_depth(10).follow_links(false).into_iter().filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }
            seen += 1;
            if seen > MAX_FILES {
                col.note(format!("services: stopped after {MAX_FILES} web files"));
                return;
            }
            let name = entry.file_name().to_string_lossy().to_lowercase();
            let ext = name.rsplit('.').next().unwrap_or("");
            if !["php", "phtml", "php3", "php4", "php5", "php7", "phar", "jsp", "jspx", "cgi", "inc"].contains(&ext) {
                continue;
            }
            let mut buf = Vec::new();
            let Ok(file) = crate::sys::open_plain_file(entry.path()) else { continue };
            if file.take(MAX_BYTES).read_to_end(&mut buf).is_err() {
                continue;
            }
            let text = String::from_utf8_lossy(&buf);
            let shown = ctx.sys.display(entry.path());
            if let Some(pattern) = webshell_pattern(&text) {
                found += 1;
                if found > 50 {
                    continue;
                }
                let direct = pattern.contains("$_") || pattern.contains("request");
                let line = text.lines().find(|l| webshell_pattern(l).is_some()).unwrap_or("");
                col.push(
                    Finding::new(if direct { Severity::Critical } else { Severity::High }, MODULE, "SVC-WEBSHELL", format!("Possible web shell: {shown}"))
                        .evidence(format!("{shown}: contains {pattern}\n{}", clip(line.trim(), 240)))
                        .description("The file runs commands or code that a web visitor sends – the way attackers keep control of a web server. Some obfuscated plug-ins look similar; compare with a clean copy of the application.")
                        .verify(format!("ls -l --time-style=full-iso {}", shq(&shown)))
                        .verify(format!("grep -nE 'eval|system|exec|base64_decode' {}", shq(&shown))),
                );
            }
        }
    }
}

fn check_docker(ctx: &ScanCtx, col: &mut Collector) {
    let mut sockets: Vec<String> = ["/run/docker.sock", "/run/podman/podman.sock", "/run/containerd/containerd.sock"].map(String::from).to_vec();
    // rootless Podman and Docker keep a socket for each user
    for user in ctx.sys.dir_names("/run/user") {
        sockets.extend([format!("/run/user/{user}/podman/podman.sock"), format!("/run/user/{user}/docker.sock")]);
    }
    for sock in sockets {
        if let Ok(m) = std::fs::symlink_metadata(ctx.sys.path(&sock)) {
            if m.mode() & 0o002 != 0 {
                col.push(
                    Finding::new(Severity::Critical, MODULE, "SVC-CONTAINER-SOCKET", format!("Everyone can control the container engine: {sock}"))
                        .evidence(format!("{sock} mode {}", mode_string(m.mode())))
                        .description("Access to this socket is the same as root on the whole machine.")
                        .verify(format!("stat {sock}")),
                );
            }
        }
    }
    for p in ctx.processes.iter().filter(|p| p.display_name() == "podman") {
        let words = &p.cmdline;
        if words.iter().any(|w| w == "service") && words.iter().any(|w| w.starts_with("tcp:")) {
            col.push(
                Finding::new(Severity::High, MODULE, "SVC-PODMAN-API", "Podman's control service listens on the network")
                    .evidence(format!("PID {} UID {}\ncmdline=\"{}\"", p.pid, p.uid, clip(&p.cmdline_str(), 300)))
                    .description("Anyone who reaches this port can start containers as this user, and as root when root runs it. It has no password.")
                    .verify(format!("ss -tlnp | grep 'pid={},'", p.pid)),
            );
        }
    }
    for proto in [Proto::Tcp, Proto::Tcp6] {
        let Ok(text) = ctx.sys.read_string(proto.proc_file()) else { continue };
        for s in parse_proc_net(&text, proto).0 {
            if s.is_listening() && s.local.port() == 2375 && !s.local.ip().is_loopback() {
                col.push(
                    Finding::new(Severity::High, MODULE, "SVC-DOCKER-API", "Docker API open on the network without encryption (port 2375)")
                        .evidence(format!("listening on {}", s.local))
                        .description("Anyone who reaches this port can start containers as root on this machine.")
                        .verify("ss -tlnp | grep 2375"),
                );
                return;
            }
        }
    }
}

fn check_containers(ctx: &ScanCtx, col: &mut Collector) {
    let mut privileged = Vec::new();
    let mut with_socket = Vec::new();
    for p in ctx.processes {
        if p.is_kernel_thread() {
            continue;
        }
        let Ok(cgroup) = ctx.sys.read_string(format!("/proc/{}/cgroup", p.pid)) else { continue };
        if !["docker", "libpod", "containerd", "kubepods", "lxc"].iter().any(|m| cgroup.contains(&format!("{m}-")) || cgroup.contains(&format!("/{m}/"))) {
            continue;
        }
        let status = ctx.sys.read_string(format!("/proc/{}/status", p.pid)).unwrap_or_default();
        let caps = status_field(&status, "CapEff").and_then(|c| u64::from_str_radix(c, 16).ok()).unwrap_or(0);
        // CAP_SYS_ADMIN (21) and CAP_SYS_MODULE (16)
        if caps & (1 << 21) != 0 && caps & (1 << 16) != 0 {
            privileged.push(format!("PID {} {} (CapEff {caps:x})", p.pid, clip(&p.cmdline_str(), 120)));
        }
        if let Ok(mounts) = ctx.sys.read_string(format!("/proc/{}/mountinfo", p.pid)) {
            if mounts.contains("docker.sock") {
                with_socket.push(format!("PID {} {}", p.pid, clip(&p.cmdline_str(), 120)));
            }
        }
    }
    let mut report = |rule: &str, title: &str, list: Vec<String>, text: &str| {
        if !list.is_empty() {
            col.findings.push(
                Finding::new(Severity::High, MODULE, rule, title)
                    .evidence(list.into_iter().take(15).collect::<Vec<_>>().join("\n"))
                    .description(text)
                    .verify("docker ps --no-trunc 2>/dev/null; podman ps 2>/dev/null")
                    .verify("docker inspect --format '{{.Name}} privileged={{.HostConfig.Privileged}} {{.HostConfig.Binds}}' $(docker ps -q) 2>/dev/null"),
            );
        }
    };
    report("SVC-CONTAINER-PRIVILEGED", "Privileged container processes", privileged, "A privileged container can load kernel modules and reach the host – a compromised program in it can take over the machine.");
    report("SVC-CONTAINER-SOCKET-MOUNT", "Container with access to the container engine", with_socket, "The engine's socket is mounted into a container, which gives it root on the host.");
}
