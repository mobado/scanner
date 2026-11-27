//! External Debian tools: debsums and lynis.
//!
//! Each tool is first looked up in PATH and in /usr/sbin, /sbin etc. If it is missing
//! a note is logged and the scan continues. The tools run with a timeout
//! and their output is turned into [`Finding`] entries.

use crate::config::Config;
use crate::error::ScanError;
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, shq};
use crate::modules::Collector;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum Tool {
    Debsums,
    Lynis,
}

impl Tool {
    pub const ALL: [Tool; 2] = [Tool::Debsums, Tool::Lynis];

    pub fn binary(&self) -> &'static str {
        match self {
            Tool::Debsums => "debsums",
            Tool::Lynis => "lynis",
        }
    }

    pub fn args(&self) -> &'static [&'static str] {
        match self {
            Tool::Debsums => &["-c"],
            Tool::Lynis => &["audit", "system", "--quick", "--no-colors"],
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Tool::Debsums => "Compares installed files with the package checksums",
            Tool::Lynis => "Security audit of the system (writes a report in /var/log)",
        }
    }

    pub fn module(&self) -> String {
        format!("external:{}", self.binary())
    }
}

impl std::str::FromStr for Tool {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.trim().to_ascii_lowercase();
        if name == "chkrootkit" || name == "rkhunter" {
            return Err(format!("{name} is no longer run by the scanner (since 0.14.0); use --tools debsums,lynis"));
        }
        Tool::ALL
            .iter()
            .find(|t| t.binary() == name)
            .copied()
            .ok_or_else(|| format!("unknown tool '{s}' (debsums, lynis)"))
    }
}

const EXTRA_DIRS: [&str; 6] = ["/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin", "/usr/bin", "/bin"];

/// Look up a program in PATH and in the usual sbin directories.
pub fn find_binary(name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    dirs.extend(EXTRA_DIRS.iter().map(PathBuf::from));
    dirs.into_iter().map(|d| d.join(name)).find(|p| {
        std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

pub fn availability() -> Vec<(Tool, Option<PathBuf>)> {
    Tool::ALL.iter().map(|t| (*t, find_binary(t.binary()))).collect()
}

#[derive(Debug, Clone, Default)]
pub struct CmdOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// Run a program, read stdout/stderr and stop after `timeout_secs`.
pub fn run_capture(program: &Path, args: &[&str], timeout_secs: u64) -> Result<CmdOutput, ScanError> {
    let tool = program.display().to_string();
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| ScanError::Tool { tool: tool.clone(), msg: e.to_string() })?;

    let mut out_pipe = child.stdout.take();
    let mut err_pipe = child.stderr.take();
    let out_t = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(p) = out_pipe.as_mut() {
            let _ = p.read_to_end(&mut s);
        }
        String::from_utf8_lossy(&s).into_owned()
    });
    let err_t = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(p) = err_pipe.as_mut() {
            let _ = p.read_to_end(&mut s);
        }
        String::from_utf8_lossy(&s).into_owned()
    });

    let start = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.code(),
            Ok(None) => {
                if start.elapsed() > Duration::from_secs(timeout_secs) {
                    let _ = child.kill();
                    let _ = child.wait();
                    timed_out = true;
                    break None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(ScanError::Tool { tool, msg: e.to_string() }),
        }
    };
    Ok(CmdOutput {
        status,
        stdout: out_t.join().unwrap_or_default(),
        stderr: err_t.join().unwrap_or_default(),
        timed_out,
    })
}

/// Run a tool if it exists and put the findings in `col`.
pub fn run_tool(tool: Tool, cfg: &Config, col: &mut Collector) {
    let Some(bin) = find_binary(tool.binary()) else {
        col.note(format!(
            "{} is missing – skipped (install with: apt install {})",
            tool.binary(),
            tool.binary()
        ));
        return;
    };
    let out = match run_capture(&bin, tool.args(), cfg.external_tool_timeout_secs) {
        Ok(o) => o,
        Err(e) => {
            col.note(e.to_string());
            return;
        }
    };
    if out.timed_out {
        col.note(format!("{} was stopped after {} s", tool.binary(), cfg.external_tool_timeout_secs));
    }
    let findings = match tool {
        Tool::Debsums => parse_debsums(&out.stdout, &out.stderr),
        Tool::Lynis => {
            let report = std::fs::read_to_string("/var/log/lynis-report.dat").unwrap_or_default();
            parse_lynis(&out.stdout, &report)
        }
    };
    col.note(format!(
        "{} ran ({}) and gave {} finding(s)",
        tool.binary(),
        bin.display(),
        findings.len()
    ));
    col.findings.extend(findings);
}

fn debsums_severity(path: &str) -> Severity {
    let bin_dirs = ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/libexec/", "/lib/modules/", "/usr/lib/modules/", "/boot/"];
    if bin_dirs.iter().any(|d| path.starts_with(d)) || path.ends_with(".so") || path.contains(".so.") || path.contains("/security/") {
        Severity::Critical
    } else if path.starts_with("/usr/share/") {
        Severity::Low
    } else if path.starts_with("/etc/") {
        Severity::Medium
    } else {
        Severity::High
    }
}

/// `debsums -c` prints changed files on stdout (one per line) and
/// "debsums: missing file X (from Y package)" / "changed file" on stderr.
pub fn parse_debsums(stdout: &str, stderr: &str) -> Vec<Finding> {
    let module = Tool::Debsums.module();
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut changed = |path: &str, pkg: Option<&str>, out: &mut Vec<Finding>| {
        if !seen.insert(path.to_string()) {
            return;
        }
        let sev = debsums_severity(path);
        out.push(
            Finding::new(sev, &module, "EXT-DEBSUMS-CHANGED", format!("Changed package file: {path}"))
                .evidence(format!("debsums -c: {path}{}", pkg.map(|p| format!(" (package {p})")).unwrap_or_default()))
                .description("The file's checksum does not match the installed .deb package. System binaries and libraries changed outside apt are a strong sign of intrusion (or a local change that should be documented).")
                .verify(format!("dpkg -S {}", shq(path)))
                .verify(format!("debsums -s \"$(dpkg -S {} | cut -d: -f1)\"", shq(path)))
                .verify(format!("ls -l --time-style=full-iso {}", shq(path)))
                .verify(format!("apt-get download \"$(dpkg -S {} | cut -d: -f1)\"   # compare with the original", shq(path))),
        );
    };
    for line in stdout.lines().map(|l| l.trim()) {
        if line.starts_with('/') {
            changed(line, None, &mut out);
        }
    }
    for line in stderr.lines().map(|l| l.trim()) {
        let rest = line.strip_prefix("debsums: ").unwrap_or(line);
        let pkg = rest
            .split("(from ")
            .nth(1)
            .and_then(|r| r.split_whitespace().next());
        if let Some(r) = rest.strip_prefix("changed file ") {
            let path = r.split(" (from").next().unwrap_or(r).trim();
            changed(path, pkg, &mut out);
        } else if let Some(r) = rest.strip_prefix("missing file ") {
            let path = r.split(" (from").next().unwrap_or(r).trim();
            out.push(
                Finding::new(Severity::Low, &module, "EXT-DEBSUMS-MISSING", format!("Missing package file: {path}"))
                    .evidence(line.to_string())
                    .description("A file the package installed no longer exists. Usually removed documentation (dpkg path-exclude), but a removed system file can also be a trace of an intrusion.")
                    .verify(format!("dpkg -S {}", shq(path))),
            );
        }
    }
    // Several changed documentation/theme files (Low, under /usr/share) become one finding.
    let (low, mut rest): (Vec<Finding>, Vec<Finding>) = out.into_iter().partition(|f| f.rule == "EXT-DEBSUMS-CHANGED" && f.severity == Severity::Low);
    if low.len() >= 3 {
        let files: Vec<String> = low.iter().map(|f| f.title.trim_start_matches("Changed package file: ").to_string()).collect();
        rest.push(
            Finding::new(Severity::Low, &module, "EXT-DEBSUMS-CHANGED", format!("{} documentation/data files differ from their packages", files.len()))
                .evidence(files.join("\n"))
                .description("These files under /usr/share do not match their .deb packages. They are not programs, so this is usually a local edit or a package script that rewrote them. Programs and libraries that differ are reported separately and are far more serious.")
                .verify("debsums -c")
                .verify("dpkg -S <file>"),
        );
    } else {
        rest.extend(low);
    }
    rest
}

/// What a Lynis warning id means in plain words.
fn lynis_note(id: &str) -> String {
    match id {
        "PKGS-7392" => "Lynis found installed packages with known vulnerabilities, which usually means security updates are waiting. The \"updates\" check of this scanner lists them; install them with: apt update && apt upgrade (as root).".into(),
        "TIME-3185" => "systemd-timesyncd has not synchronised the clock recently (for example because the computer was offline). A wrong clock breaks logs and certificates. Check: timedatectl timesync-status.".into(),
        _ => "Lynis reports a warning in the security audit. Run the command below for Lynis's own explanation.".into(),
    }
}

/// Lynis: warnings from the report file (warning[]=ID|text|…) or from the output ("! text [ID]").
pub fn parse_lynis(stdout: &str, report_dat: &str) -> Vec<Finding> {
    let module = Tool::Lynis.module();
    let mut warnings: Vec<(String, String)> = report_dat
        .lines()
        .filter_map(|l| l.strip_prefix("warning[]="))
        .map(|w| {
            let mut p = w.split('|');
            let id = p.next().unwrap_or("").to_string();
            let text = p.next().unwrap_or("").to_string();
            (id, text)
        })
        .collect();
    if warnings.is_empty() {
        for l in stdout.lines().map(|l| l.trim()) {
            if let Some(rest) = l.strip_prefix("! ") {
                let id = rest.rsplit('[').next().map(|s| s.trim_end_matches(']').to_string()).unwrap_or_default();
                let text = rest.split(" [").next().unwrap_or(rest).to_string();
                warnings.push((id, text));
            }
        }
    }
    let suggestions = report_dat.lines().filter(|l| l.starts_with("suggestion[]=")).count();
    let mut out: Vec<Finding> = warnings
        .into_iter()
        .map(|(id, text)| {
            Finding::new(Severity::Medium, &module, "EXT-LYNIS-WARN", format!("Lynis: {}", clip(&text, 120)))
                .evidence(format!("{id}: {text}"))
                .description(lynis_note(&id))
                .verify(format!("sudo lynis show details {}", shq(&id)))
        })
        .collect();
    if suggestions > 0 {
        out.push(
            Finding::new(Severity::Low, &module, "EXT-LYNIS-SUGGEST", format!("Lynis has {suggestions} hardening suggestions"))
                .evidence({
                    let mut lines: Vec<String> = report_dat
                        .lines()
                        .filter_map(|l| l.strip_prefix("suggestion[]="))
                        .map(|l| {
                            let mut p = l.split('|');
                            format!("{}: {}", p.next().unwrap_or(""), p.next().unwrap_or(""))
                        })
                        .take(15)
                        .collect();
                    if suggestions > 15 {
                        lines.push(format!("… and {} more (see the verification command)", suggestions - 15));
                    }
                    lines.join("\n")
                })
                .description("Hardening suggestions – no signs of intrusion in themselves. The first ones are listed below; each ID can be looked up with lynis show details.")
                .verify("grep suggestion /var/log/lynis-report.dat"),
        );
    }
    out
}
