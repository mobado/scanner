//! The common finding structure that every module produces.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Severity. The order is Info < Low < Medium < High < Critical,
/// so `sort` + `rev` puts Critical first. Info is ordinary activity worth knowing about: it
/// never changes the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// From most to least severe.
    pub const ALL_DESC: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Label for the terminal and the window.
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    /// ANSI colour code for terminal output.
    pub fn ansi(&self) -> &'static str {
        match self {
            Severity::Info => "\x1b[37m",
            Severity::Low => "\x1b[36m",
            Severity::Medium => "\x1b[33m",
            Severity::High => "\x1b[31m",
            Severity::Critical => "\x1b[1;37;41m",
        }
    }

    /// Raise one step (Critical stays).
    pub fn bump(self) -> Severity {
        match self {
            Severity::Info => Severity::Low,
            Severity::Low => Severity::Medium,
            Severity::Medium => Severity::High,
            Severity::High | Severity::Critical => Severity::Critical,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "info" | "i" => Ok(Severity::Info),
            "low" | "l" => Ok(Severity::Low),
            "medium" | "med" | "m" => Ok(Severity::Medium),
            "high" | "h" => Ok(Severity::High),
            "critical" | "crit" | "c" => Ok(Severity::Critical),
            other => Err(format!(
                "unknown severity '{other}' (use info, low, medium, high or critical)"
            )),
        }
    }
}

/// A finding from a module.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub severity: Severity,
    /// The module that found it (net_proc, proc_audit, fs_perms, persistence, baseline, external:debsums ...).
    pub module: String,
    /// Stable rule id, e.g. `NET-REVSHELL`. Used by tests and whitelists.
    #[serde(default)]
    pub rule: String,
    pub title: String,
    /// Raw evidence: paths, command lines, file lines.
    pub evidence: String,
    /// Explanation of why it is suspicious.
    pub description: String,
    /// Concrete commands for manual verification.
    #[serde(default)]
    pub verify: Vec<String>,
    /// About a user's own files (autostart, shell files, settings): something to review,
    /// not a change to the system.
    #[serde(default)]
    pub user_level: bool,
}

impl Finding {
    pub fn new(severity: Severity, module: &str, rule: &str, title: impl Into<String>) -> Self {
        Finding {
            severity,
            module: module.to_string(),
            rule: rule.to_string(),
            title: title.into(),
            evidence: String::new(),
            description: String::new(),
            verify: Vec::new(),
            user_level: false,
        }
    }

    pub fn evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence = e.into();
        self
    }

    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    pub fn verify(mut self, cmd: impl Into<String>) -> Self {
        self.verify.push(cmd.into());
        self
    }

    pub fn verify_all<I, S>(mut self, cmds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.verify.extend(cmds.into_iter().map(Into::into));
        self
    }
}

/// Commands that only work (or only show everything) as root.
const ROOT_COMMANDS: [&str; 26] = [
    "lynis", "chkrootkit", "rkhunter", "sshd ", "visudo", "passwd ", "dmesg", "debsums", "unhide",
    "cat /proc/", "ls -l /proc/", "sha256sum /proc/", "cp /proc/", "find /proc/", "ss -tulp", "ss -tunap",
    "crontab -l -u", "cat /var/spool", "cat /root", "ssh-keygen -lf /root", "stat /root",
    "grep -A5 Warning /var/log/rkhunter.log", "grep suggestion /var/log/lynis-report.dat", "grep -c warning /var/log/lynis",
    "cat /var/log/lynis", "ls -l /var/spool/cron",
];

fn sudo_segment(seg: &str) -> String {
    let t = seg.trim_start();
    let lead = &seg[..seg.len() - t.len()];
    if ROOT_COMMANDS.iter().any(|p| t.starts_with(p)) {
        format!("{lead}sudo {t}")
    } else {
        seg.to_string()
    }
}

/// Put `sudo` in front of the commands that need root, so a copied command just works:
/// `lynis show details X` becomes `sudo lynis show details X`. Commands chained with
/// `;` or `&&` are handled one by one; a command that already uses sudo is left alone.
pub fn sudoize(cmd: &str) -> String {
    if cmd.contains("sudo") {
        return cmd.to_string();
    }
    let mut out = String::new();
    let mut rest = cmd;
    loop {
        let next = [("; ", rest.find("; ")), (" && ", rest.find(" && "))]
            .into_iter()
            .filter_map(|(sep, i)| i.map(|i| (i, sep)))
            .min();
        match next {
            Some((i, sep)) => {
                out.push_str(&sudo_segment(&rest[..i]));
                out.push_str(sep);
                rest = &rest[i + sep.len()..];
            }
            None => {
                out.push_str(&sudo_segment(rest));
                break;
            }
        }
    }
    out
}

/// Sort: most severe first, then module and title for a stable order.
pub fn sort_findings(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.evidence.cmp(&b.evidence))
    });
}
