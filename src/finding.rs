//! The common finding structure that every module produces.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Severity. The order is Low < Medium < High < Critical,
/// so `sort` + `rev` puts Critical first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// From most to least severe.
    pub const ALL_DESC: [Severity; 4] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Label for the terminal and the window.
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    /// ANSI colour code for terminal output.
    pub fn ansi(&self) -> &'static str {
        match self {
            Severity::Low => "\x1b[36m",
            Severity::Medium => "\x1b[33m",
            Severity::High => "\x1b[31m",
            Severity::Critical => "\x1b[1;37;41m",
        }
    }

    /// Raise one step (Critical stays).
    pub fn bump(self) -> Severity {
        match self {
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
            "low" | "l" => Ok(Severity::Low),
            "medium" | "med" | "m" => Ok(Severity::Medium),
            "high" | "h" => Ok(Severity::High),
            "critical" | "crit" | "c" => Ok(Severity::Critical),
            other => Err(format!(
                "unknown severity '{other}' (use low, medium, high or critical)"
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
