//! Final report: summary, sorting (Critical first), JSON and readable text.

use crate::finding::{sort_findings, Finding, Severity};
use crate::modules::Inventory;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Summary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total: usize,
}

impl Summary {
    pub fn count(&self, s: Severity) -> usize {
        match s {
            Severity::Critical => self.critical,
            Severity::High => self.high,
            Severity::Medium => self.medium,
            Severity::Low => self.low,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictLevel {
    Clean,
    Minor,
    Attention,
    Alarm,
}

#[derive(Debug, Clone)]
pub struct Verdict {
    pub level: VerdictLevel,
    pub headline: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub scanner: String,
    pub version: String,
    pub generated_at: String,
    pub hostname: String,
    pub kernel: String,
    pub os: String,
    pub running_as_root: bool,
    pub scan_root: String,
    pub duration_ms: u128,
    pub modules: Vec<String>,
    pub tools_run: Vec<String>,
    pub baseline_compared: Option<String>,
    /// Set when the scanner saved a baseline by itself during this scan.
    #[serde(default)]
    pub baseline_auto_saved: Option<String>,
    /// Files that changed since the baseline but were verified as apt upgrades.
    #[serde(default)]
    pub upgraded_files: Vec<String>,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    /// What was skipped or could not be read.
    pub notes: Vec<String>,
    pub inventory: Inventory,
}

impl Report {
    /// Sort the findings and recompute the summary.
    pub fn finalize(&mut self) {
        sort_findings(&mut self.findings);
        let mut s = Summary::default();
        for f in &self.findings {
            match f.severity {
                Severity::Critical => s.critical += 1,
                Severity::High => s.high += 1,
                Severity::Medium => s.medium += 1,
                Severity::Low => s.low += 1,
            }
        }
        s.total = self.findings.len();
        self.summary = s;
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// 0 = nothing serious, 1 = at least one High, 2 = at least one Critical.
    pub fn exit_code(&self) -> u8 {
        if self.summary.critical > 0 {
            2
        } else if self.summary.high > 0 {
            1
        } else {
            0
        }
    }

    pub fn has_rule(&self, rule: &str) -> bool {
        self.findings.iter().any(|f| f.rule == rule)
    }

    /// One line for monitoring: `OK|NOTICE|ATTENTION|ALARM host: headline (counts)`.
    pub fn summary_line(&self) -> String {
        let v = self.verdict();
        let tag = match v.level {
            VerdictLevel::Clean => "OK",
            VerdictLevel::Minor => "NOTICE",
            VerdictLevel::Attention => "ATTENTION",
            VerdictLevel::Alarm => "ALARM",
        };
        let s = &self.summary;
        format!("{tag} {}: {} ({} critical, {} high, {} medium, {} low)", self.hostname, v.headline, s.critical, s.high, s.medium, s.low)
    }

    /// A plain-language conclusion for people who do not read every finding.
    pub fn verdict(&self) -> Verdict {
        let s = &self.summary;
        let not_root = if self.running_as_root || self.scan_root != "/" {
            ""
        } else {
            " This scan did not run as root, so parts of the system could not be checked."
        };
        let (level, headline, detail) = if s.critical > 0 {
            (
                VerdictLevel::Alarm,
                format!("Possible intrusion – {} critical finding(s) need attention now", s.critical),
                "Read the critical findings first and run their verification commands. Do not reboot or delete anything before you have looked: evidence can disappear.".to_string(),
            )
        } else if s.high > 0 {
            (
                VerdictLevel::Attention,
                format!("{} finding(s) should be checked", s.high),
                "Nothing clearly shows an intrusion, but the high findings can be serious. Check each one with its verification commands.".to_string(),
            )
        } else if s.medium > 0 {
            (
                VerdictLevel::Minor,
                if self.has_rule("UPD-SECURITY") {
                    "No signs of intrusion – but security updates are waiting".to_string()
                } else {
                    "No signs of intrusion – a few things are worth a look".to_string()
                },
                "The medium findings are mostly exposure, settings or missing updates, not intrusion.".to_string(),
            )
        } else {
            (
                VerdictLevel::Clean,
                "No signs of intrusion found".to_string(),
                if self.baseline_compared.is_some() {
                    "Compared with the saved baseline, nothing suspicious changed.".to_string()
                } else {
                    "Later scans are compared with a baseline that is saved automatically after the first clean scan as root.".to_string()
                },
            )
        };
        let updates = if self.has_rule("UPD-SECURITY") {
            " Security updates are available – install them with: sudo apt update && sudo apt upgrade."
        } else if self.has_rule("UPD-AVAILABLE") {
            " Package updates are available – sudo apt update && sudo apt upgrade."
        } else if self.has_rule("UPD-REBOOT") {
            " A reboot is needed to finish installed updates."
        } else {
            ""
        };
        Verdict { level, headline, detail: format!("{detail}{updates}{not_root}") }
    }

    /// Readable terminal report. `color` turns on ANSI colours.
    pub fn to_text(&self, color: bool) -> String {
        let (bold, dim, reset) = if color { ("\x1b[1m", "\x1b[2m", "\x1b[0m") } else { ("", "", "") };
        let mut o = String::new();
        let line = "═".repeat(78);
        let _ = writeln!(o, "{line}");
        let _ = writeln!(o, "{bold} SCANNER – intrusion and backdoor report (read-only){reset}");
        let _ = writeln!(o, "{line}");
        let _ = writeln!(o, " Host:      {}   Kernel: {}", self.hostname, self.kernel);
        let _ = writeln!(o, " System:    {}", self.os);
        let _ = writeln!(o, " Time:      {}   Duration: {:.1} s", self.generated_at, self.duration_ms as f64 / 1000.0);
        let _ = writeln!(o, " Root:      {}{}", if self.running_as_root { "yes" } else { "NO – the result is incomplete" }, if self.scan_root != "/" { format!("   Scanned root: {}", self.scan_root) } else { String::new() });
        let _ = writeln!(o, " Modules:   {}", self.modules.join(", "));
        if !self.tools_run.is_empty() {
            let _ = writeln!(o, " Tools:     {}", self.tools_run.join(", "));
        }
        if let Some(b) = &self.baseline_compared {
            let _ = writeln!(o, " Baseline:  {b}");
        }
        let _ = writeln!(o);
        let s = &self.summary;
        let _ = writeln!(
            o,
            "{bold} SUMMARY:{reset} {} critical · {} high · {} medium · {} low  ({} findings in total)",
            s.critical, s.high, s.medium, s.low, s.total
        );
        let v = self.verdict();
        let _ = writeln!(o, "{bold} VERDICT:{reset} {}", v.headline);
        let _ = writeln!(o, "          {}", v.detail);
        let _ = writeln!(o, "{line}");

        for sev in Severity::ALL_DESC {
            let group: Vec<&Finding> = self.findings.iter().filter(|f| f.severity == sev).collect();
            if group.is_empty() {
                continue;
            }
            let _ = writeln!(o);
            let tag = if color { format!("{} {} {reset}", sev.ansi(), sev.label().to_uppercase()) } else { format!("[{}]", sev.label().to_uppercase()) };
            let _ = writeln!(o, "{tag} {bold}{} finding(s){reset}", group.len());
            let _ = writeln!(o, "{}", "─".repeat(78));
            for (i, f) in group.iter().enumerate() {
                let _ = writeln!(o, "{bold}{}. {}{reset}", i + 1, f.title);
                let _ = writeln!(o, "   {dim}module {} · rule {}{reset}", f.module, f.rule);
                if !f.description.is_empty() {
                    let _ = writeln!(o, "   {}", f.description);
                }
                if !f.evidence.is_empty() {
                    let _ = writeln!(o, "   Evidence:");
                    for l in f.evidence.lines() {
                        let _ = writeln!(o, "     {l}");
                    }
                }
                if !f.verify.is_empty() {
                    let _ = writeln!(o, "   Verify manually:");
                    for v in &f.verify {
                        let _ = writeln!(o, "     $ {v}");
                    }
                }
                let _ = writeln!(o);
            }
        }
        if self.findings.is_empty() {
            let _ = writeln!(o, "\n No findings. That does not guarantee the system is clean – compare against a baseline regularly.\n");
        }
        if !self.notes.is_empty() {
            let _ = writeln!(o, "{line}");
            let _ = writeln!(o, "{bold} NOTES (skipped / could not be read){reset}");
            for n in &self.notes {
                let _ = writeln!(o, "  • {n}");
            }
        }
        let _ = writeln!(o, "{line}");
        let _ = writeln!(o, " The scanner changes nothing on the system. Every action is done manually after verification.");
        o
    }
}
