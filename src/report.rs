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
        let _ = writeln!(o, " Moduler:   {}", self.modules.join(", "));
        if !self.tools_run.is_empty() {
            let _ = writeln!(o, " Verktyg:   {}", self.tools_run.join(", "));
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
                    let _ = writeln!(o, "   Bevis:");
                    for l in f.evidence.lines() {
                        let _ = writeln!(o, "     {l}");
                    }
                }
                if !f.verify.is_empty() {
                    let _ = writeln!(o, "   Verifiera manuellt:");
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
