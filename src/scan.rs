//! Orchestration: runs the selected modules and tools, compares against a baseline,
//! filters according to the whitelist and builds the report.

use crate::baseline::{self, Baseline};
use crate::config::Config;
use crate::external_tools::{self, Tool};
use crate::finding::{Finding, Severity};
use crate::modules::{fs_perms, net_proc, persistence, proc_audit, updates, Collector, ScanCtx};
use crate::procinfo;
use crate::report::Report;
use crate::sys::{self, SysRoot};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum ModuleId {
    NetProc,
    ProcAudit,
    FsPerms,
    Persistence,
    Updates,
}

impl ModuleId {
    pub const ALL: [ModuleId; 5] = [ModuleId::NetProc, ModuleId::ProcAudit, ModuleId::FsPerms, ModuleId::Persistence, ModuleId::Updates];
    /// The modules a baseline needs (the updates check says nothing about changes).
    pub const CORE: [ModuleId; 4] = [ModuleId::NetProc, ModuleId::ProcAudit, ModuleId::FsPerms, ModuleId::Persistence];

    pub fn id(&self) -> &'static str {
        match self {
            ModuleId::NetProc => "net_proc",
            ModuleId::ProcAudit => "proc_audit",
            ModuleId::FsPerms => "fs_perms",
            ModuleId::Persistence => "persistence",
            ModuleId::Updates => "updates",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ModuleId::NetProc => "Network and hidden processes",
            ModuleId::ProcAudit => "Processes and run paths",
            ModuleId::FsPerms => "File permissions and SUID/SGID",
            ModuleId::Persistence => "Persistence (systemd, cron, SSH, PAM)",
            ModuleId::Updates => "Pending updates",
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            ModuleId::NetProc => "Reverse/bind shells, unknown ports, hidden PIDs, disguised names",
            ModuleId::ProcAudit => "Programs from /tmp or /dev/shm, deleted binaries, LD_PRELOAD",
            ModuleId::FsPerms => "Walks local file systems (takes the longest)",
            ModuleId::Persistence => "Services, scheduled jobs, keys and login",
            ModuleId::Updates => "Security updates and reboot needed (apt simulation, installs nothing)",
        }
    }
}

impl std::str::FromStr for ModuleId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ModuleId::ALL
            .iter()
            .find(|m| m.id().eq_ignore_ascii_case(s.trim()))
            .copied()
            .ok_or_else(|| format!("unknown module '{s}' (net_proc, proc_audit, fs_perms, persistence, updates)"))
    }
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub modules: Vec<ModuleId>,
    pub tools: Vec<Tool>,
    pub deep_pid_scan: bool,
    pub baseline_compare: Option<PathBuf>,
    pub min_severity: Severity,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            modules: ModuleId::ALL.to_vec(),
            tools: Vec::new(),
            deep_pid_scan: false,
            baseline_compare: None,
            min_severity: Severity::Low,
        }
    }
}

/// Like [`run_scan`], plus the automatic baseline: when no baseline file is given and the
/// automatic one exists, compare against it; when it does not exist yet, save it after
/// a clean, complete scan as root (see [`crate::autobaseline`]). The result is noted in the report.
pub fn run_scan_auto(sys: &SysRoot, cfg: &Config, opts: &ScanOptions, auto: bool, progress: &dyn Fn(&str)) -> Report {
    let mut opts = opts.clone();
    let live = sys.is_live();
    if auto && live && opts.baseline_compare.is_none() {
        opts.baseline_compare = crate::autobaseline::default_if_exists();
    }
    let mut report = run_scan(sys, cfg, &opts, progress);
    if auto && live {
        match crate::autobaseline::auto_save(&report) {
            crate::autobaseline::AutoBaseline::Saved(p) => {
                report.notes.push(format!("A baseline of this machine was saved automatically: {}. Later scans compare against it.", p.display()));
                report.baseline_auto_saved = Some(p.display().to_string());
            }
            crate::autobaseline::AutoBaseline::Skipped(why) => report.notes.push(why),
            crate::autobaseline::AutoBaseline::NotNeeded => {}
        }
    }
    report
}

/// Run a whole scan. Never panics because of system data; everything that
/// could not be read ends up in `Report::notes`.
pub fn run_scan(sys: &SysRoot, cfg: &Config, opts: &ScanOptions, progress: &dyn Fn(&str)) -> Report {
    let start = Instant::now();
    let running_as_root = sys::is_root();
    let privileged = !sys.is_live() || running_as_root;
    let (hostname, kernel, os) = sys::host_facts(sys);
    let mut col = Collector::default();
    if !privileged {
        col.note("The scanner is not running as root: other users' processes, /var/spool/cron, /root and some /proc files cannot be read. Run with sudo for a complete scan.");
    }

    let need_procs = opts.modules.contains(&ModuleId::NetProc) || opts.modules.contains(&ModuleId::ProcAudit);
    let processes = if need_procs {
        progress("Reading processes in /proc …");
        procinfo::snapshot(sys)
    } else {
        Vec::new()
    };
    let ctx = ScanCtx { sys, cfg, deep_pid_scan: opts.deep_pid_scan, privileged, processes: &processes };

    let mut modules_run = Vec::new();
    for m in ModuleId::ALL {
        if !opts.modules.contains(&m) {
            continue;
        }
        progress(&format!("Running {} – {} …", m.id(), m.label()));
        match m {
            ModuleId::NetProc => net_proc::run(&ctx, &mut col),
            ModuleId::ProcAudit => proc_audit::run(&ctx, &mut col),
            ModuleId::FsPerms => fs_perms::run(&ctx, &mut col),
            ModuleId::Persistence => persistence::run(&ctx, &mut col),
            ModuleId::Updates => updates::run(&ctx, &mut col),
        }
        modules_run.push(m.id().to_string());
    }

    let mut tools_run = Vec::new();
    if !opts.tools.is_empty() {
        if sys.is_live() {
            for t in &opts.tools {
                progress(&format!("Running external tool {} …", t.binary()));
                external_tools::run_tool(*t, cfg, &mut col);
                tools_run.push(t.binary().to_string());
            }
        } else {
            col.note("External tools only run against the live system (the root is not /)");
        }
    }

    let mut baseline_compared = None;
    if let Some(path) = &opts.baseline_compare {
        progress("Comparing against the baseline …");
        match Baseline::load(path) {
            Ok(b) => {
                let (mut f, notes) = baseline::compare(&b, &col.inventory, &modules_run);
                let dpkg_modified = std::fs::metadata(sys.path("/var/lib/dpkg/status")).and_then(|m| m.modified()).ok();
                crate::autobaseline::soften_after_updates(&mut f, &b.created_at, dpkg_modified);
                col.findings.extend(f);
                col.notes.extend(notes);
                baseline_compared = Some(format!("{} (created {} on {})", path.display(), b.created_at, b.hostname));
            }
            Err(e) => col.note(format!("The baseline could not be read: {e}")),
        }
    }

    // Whitelist, minimum severity and duplicates
    let mut seen = HashSet::new();
    let suppressed_before = col.findings.len();
    let findings: Vec<Finding> = std::mem::take(&mut col.findings)
        .into_iter()
        .filter(|f| f.severity >= opts.min_severity && !cfg.suppresses(f))
        .filter(|f| seen.insert((f.rule.clone(), f.title.clone(), f.evidence.clone())))
        .collect();
    let findings: Vec<Finding> = findings
        .into_iter()
        .map(|mut f| {
            f.verify = f.verify.iter().map(|c| crate::finding::sudoize(c)).collect();
            f
        })
        .collect();
    let hidden = suppressed_before - findings.len();
    if hidden > 0 {
        col.note(format!("{hidden} findings hidden by the whitelist, minimum severity or duplicate filter"));
    }

    let mut report = Report {
        scanner: "scanner".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        generated_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S %z").to_string(),
        hostname,
        kernel,
        os,
        running_as_root,
        scan_root: sys.root().display().to_string(),
        duration_ms: start.elapsed().as_millis(),
        modules: modules_run,
        tools_run,
        baseline_compared,
        baseline_auto_saved: None,
        summary: Default::default(),
        findings,
        notes: col.notes,
        inventory: col.inventory,
    };
    report.finalize();
    progress("Done.");
    report
}
