//! Orchestration: runs the selected modules and tools, compares against a baseline,
//! filters according to the whitelist and builds the report.

use crate::baseline::{self, Baseline};
use crate::config::Config;
use crate::external_tools::{self, Tool};
use crate::finding::{Finding, Severity};
use crate::modules::{auth_logs, integrity, kernel, services, fs_perms, net_proc, persistence, proc_audit, updates, Collector, ScanCtx};
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
    AuthLogs,
    Kernel,
    Services,
    Integrity,
}

impl ModuleId {
    pub const ALL: [ModuleId; 9] = [
        ModuleId::NetProc,
        ModuleId::ProcAudit,
        ModuleId::FsPerms,
        ModuleId::Persistence,
        ModuleId::Kernel,
        ModuleId::Services,
        ModuleId::AuthLogs,
        ModuleId::Integrity,
        ModuleId::Updates,
    ];
    /// The modules a baseline needs (the updates check says nothing about changes).
    pub const CORE: [ModuleId; 4] = [ModuleId::NetProc, ModuleId::ProcAudit, ModuleId::FsPerms, ModuleId::Persistence];

    pub fn id(&self) -> &'static str {
        match self {
            ModuleId::NetProc => "net_proc",
            ModuleId::ProcAudit => "proc_audit",
            ModuleId::FsPerms => "fs_perms",
            ModuleId::Persistence => "persistence",
            ModuleId::Updates => "updates",
            ModuleId::AuthLogs => "auth_logs",
            ModuleId::Kernel => "kernel",
            ModuleId::Services => "services",
            ModuleId::Integrity => "integrity",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ModuleId::NetProc => "Network and hidden processes",
            ModuleId::ProcAudit => "Processes and run paths",
            ModuleId::FsPerms => "File permissions and SUID/SGID",
            ModuleId::Persistence => "Persistence (systemd, cron, SSH, PAM)",
            ModuleId::Updates => "Pending updates",
            ModuleId::AuthLogs => "Login attempts",
            ModuleId::Kernel => "Kernel and modules",
            ModuleId::Services => "Web files and containers",
            ModuleId::Integrity => "Logs and clock",
        }
    }

    pub fn describe(&self) -> &'static str {
        match self {
            ModuleId::NetProc => "Reverse/bind shells, unknown ports, hidden PIDs, disguised names",
            ModuleId::ProcAudit => "Programs from /tmp or /dev/shm, deleted binaries, LD_PRELOAD",
            ModuleId::FsPerms => "Walks local file systems (takes the longest)",
            ModuleId::Persistence => "Services, scheduled jobs, keys and login",
            ModuleId::Updates => "Security updates and reboot needed (apt simulation, installs nothing)",
            ModuleId::AuthLogs => "Wrong passwords, unknown users, break-ins in the system logs",
            ModuleId::Kernel => "Hidden or unknown modules, dangerous kernel settings",
            ModuleId::Services => "Web shells, privileged containers, Docker access",
            ModuleId::Integrity => "Cleared or damaged logs, journal check, clock",
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
            .ok_or_else(|| format!("unknown module '{s}' (net_proc, proc_audit, fs_perms, persistence, updates, auth_logs, kernel, services, integrity)"))
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
    // Bring verified upgrades into the automatic baseline, so it follows the system.
    if auto && live && report.running_as_root && !report.upgraded_files.is_empty() && opts.baseline_compare == Some(crate::autobaseline::default_path()) {
        match crate::autobaseline::refresh_upgraded(&report, &crate::autobaseline::default_path()) {
            Ok(n) => report.notes.push(format!("The automatic baseline was updated with {n} verified upgraded file(s).")),
            Err(e) => report.notes.push(format!("The baseline could not be updated with the upgraded files: {e}")),
        }
    }
    if auto && live {
        match crate::autobaseline::auto_save(&report) {
            crate::autobaseline::AutoBaseline::Saved(p) => {
                report.notes.push(format!("A baseline of this machine was saved automatically: {}. Later scans compare against it.", p.display()));
                report.baseline_auto_saved = Some(p.display().to_string());
            }
            crate::autobaseline::AutoBaseline::Completed(p, parts) => {
                report.notes.push(format!("The baseline {} was missing {}; it was added from this clean scan, so everything is compared from now on.", p.display(), parts.join(", ")));
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

    let need_procs = [ModuleId::NetProc, ModuleId::ProcAudit, ModuleId::Services].iter().any(|m| opts.modules.contains(m));
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
            ModuleId::AuthLogs => auth_logs::run(&ctx, &mut col),
            ModuleId::Kernel => kernel::run(&ctx, &mut col),
            ModuleId::Services => services::run(&ctx, &mut col),
            ModuleId::Integrity => integrity::run(&ctx, &mut col),
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
    let mut upgraded_files = Vec::new();
    if let Some(path) = &opts.baseline_compare {
        progress("Comparing against the baseline …");
        match Baseline::load(path) {
            Ok(b) => {
                let (mut f, notes) = baseline::compare(&b, &col.inventory, &modules_run);
                // Changes that apt explains (verified against the package) are not reported.
                progress("Checking changed files against dpkg …");
                let apt = crate::pkgverify::apply(sys, &mut f, &b.created_at);
                if !apt.upgraded.is_empty() {
                    let files: Vec<String> = apt.upgraded.iter().map(|(p, pkg)| format!("{p} ({pkg})")).collect();
                    col.notes.push(format!(
                        "{} changed file(s) were verified against their package and an apt install/upgrade after the baseline, so they are not reported: {}",
                        files.len(),
                        files.join(", ")
                    ));
                    for op in apt.operations.iter().take(20) {
                        col.notes.push(format!("apt: {op}"));
                    }
                }
                upgraded_files = apt.upgraded.into_iter().map(|(p, _)| p).collect();
                // New ports of a program you trust in the whitelist (installed under /usr) are not news.
                f.retain(|x| {
                    x.rule != "BASE-LISTEN-NEW"
                        || !crate::modules::net_group::process_in_title(&x.title)
                            .map(|name| cfg.allowed_listen_processes.contains(&name))
                            .unwrap_or(false)
                });
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
        upgraded_files,
        summary: Default::default(),
        findings,
        notes: col.notes,
        inventory: col.inventory,
    };
    report.finalize();
    progress("Done.");
    report
}
