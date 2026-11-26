//! The four internal detection modules and what they share.

pub mod common;
pub mod auth_logs;
pub mod fs_perms;
pub mod net_group;
pub mod net_proc;
pub mod persistence;
pub mod proc_audit;
pub mod updates;

use crate::config::Config;
use crate::finding::Finding;
use crate::procinfo::ProcInfo;
use crate::sys::SysRoot;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What a module needs to run.
pub struct ScanCtx<'a> {
    pub sys: &'a SysRoot,
    pub cfg: &'a Config,
    /// Walk the whole PID range to find hidden processes (slower).
    pub deep_pid_scan: bool,
    /// Are we running with root privileges (or against a test root, where everything is readable)?
    pub privileged: bool,
    /// Processes read once and shared between the modules.
    pub processes: &'a [ProcInfo],
}

/// Collected data that is not findings but is needed for baselines and the window.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Inventory {
    pub connections: Vec<net_proc::Connection>,
    pub suid: Vec<fs_perms::SuidEntry>,
    /// Path → SHA-256 for files that control persistence (cron, systemd, ssh, pam ...).
    pub persistence_files: BTreeMap<String, String>,
    pub units: Vec<persistence::UnitSummary>,
    pub process_count: usize,
    pub fs_files_scanned: u64,
}

/// Collects findings and notes from the modules.
#[derive(Debug, Default)]
pub struct Collector {
    pub findings: Vec<Finding>,
    /// Things that were skipped or could not be read.
    pub notes: Vec<String>,
    pub inventory: Inventory,
}

impl Collector {
    pub fn push(&mut self, f: Finding) {
        self.findings.push(f);
    }

    pub fn note(&mut self, s: impl Into<String>) {
        self.notes.push(s.into());
    }
}
