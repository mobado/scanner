//! The four internal detection modules and what they share.

pub mod common;
pub mod desktop_session;
pub mod auth_logs;
pub mod browsers;
pub mod filemarks;
pub mod homefiles;
pub mod fs_perms;
pub mod integrity;
pub mod kernel;
pub mod kernelstate;
pub mod firewall;
pub mod procrights;
pub mod bootchain;
pub mod netlocal;
pub mod debianfs;
pub mod hardware;
pub mod sandboxes;
pub mod secrets;
pub mod wallet;
pub mod procwatch;
pub mod tunnels;
pub mod net_group;
pub mod net_proc;
pub mod netwatch;
pub mod persistence;
pub mod proc_audit;
pub mod services;
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
    /// How long to listen for requests to the password wallet (0 = not at all).
    pub wallet_watch_secs: u64,
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
    /// Accounts with their privileged groups (compared with the baseline).
    #[serde(default)]
    pub accounts: Vec<persistence::extra::AccountEntry>,
    /// Secure Boot, lockdown and the firmware's boot entries (compared with the baseline).
    #[serde(default)]
    pub boot: BTreeMap<String, String>,
    /// Signs of a graphical desktop (empty on a server); `None` when desktop_session did not run.
    #[serde(default)]
    pub desktop: Option<Vec<String>>,
    /// Accepted SSH keys ("file key-type fingerprint comment"); `None` when persistence did not run.
    #[serde(default)]
    pub ssh_keys: Option<Vec<String>>,
    /// Paired Bluetooth devices; `None` when they could not be read.
    #[serde(default)]
    pub bluetooth: Option<Vec<String>>,
    /// Browser add-ons that are switched on ("profile: id name"); `None` when not read.
    #[serde(default)]
    pub addons: Option<Vec<String>>,
    /// Editor extensions ("folder: id"); `None` when persistence did not run.
    #[serde(default)]
    pub editor_plugins: Option<Vec<String>>,
    /// Names of packages no software source offers; `None` when they could not be compared.
    #[serde(default)]
    pub local_packages: Option<Vec<String>>,
    /// Loaded firewall rules that accept traffic, without counters; `None` when they were not read.
    #[serde(default)]
    pub firewall_rules: Option<Vec<String>>,
    /// USB keyboards and Thunderbolt devices; `None` when the machine's buses were not read.
    #[serde(default)]
    pub peripherals: Option<Vec<String>>,
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
