//! `scanner` – a read-only intrusion and backdoor scanner for Debian 13 ("Trixie").
//!
//! The library holds all detection logic. The binary (`src/main.rs`) adds
//! the CLI (clap) and, with the `gui` feature, a window (egui).
//!
//! Principles:
//! * Strictly read-only: the scanner only reads. The only writes are report
//!   and baseline files that the user explicitly asks for.
//! * No `.unwrap()` on system data: missing /proc files or processes that
//!   disappear mid-scan become notes, never a crash.
//! * All modules read through [`sys::SysRoot`], so the same code can run against a
//!   made-up file system in a temporary directory (tests and self-test).

pub mod autobaseline;
pub mod baseline;
pub mod config;
pub mod config_update;
pub mod context;
pub mod error;
pub mod external_tools;
pub mod finding;
pub mod html;
pub mod modules;
pub mod pkgverify;
pub mod procinfo;
pub mod report;
pub mod sandbox;
pub mod scan;
pub mod second_look;
pub mod sys;

pub use config::Config;
pub use error::ScanError;
pub use finding::{Finding, Severity};
pub use report::Report;
pub use scan::{run_scan, ModuleId, ScanOptions};
pub use sys::SysRoot;
