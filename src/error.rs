//! Error types. Modules return `Result<_, ScanError>`; the orchestration
//! turns errors into notes in the report instead of aborting.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("could not read or write {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid format in {path}: {msg}")]
    Parse { path: String, msg: String },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("tool {tool} failed: {msg}")]
    Tool { tool: String, msg: String },

    #[error("baseline error: {0}")]
    Baseline(String),
}

impl ScanError {
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        ScanError::Io {
            path: path.into(),
            source,
        }
    }

    pub fn parse(path: impl Into<String>, msg: impl Into<String>) -> Self {
        ScanError::Parse {
            path: path.into(),
            msg: msg.into(),
        }
    }

    /// True when the error only means the file does not exist (common and harmless).
    pub fn is_not_found(&self) -> bool {
        matches!(self, ScanError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound)
    }

    /// True when the error is caused by missing permissions (the scanner is not running as root).
    pub fn is_permission_denied(&self) -> bool {
        matches!(self, ScanError::Io { source, .. } if source.kind() == std::io::ErrorKind::PermissionDenied)
    }
}

pub type Result<T> = std::result::Result<T, ScanError>;
