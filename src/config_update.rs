//! Keeping the whitelist up to date with new program versions.
//!
//! A new version may ship new default entries (a newly recognised harmless program, a new
//! PAM module ...). This adds them to the person's whitelist:
//!
//! * when the program **loads** a whitelist, new defaults are added in memory, and
//! * `scanner --update-config` (run by the Debian package on every install and upgrade)
//!   writes them into the file, keeping comments and the person's own entries, after saving
//!   a `.bak` copy.
//!
//! A small record next to the file (`whitelist.defaults.json`) remembers which defaults have
//! been offered, so an entry the person removed is not added again. `add_new_defaults = false`
//! in the file switches all of this off.

use crate::config::Config;
use crate::error::ScanError;
use serde_json::{Map, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The lists that new versions may add entries to. Lists that only the person fills
/// (ignored findings, own units, key comments, roots to scan) are never touched.
const GROWING_LISTS: [&str; 21] = [
    "allowed_capability_files",
    "trusted_apt_hosts",
    "common_remote_ports",
    "trusted_resolvers",
    "allowed_out_of_tree_modules",
    "known_rootkit_modules",
    "web_roots",
    "allowed_listen_ports",
    "allowed_listen_processes",
    "suspicious_remote_ports",
    "temp_dirs",
    "shell_names",
    "script_interpreters",
    "known_malware_names",
    "allowed_argv0_mismatch",
    "kernel_thread_prefixes",
    "allowed_suid",
    "fs_exclude_paths",
    "allowed_cron_files",
    "allowed_pam_modules",
    "allowed_ld_preload",
];

fn to_map(cfg: &Config) -> Map<String, Value> {
    match serde_json::to_value(cfg) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

fn key(field: &str, v: &Value) -> String {
    format!("{field}={v}")
}

/// Default entries that are neither in `current` nor already offered, per list.
fn missing(current: &Map<String, Value>, seen: &BTreeSet<String>) -> Vec<(&'static str, Vec<Value>)> {
    let defaults = to_map(&Config::default());
    let mut out = Vec::new();
    for field in GROWING_LISTS {
        let Some(Value::Array(def)) = defaults.get(field) else { continue };
        let have: &[Value] = current.get(field).and_then(|v| v.as_array()).map(|a| a.as_slice()).unwrap_or(&[]);
        let mut add: Vec<Value> = Vec::new();
        for v in def {
            if !have.contains(v) && !add.contains(v) && !seen.contains(&key(field, v)) {
                add.push(v.clone());
            }
        }
        if !add.is_empty() {
            out.push((field, add));
        }
    }
    out
}

/// Add new defaults to a loaded configuration (in memory). Returns how many were added.
pub fn merge(cfg: &mut Config, seen: &BTreeSet<String>) -> usize {
    if !cfg.add_new_defaults {
        return 0;
    }
    let mut map = to_map(cfg);
    let additions = missing(&map, seen);
    let mut n = 0;
    for (field, values) in additions {
        if let Some(Value::Array(a)) = map.get_mut(field) {
            n += values.len();
            a.extend(values);
        }
    }
    if n > 0 {
        if let Ok(new) = serde_json::from_value(Value::Object(map)) {
            *cfg = new;
        }
    }
    n
}

/// `whitelist.toml` → `whitelist.defaults.json`
pub fn record_path(file: &Path) -> PathBuf {
    file.with_extension("defaults.json")
}

pub fn read_record(file: &Path) -> BTreeSet<String> {
    std::fs::read_to_string(record_path(file))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// Remember that every current default has been offered for this file.
pub fn write_record(file: &Path) -> Result<(), ScanError> {
    let defaults = to_map(&Config::default());
    let mut all = BTreeSet::new();
    for field in GROWING_LISTS {
        if let Some(Value::Array(a)) = defaults.get(field) {
            all.extend(a.iter().map(|v| key(field, v)));
        }
    }
    let path = record_path(file);
    let json = serde_json::to_string_pretty(&all).map_err(|e| ScanError::Config(e.to_string()))?;
    std::fs::write(&path, json).map_err(|e| ScanError::io(path, e))
}

#[derive(Debug, PartialEq)]
pub enum Update {
    /// There was no file; one with the defaults was written.
    Created,
    /// Entries were added (listed as "list: value"); the old file was saved as the backup.
    Added { entries: Vec<String>, backup: PathBuf },
    UpToDate,
    /// The file says `add_new_defaults = false`.
    SwitchedOff,
}

fn show(v: &Value) -> String {
    v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string())
}

/// Add new defaults to a TOML document without disturbing comments or layout.
fn edit_toml(text: &str, additions: &[(&str, Vec<Value>)]) -> Result<String, ScanError> {
    let mut doc: toml_edit::DocumentMut = text.parse().map_err(|e: toml_edit::TomlError| ScanError::Config(e.to_string()))?;
    for (field, values) in additions {
        if !doc.contains_key(field) {
            doc.insert(field, toml_edit::value(toml_edit::Array::new()));
        }
        let Some(array) = doc.get_mut(field).and_then(|i| i.as_array_mut()) else { continue };
        for v in values {
            let mut item = match v {
                Value::Number(n) => toml_edit::Value::from(n.as_i64().unwrap_or_default()),
                other => toml_edit::Value::from(show(other)),
            };
            item.decor_mut().set_prefix("\n    ");
            array.push_formatted(item);
        }
        array.set_trailing("\n");
        array.set_trailing_comma(true);
    }
    Ok(doc.to_string())
}

/// Create or update a whitelist file with the defaults of this version.
pub fn update_file(path: &Path) -> Result<Update, ScanError> {
    if !path.exists() {
        if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir).map_err(|e| ScanError::io(dir, e))?;
        }
        let body = Config::default().to_toml()?;
        let text = format!(
            "# Whitelist for scanner (Debian 13 \"Trixie\").\n# New default entries are added automatically when scanner is upgraded; your own changes\n# are kept, and entries you remove stay removed. Set add_new_defaults = false to stop that.\n# '*' in allowed_suid and fs_exclude_paths matches one name (not '/').\n\n{body}"
        );
        std::fs::write(path, text).map_err(|e| ScanError::io(path, e))?;
        write_record(path)?;
        return Ok(Update::Created);
    }
    let text = std::fs::read_to_string(path).map_err(|e| ScanError::io(path, e))?;
    let is_json = path.extension().map(|e| e.eq_ignore_ascii_case("json")).unwrap_or(false);
    // What the file itself contains (fields it lacks count as empty here).
    let present: Value = if is_json {
        serde_json::from_str(&text).map_err(|e| ScanError::Config(format!("{}: {e}", path.display())))?
    } else {
        toml::from_str(&text).map_err(|e| ScanError::Config(format!("{}: {e}", path.display())))?
    };
    // A file that does not load must not be rewritten.
    let cfg: Config = serde_json::from_value(present.clone()).map_err(|e| ScanError::Config(format!("{}: {e}", path.display())))?;
    if !cfg.add_new_defaults {
        return Ok(Update::SwitchedOff);
    }
    let mut map = present.as_object().cloned().unwrap_or_default();
    let additions = missing(&map, &read_record(path));
    if additions.is_empty() {
        write_record(path)?;
        return Ok(Update::UpToDate);
    }
    let new_text = if is_json {
        for (field, values) in &additions {
            if let Some(a) = map.entry(field.to_string()).or_insert_with(|| Value::Array(Vec::new())).as_array_mut() {
                a.extend(values.clone());
            }
        }
        serde_json::to_string_pretty(&map).map_err(|e| ScanError::Config(e.to_string()))?
    } else {
        edit_toml(&text, &additions)?
    };
    let mut backup = path.as_os_str().to_owned();
    backup.push(".bak");
    let backup = PathBuf::from(backup);
    std::fs::write(&backup, &text).map_err(|e| ScanError::io(&backup, e))?;
    std::fs::write(path, new_text).map_err(|e| ScanError::io(path, e))?;
    write_record(path)?;
    let entries = additions.iter().flat_map(|(f, v)| v.iter().map(move |v| format!("{f}: {}", show(v)))).collect();
    Ok(Update::Added { entries, backup })
}
