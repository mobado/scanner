//! Files in home folders (part of `fs_perms`): what lies in the download folder, scripts in
//! `~/.local/bin` and program files hidden in dot folders. Nothing is executed or changed.

use super::common::{clip, mode_string, shq};
use super::filemarks::program_kind;
use super::fs_perms::MODULE;
use super::persistence::history::judge_command;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::MetadataExt;
use walkdir::{DirEntry, WalkDir};

/// Most files looked at per folder tree.
const LIMIT: usize = 30_000;
/// Scripts bigger than this are not read.
const SCRIPT_LIMIT: u64 = 256 * 1024;
/// Most single findings per kind and user.
const SHOWN: usize = 20;

const DOCUMENT_LIKE: [&str; 11] = ["pdf", "doc", "docx", "xls", "xlsx", "odt", "jpg", "jpeg", "png", "txt", "mp4"];
const RUNNABLE: [&str; 9] = ["desktop", "sh", "run", "bin", "elf", "appimage", "exe", "scr", "bat"];

/// Folders that hold thousands of ordinary program files (games, sandboxes, the wastebasket).
const SKIPPED: [&str; 8] = ["Trash", "Steam", "flatpak", "containers", "docker", "node_modules", "ms-playwright", ".git"];

/// "invoice.pdf.desktop": looks like a document but runs.
pub fn is_disguised(name: &str) -> bool {
    let lower = name.to_lowercase();
    let mut parts = lower.rsplit('.');
    let (Some(last), Some(before), Some(_)) = (parts.next(), parts.next(), parts.next()) else { return false };
    RUNNABLE.contains(&last) && DOCUMENT_LIKE.contains(&before.trim())
}

/// The download folders of one home: the configured names and the user's XDG setting.
pub fn download_folders(ctx: &ScanCtx, home: &str) -> BTreeSet<String> {
    let mut names: BTreeSet<String> = ctx.cfg.download_dirs.iter().map(|d| format!("{home}/{d}")).collect();
    if let Ok(text) = ctx.sys.read_string(format!("{home}/.config/user-dirs.dirs")) {
        for line in text.lines() {
            let Some(value) = line.trim().strip_prefix("XDG_DOWNLOAD_DIR=") else { continue };
            let value = value.trim_matches('"').trim_end_matches('/');
            // "$HOME" alone would mean the whole home folder
            if let Some(rest) = value.strip_prefix("$HOME/").filter(|r| !r.is_empty()) {
                names.insert(format!("{home}/{rest}"));
            }
        }
    }
    names.into_iter().filter(|d| fs::symlink_metadata(ctx.sys.path(d)).map(|m| m.is_dir()).unwrap_or(false)).collect()
}

fn files(ctx: &ScanCtx, folder: &str, depth: usize) -> impl Iterator<Item = DirEntry> {
    WalkDir::new(ctx.sys.path(folder))
        .follow_links(false)
        .max_depth(depth)
        .into_iter()
        .filter_entry(|e| e.depth() == 0 || !SKIPPED.iter().any(|s| e.file_name() == *s))
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .take(LIMIT)
}

/// The first line of a script that looks like an intrusion command.
fn suspicious_line(ctx: &ScanCtx, entry: &DirEntry) -> Option<String> {
    if entry.metadata().ok()?.len() > SCRIPT_LIMIT {
        return None;
    }
    let bytes = fs::read(entry.path()).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    let text = String::from_utf8_lossy(&bytes);
    // /dev/tcp is also the usual way for a script to test whether a port answers
    let shell = hands_over_a_shell(&text);
    text.lines()
        .map(str::trim)
        // lines that search for or print such text are what security scripts are full of
        .filter(|l| !l.starts_with('#') && !l.contains("grep") && !l.starts_with("echo ") && !l.starts_with("printf "))
        .find_map(|l| match judge_command(ctx, l) {
            Some((Severity::High | Severity::Critical, why)) if shell || !why.starts_with("uses /dev/tcp") => Some(format!("{}  ← {why}", clip(l, 200))),
            _ => None,
        })
}

/// Does a script that uses `/dev/tcp` also feed what arrives there to a shell?
pub fn hands_over_a_shell(text: &str) -> bool {
    ["0>&1", "0<&", ">& /dev/tcp", ">&/dev/tcp", "sh -i", "| sh", "|sh", "| bash", "|bash", "| /bin/sh", "| /bin/bash", "do $"]
        .iter()
        .any(|sign| text.contains(sign))
}

fn looks_like_script(name: &str, kind: Option<&str>) -> bool {
    kind == Some("script") || [".sh", ".py", ".pl", ".run"].iter().any(|e| name.ends_with(e))
}

fn suspicious_script(path: &str, line: &str) -> Finding {
    Finding::new(Severity::High, MODULE, "FS-SCRIPT-SUSPICIOUS", format!("Script with suspicious commands: {path}"))
        .evidence(format!("{path}\n{line}"))
        .description("The script contains a command typical of a break-in (a reverse shell, deleting logs, switching off the history …). Do not run it. If you did not put it there, find out when it appeared.")
        .verify(format!("less {}", shq(path)))
        .verify(format!("ls -l --time-style=full-iso {}", shq(path)))
}

fn check_downloads(ctx: &ScanCtx, col: &mut Collector, folder: &str) {
    let mut programs = Vec::new();
    let mut odd = 0usize;
    for entry in files(ctx, folder, 3) {
        let Ok(meta) = entry.metadata() else { continue };
        let path = ctx.sys.display(entry.path());
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if is_disguised(&name) {
            odd += 1;
            if odd <= SHOWN {
                col.push(
                    Finding::new(Severity::Medium, MODULE, "FS-DOWNLOAD-DISGUISED", format!("File that pretends to be a document: {path}"))
                        .evidence(format!("{path} (mode {}, {} bytes)", mode_string(meta.mode()), meta.size()))
                        .description("The name looks like a document or picture, but the last ending makes it something that runs. That is how malicious downloads trick people into starting them. Do not open it.")
                        .verify(format!("file {}", shq(&path)))
                        .verify(format!("less {}", shq(&path))),
                );
            }
        }
        let executable = meta.mode() & 0o111 != 0;
        let kind = if executable { program_kind(entry.path()) } else { None };
        if looks_like_script(&name, kind) {
            if let Some(line) = suspicious_line(ctx, &entry) {
                odd += 1;
                if odd <= SHOWN {
                    col.push(suspicious_script(&path, &line));
                }
            }
        }
        if let Some(kind) = kind.or_else(|| (executable && name.ends_with(".desktop")).then_some("launcher")) {
            programs.push(format!("{path} ({kind}, {} bytes)", meta.size()));
        }
    }
    if odd > SHOWN {
        col.note(format!("{} more suspicious files in {folder} were not listed", odd - SHOWN));
    }
    if programs.is_empty() {
        return;
    }
    programs.sort();
    let count = programs.len();
    if count > 15 {
        programs.truncate(15);
        programs.push(format!("… and {} more", count - 15));
    }
    col.push(
        Finding::new(Severity::Low, MODULE, "FS-DOWNLOAD-PROGRAM", format!("Programs ready to run in the download folder: {folder}"))
            .evidence(clip(&programs.join("\n"), 1500))
            .description("These downloaded files are allowed to run. Installers and AppImages you fetched yourself are normal; remove what you do not recognise.")
            .verify(format!("find {} -maxdepth 3 -type f -perm /111 -exec file {{}} +", shq(folder))),
    );
}

fn hidden_program(path: &str, size: u64) -> Finding {
    Finding::new(Severity::Medium, MODULE, "FS-HOME-HIDDEN-PROGRAM", format!("Program file hidden in a home folder: {path}"))
        .evidence(format!("{path} (ELF program, {size} bytes)"))
        .description("A compiled program with a hidden name, or lying loose in a settings or cache folder. Programs normally have their own folder or come from a package; miners and backdoors installed without root often hide like this.")
        .verify(format!("file {}", shq(path)))
        .verify(format!("ls -l --time-style=full-iso {}", shq(path)))
        .verify(format!("sha256sum {}", shq(path)))
}

fn check_hidden(ctx: &ScanCtx, col: &mut Collector, home: &str) {
    let mut found: BTreeSet<(String, u64)> = BTreeSet::new();
    // (folder, depth, report every program at the top level)
    let places = [(home.to_string(), 1, false), (format!("{home}/.cache"), 4, true), (format!("{home}/.config"), 4, true), (format!("{home}/.local/share"), 4, true), (format!("{home}/.local"), 1, true)];
    for (folder, depth, loose_counts) in places {
        for entry in files(ctx, &folder, depth) {
            let hidden = entry.file_name().to_string_lossy().starts_with('.');
            if !(hidden || (loose_counts && entry.depth() == 1)) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.mode() & 0o111 != 0 && program_kind(entry.path()) == Some("ELF program") {
                found.insert((ctx.sys.display(entry.path()), meta.size()));
            }
        }
    }
    let total = found.len();
    for (path, size) in found.into_iter().take(SHOWN) {
        col.push(hidden_program(&path, size));
    }
    if total > SHOWN {
        col.note(format!("{} more hidden program files in {home} were not listed", total - SHOWN));
    }
    let bin = format!("{home}/.local/bin");
    for entry in files(ctx, &bin, 1) {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if looks_like_script(&name, program_kind(entry.path())) {
            if let Some(line) = suspicious_line(ctx, &entry) {
                col.push(suspicious_script(&ctx.sys.display(entry.path()), &line));
            }
        }
    }
}

pub(crate) fn check_home_files(ctx: &ScanCtx, col: &mut Collector, homes: &[String]) {
    for home in homes {
        for folder in download_folders(ctx, home) {
            check_downloads(ctx, col, &folder);
        }
        check_hidden(ctx, col, home);
    }
}
