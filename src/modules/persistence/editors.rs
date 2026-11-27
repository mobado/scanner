//! Editors and IDEs run their settings and plugins whenever they start: Vim and Neovim
//! scripts that start shell commands, and VS Code-family extensions that did not come from the
//! marketplace. The extensions are recorded so that the baseline notices new ones.

use super::history::judge_command;
use super::{record, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, shq};
use crate::modules::{Collector, ScanCtx};
use serde_json::Value;
use walkdir::WalkDir;

type Homes = [(String, u32, String)];

/// Ways a Vim or Lua script starts a program.
const SHELL_CALLS: [&str; 10] = ["system(", "systemlist(", "jobstart(", "os.execute(", "io.popen(", "vim.system(", "vim.loop.spawn(", "uv.spawn(", ":!", "silent !"];

/// Lines of an editor script that run a command typical of a break-in: (severity, line).
pub fn editor_commands(ctx: &ScanCtx, text: &str, lua: bool) -> Vec<(Severity, String)> {
    let comment = if lua { "--" } else { "\"" };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with(comment))
        .filter(|l| SHELL_CALLS.iter().any(|c| l.contains(c)) || l.starts_with('!') || l.contains("autocmd") && l.contains(" !"))
        .filter_map(|l| {
            // the command itself stands after the call or between quotes
            let inner = SHELL_CALLS.iter().find_map(|c| l.split_once(c).map(|(_, r)| r)).or_else(|| l.split_once('!').map(|(_, r)| r)).unwrap_or(l);
            let command = inner.trim_matches(|c| matches!(c, '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ' '));
            let (severity, why) = judge_command(ctx, command).or_else(|| judge_command(ctx, l))?;
            // fetching and running code is never an editor's job
            Some((severity.max(Severity::Medium), format!("{}  ← {why}", clip(l, 220))))
        })
        .collect()
}

fn script_files(ctx: &ScanCtx, homes: &Homes) -> Vec<String> {
    let mut files: Vec<String> = ["/etc/vim/vimrc.local", "/etc/xdg/nvim/sysinit.vim"].map(String::from).to_vec();
    for (_, _, home) in homes {
        files.extend([".vimrc", ".vim/vimrc", ".gvimrc", ".exrc"].iter().map(|f| format!("{home}/{f}")));
        for (folder, depth) in [(".vim/plugin", 2), (".vim/after", 3), (".vim/autoload", 2), (".vim/ftplugin", 2), (".vim/pack", 6), (".config/nvim", 5), (".local/share/nvim/site", 6)] {
            let walk = WalkDir::new(ctx.sys.path(format!("{home}/{folder}")))
                .max_depth(depth)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| e.file_name() != ".git")
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .take(1500);
            files.extend(walk.map(|e| ctx.sys.display(e.path())).filter(|p| p.ends_with(".vim") || p.ends_with(".lua")));
        }
    }
    files
}

fn check_scripts(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    for path in script_files(ctx, homes) {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        // settings and own plugins are watched; downloaded plugin collections change too often
        if !path.contains("/pack/") && !path.contains("/site/") {
            record(ctx, col, &path);
        }
        let found = editor_commands(ctx, &text, path.ends_with(".lua"));
        let Some(severity) = found.iter().map(|f| f.0).max() else { continue };
        let lines: Vec<String> = found.into_iter().map(|f| f.1).collect();
        col.push(
            Finding::new(severity, MODULE, "PERS-EDITOR-SCRIPT", format!("An editor script runs a suspicious command: {path}"))
                .evidence(format!("{path}\n{}", clip(&lines.join("\n"), 700)))
                .description("Vim and Neovim run their scripts whenever you open them, also with sudo if you kept your settings. Check that you added this.")
                .verify(format!("cat {}", shq(&path))),
        );
    }
}

/// Folders where VS Code and its relatives keep extensions, below a home folder.
const EXTENSION_ROOTS: [&str; 6] = [
    ".vscode/extensions", ".vscode-oss/extensions", ".vscode-server/extensions", ".cursor/extensions",
    ".var/app/com.vscodium.codium/data/codium/extensions", ".var/app/com.visualstudio.code/data/vscode/extensions",
];

/// An extension from `extensions.json`: (id, where it lies, where it came from).
pub fn listed_extensions(json: &str) -> Vec<(String, String, String)> {
    let Ok(Value::Array(list)) = serde_json::from_str::<Value>(json) else { return Vec::new() };
    list.iter()
        .filter_map(|e| {
            let id = e.pointer("/identifier/id")?.as_str()?.to_string();
            let path = e.pointer("/location/path").or_else(|| e.pointer("/location/fsPath")).and_then(Value::as_str).unwrap_or("");
            let relative = e.get("relativeLocation").and_then(Value::as_str).unwrap_or("");
            let place = if path.is_empty() { relative } else { path };
            let source = e.pointer("/metadata/source").and_then(Value::as_str).unwrap_or("");
            Some((id, place.to_string(), source.to_string()))
        })
        .collect()
}

fn check_extensions(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let mut inventory = Vec::new();
    for (_, _, home) in homes {
        for root in EXTENSION_ROOTS {
            let root = format!("{home}/{root}");
            if !ctx.sys.exists(&root) {
                continue;
            }
            let index = format!("{root}/extensions.json");
            let listed = ctx.sys.read_string(&index).ok().map(|t| listed_extensions(&t));
            let folders: Vec<String> = ctx.sys.dir_names(&root).into_iter().filter(|n| !n.starts_with('.') && ctx.sys.exists(format!("{root}/{n}/package.json"))).collect();
            let mut lines = Vec::new();
            let mut worst = None;
            for (id, place, source) in listed.iter().flatten() {
                inventory.push(format!("{root}: {id}"));
                let odd = !place.is_empty() && place.starts_with('/') && !place.starts_with(&format!("{root}/"));
                if odd {
                    worst = worst.max(Some(Severity::Medium));
                    lines.push(format!("{id}: loaded from {place}"));
                } else if source == "vsix" {
                    worst = worst.max(Some(Severity::Low));
                    lines.push(format!("{id}: installed from a file, not from the marketplace"));
                }
            }
            // a folder the editor does not list was put there by something else
            if let Some(listed) = &listed {
                for folder in &folders {
                    // folders are named "publisher.name-version"
                    let lower = folder.to_ascii_lowercase();
                    if !listed.iter().any(|(id, place, _)| lower.starts_with(&id.to_ascii_lowercase()) || place.ends_with(folder.as_str())) {
                        inventory.push(format!("{root}: {folder}"));
                        worst = worst.max(Some(Severity::Low));
                        lines.push(format!("{folder}: a folder the editor's list does not name (old version, or added by hand)"));
                    }
                }
            } else {
                inventory.extend(folders.iter().map(|f| format!("{root}: {f}")));
            }
            if let Some(severity) = worst {
                lines.sort();
                col.push(
                    Finding::new(severity, MODULE, "PERS-EDITOR-EXTENSION", format!("Editor extensions that did not come the usual way: {root}"))
                        .evidence(format!("{root}\n{}", clip(&lines.join("\n"), 800)))
                        .description("An extension can read your files, run programs and use your keys. Check that you installed each of these.")
                        .verify(format!("ls -l --time-style=full-iso {}", shq(&root))),
                );
            }
        }
    }
    inventory.sort();
    inventory.dedup();
    col.inventory.editor_plugins = Some(inventory);
}

pub fn check_editors(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    check_scripts(ctx, col, homes);
    check_extensions(ctx, col, homes);
}
