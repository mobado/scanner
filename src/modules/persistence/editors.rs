//! Editors and IDEs run their settings and plugins whenever they start: Vim and Neovim
//! scripts that start shell commands, and VS Code-family extensions that did not come from the
//! marketplace. The extensions are recorded so that the baseline notices new ones.

use super::history::judge_command;
use super::{record, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_command, capped, clip, shq};
use crate::modules::{homeindex, Collector, ScanCtx};
use serde_json::Value;
use walkdir::WalkDir;

type Homes = [(String, u32, String)];

/// Ways a Vim or Lua script starts a program.
const SHELL_CALLS: [&str; 10] = ["system(", "systemlist(", "jobstart(", "os.execute(", "io.popen(", "vim.system(", "vim.loop.spawn(", "uv.spawn(", ":!", "silent !"];

/// The shell command in `vim.cmd("!…")`, `vim.cmd [[silent !…]]` and the older `nvim_command`
/// and `nvim_exec`.
fn command_from_lua(line: &str) -> Option<&str> {
    ["vim.cmd", "nvim_command", "nvim_exec2", "nvim_exec"].iter().filter_map(|call| line.split_once(call)).find_map(|(_, rest)| {
        let text = rest.trim_start_matches(['(', ' ', '"', '\'', '[', '=']);
        let text = ["silent! ", "silent ", "sil! ", "sil "].iter().find_map(|s| text.strip_prefix(s)).unwrap_or(text);
        text.strip_prefix('!')
    })
}

/// Lines of an editor script that run a command typical of a break-in: (severity, line).
pub fn editor_commands(ctx: &ScanCtx, text: &str, lua: bool) -> Vec<(Severity, String)> {
    let comment = if lua { "--" } else { "\"" };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with(comment))
        .filter(|l| SHELL_CALLS.iter().any(|c| l.contains(c)) || l.starts_with('!') || l.contains("autocmd") && l.contains(" !") || command_from_lua(l).is_some())
        .filter_map(|l| {
            // the command itself stands after the call or between quotes
            let inner = command_from_lua(l)
                .or_else(|| SHELL_CALLS.iter().find_map(|c| l.split_once(c).map(|(_, r)| r)))
                .or_else(|| l.split_once('!').map(|(_, r)| r))
                .unwrap_or(l);
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
        // ".local/share/nvim/lazy" is where the lazy.nvim plugin manager puts plugins
        for (folder, depth) in [(".vim/plugin", 2), (".vim/after", 3), (".vim/autoload", 2), (".vim/ftplugin", 2), (".vim/pack", 6), (".config/nvim", 5), (".local/share/nvim/site", 6), (".local/share/nvim/lazy", 7)] {
            let folder = format!("{home}/{folder}");
            let walk = WalkDir::new(ctx.sys.path(&folder))
                .max_depth(depth)
                .follow_links(false)
                .into_iter()
                .filter_entry(|e| e.file_name() != ".git")
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file() && e.file_name().to_str().is_some_and(|n| n.ends_with(".vim") || n.ends_with(".lua")));
            files.extend(capped(walk, 5000, format!("{folder} for editor scripts")).map(|e| ctx.sys.display(e.path())));
        }
    }
    files
}

fn check_scripts(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    for path in script_files(ctx, homes) {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        // settings and own plugins are watched; downloaded plugin collections change too often
        if !["/pack/", "/site/", "/nvim/lazy/"].iter().any(|p| path.contains(p)) {
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

/// Is the folder the one of this extension: the id itself, or the id, "-" and a version number?
pub fn folder_of(folder: &str, id: &str) -> bool {
    match folder.strip_prefix(id) {
        Some("") => true,
        Some(rest) => rest.strip_prefix('-').is_some_and(|v| v.starts_with(|c: char| c.is_ascii_digit())),
        None => false,
    }
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
                    if !listed.iter().any(|(id, place, _)| folder_of(&lower, &id.to_ascii_lowercase()) || place.rsplit('/').next() == Some(folder.as_str())) {
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

/// VS Code settings files allow comments and trailing commas; take them out before reading.
pub fn plain_json(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            if c == '\\' {
                out.extend(chars.next());
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match (c, chars.peek()) {
            ('/', Some('/')) => {
                while chars.peek().is_some_and(|c| *c != '\n') {
                    chars.next();
                }
            }
            ('/', Some('*')) => {
                chars.next();
                let mut star = false;
                for c in chars.by_ref() {
                    if star && c == '/' {
                        break;
                    }
                    star = c == '*';
                }
            }
            ('}' | ']', _) => {
                let kept = out.trim_end().len();
                if out[..kept].ends_with(',') {
                    out.truncate(kept - 1);
                }
                out.push(c);
            }
            _ => {
                in_string = c == '"';
                out.push(c);
            }
        }
    }
    out
}

/// The commands of a `tasks.json` that run by themselves when the folder is opened. `None` when
/// the file asks for that but cannot be understood.
pub fn folder_open_tasks(text: &str) -> Option<Vec<String>> {
    if !text.contains("folderOpen") {
        return Some(Vec::new());
    }
    let json: Value = serde_json::from_str(&plain_json(text)).ok()?;
    let text_of = |v: &Value| v.as_str().map(String::from).or_else(|| v.get("value").and_then(Value::as_str).map(String::from));
    // a task, or its settings for Linux, names a program and its arguments
    let command = |task: &Value| -> Option<String> {
        let place = task.get("linux").filter(|l| l.get("command").is_some()).unwrap_or(task);
        let program = place.get("command").and_then(text_of).or_else(|| task.get("script").and_then(text_of).map(|s| format!("npm run {s}")))?;
        let arguments = place.get("args").or_else(|| task.get("args")).and_then(Value::as_array).into_iter().flatten().filter_map(text_of);
        Some(std::iter::once(program).chain(arguments).collect::<Vec<_>>().join(" "))
    };
    let tasks = json.get("tasks").and_then(Value::as_array)?;
    Some(
        tasks
            .iter()
            .filter(|t| t.pointer("/runOptions/runOn").and_then(Value::as_str) == Some("folderOpen"))
            .map(|t| command(t).unwrap_or_else(|| format!("task {}", t.get("label").and_then(Value::as_str).unwrap_or("without a name"))))
            .collect(),
    )
}

/// Where VS Code and its relatives keep a user's own settings and tasks, below a home folder.
const USER_FOLDERS: [&str; 8] = [
    ".config/Code/User", ".config/Code - Insiders/User", ".config/Code - OSS/User", ".config/VSCodium/User", ".config/Cursor/User",
    ".var/app/com.visualstudio.code/config/Code/User", ".var/app/com.vscodium.codium/config/VSCodium/User", ".vscode-server/data/User",
];

/// The user folders a home has, with their profiles, and the settings of a remote server.
fn user_folders(ctx: &ScanCtx, home: &str) -> Vec<String> {
    let mut found = Vec::new();
    for folder in USER_FOLDERS.iter().map(|f| format!("{home}/{f}")) {
        if !ctx.sys.exists(&folder) {
            continue;
        }
        found.extend(ctx.sys.dir_names(format!("{folder}/profiles")).into_iter().map(|p| format!("{folder}/profiles/{p}")));
        found.push(folder);
    }
    found.push(format!("{home}/.vscode-server/data/Machine"));
    found
}

/// Do these settings let folder tasks run without asking (`task.allowAutomaticTasks`)?
pub fn allows_automatic_tasks(settings: &str) -> bool {
    const KEY: &str = "task.allowAutomaticTasks";
    match serde_json::from_str::<Value>(&plain_json(settings)) {
        Ok(json) => json.get(KEY).and_then(Value::as_str) == Some("on"),
        // a damaged file: look at the line that sets it
        Err(_) => settings.lines().map(str::trim).any(|l| !l.starts_with("//") && l.contains(KEY) && l.contains("\"on\"")),
    }
}

/// A `tasks.json` with tasks that start by themselves. `own` is a user's own file, which counts
/// for every window; `allowed` names the settings file that lets such tasks run unasked.
fn judge_tasks(ctx: &ScanCtx, col: &mut Collector, path: &str, own: bool, allowed: Option<&str>) {
    let Ok(bytes) = ctx.sys.read_bytes(path) else { return };
    let text = String::from_utf8_lossy(&bytes);
    let tasks = folder_open_tasks(&text);
    if tasks.as_ref().is_some_and(Vec::is_empty) {
        return;
    }
    record(ctx, col, path);
    // a file that cannot be read as settings is judged as plain text
    let commands = tasks.unwrap_or_else(|| text.lines().map(|l| l.trim().to_string()).filter(|l| l.contains("\"command\"") || l.contains("folderOpen")).collect());
    let mut suspicious = false;
    let mut lines: Vec<String> = commands
        .iter()
        .map(|command| {
            let typed = judge_command(ctx, command).filter(|j| j.0 >= Severity::Medium).map(|j| j.1);
            let why = typed.or_else(|| analyze_command(command, ctx.cfg).into_iter().find(|i| i.severity >= Severity::Critical).map(|i| i.reason));
            suspicious |= why.is_some();
            match why {
                Some(why) => format!("{}  ← {why}", clip(command, 220)),
                None => clip(command, 220),
            }
        })
        .collect();
    if let Some(settings) = allowed {
        lines.insert(0, format!("runs without asking: task.allowAutomaticTasks is \"on\" in {settings}"));
    }
    let (title, text) = if own {
        ("Your VS Code tasks run a command whenever a window opens", "A task in your own tasks.json with runOn folderOpen starts in every folder you open, once automatic tasks are allowed. Check that you added it.")
    } else {
        ("A project runs a command as soon as its folder is opened", "VS Code and its relatives run this task when the folder is opened, once you trust the folder and allow automatic tasks. Cloned projects use it to run code on your computer. Check the command before you open the folder.")
    };
    col.push(
        Finding::new(if suspicious || allowed.is_some() { Severity::High } else { Severity::Medium }, MODULE, "PERS-VSCODE-TASK", format!("{title}: {path}"))
            .evidence(format!("{path}\n{}", clip(&lines.join("\n"), 700)))
            .description(text)
            .verify(format!("cat {}", shq(path))),
    );
}

/// Tasks that start when a folder is opened, in projects and in the user's own settings.
fn check_folder_tasks(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    for (user, _, home) in homes {
        let folders = user_folders(ctx, home);
        let mut allowed = Vec::new();
        for settings in folders.iter().map(|f| format!("{f}/settings.json")) {
            if ctx.sys.read_bytes(&settings).is_ok_and(|b| allows_automatic_tasks(&String::from_utf8_lossy(&b))) {
                allowed.push(settings);
            }
        }
        if let Some(first) = allowed.first() {
            col.push(
                Finding::new(Severity::Low, MODULE, "PERS-VSCODE-AUTOTASKS", format!("VS Code runs folder tasks of {user} without asking"))
                    .evidence(allowed.join("\n"))
                    .description("With task.allowAutomaticTasks \"on\", a trusted project can run commands the moment you open it, with no question. Set it to \"off\" unless you need it.")
                    .verify(format!("grep -n allowAutomaticTasks {}", shq(first))),
            );
        }
        let allowed = allowed.first().map(String::as_str);
        for path in folders.iter().map(|f| format!("{f}/tasks.json")) {
            judge_tasks(ctx, col, &path, true, allowed);
        }
        for path in &homeindex::of(ctx, home).vscode_tasks {
            judge_tasks(ctx, col, path, false, allowed);
        }
    }
}

/// Plugins of IntelliJ, PyCharm and the other JetBrains editors: one folder per editor and
/// version, with one folder or `.jar` file per plugin you added.
fn jetbrains_plugins(ctx: &ScanCtx, homes: &Homes) -> Vec<String> {
    let mut plugins = Vec::new();
    for (_, _, home) in homes {
        let base = format!("{home}/.local/share/JetBrains");
        // "IntelliJIdea2025.1", "PyCharm2024.3": other folders hold the Toolbox and shared data
        for editor in ctx.sys.dir_names(&base).into_iter().filter(|n| n.contains("20") && n.chars().next_back().is_some_and(|c| c.is_ascii_digit())) {
            let folder = format!("{base}/{editor}");
            for name in ctx.sys.dir_names(&folder) {
                if name.ends_with(".jar") || ctx.sys.exists(format!("{folder}/{name}/lib")) {
                    plugins.push(format!("{folder}: {name}"));
                }
            }
        }
    }
    plugins
}

pub fn check_editors(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    check_scripts(ctx, col, homes);
    check_extensions(ctx, col, homes);
    check_folder_tasks(ctx, col, homes);
    let plugins = jetbrains_plugins(ctx, homes);
    if !plugins.is_empty() {
        col.push(
            Finding::new(Severity::Info, MODULE, "PERS-JETBRAINS-PLUGIN", format!("{} plugin(s) added to JetBrains editors", plugins.len()))
                .evidence(clip(&plugins.join("\n"), 1500))
                .description("A plugin can read your files and run programs. The baseline notices new ones; check that you installed each of these.")
                .verify("ls -l --time-style=full-iso ~/.local/share/JetBrains/*/"),
        );
        let inventory = col.inventory.editor_plugins.get_or_insert_with(Vec::new);
        inventory.extend(plugins);
        inventory.sort();
        inventory.dedup();
    }
}
