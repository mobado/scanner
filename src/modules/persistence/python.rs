//! Code that Python runs at every start: `.pth` files (lines starting with `import` are
//! executed) and `sitecustomize.py` / `usercustomize.py`. Looked for in the system folders,
//! `/usr/local`, each user's own packages and virtual environments in home folders.

use super::{record, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, shq};
use crate::modules::{homeindex, Collector, ScanCtx};
use crate::pkgverify::{tidy, verify_paths, Verdict};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::os::unix::fs::MetadataExt;
use std::time::SystemTime;

type Homes = [(String, u32, String)];

/// Things startup code has no business doing: running text as code, starting programs or
/// talking to the network.
const DANGEROUS: [(&str, &str); 14] = [
    ("exec(", "runs text as code"),
    ("eval(", "runs text as code"),
    ("marshal.loads", "loads hidden code"),
    ("base64", "unpacks encoded data"),
    ("zlib.decompress", "unpacks packed data"),
    ("subprocess", "starts programs"),
    ("os.system", "starts programs"),
    ("os.popen", "starts programs"),
    ("os.exec", "starts programs"),
    ("pty.spawn", "opens a terminal"),
    ("socket", "talks to the network"),
    ("urllib", "talks to the network"),
    ("urlopen", "talks to the network"),
    ("requests.", "talks to the network"),
];

/// Why a line of Python startup code is dangerous.
pub fn python_danger(line: &str) -> Option<&'static str> {
    DANGEROUS.iter().find(|(word, _)| line.contains(word)).map(|(_, why)| *why)
}

/// The lines of a `.pth` file that Python executes.
pub fn pth_code(text: &str) -> Vec<&str> {
    // Python reads the file as "utf-8-sig": a byte order mark does not hide the first line
    text.trim_start_matches('\u{feff}').lines().filter(|l| l.starts_with("import ") || l.starts_with("import\t")).collect()
}

/// Lines that tools write exactly like this: setuptools (new and old), virtualenv and coverage.
const TOOL_LINES: [&str; 4] = [
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; enabled and __import__('_distutils_hack').add_shim();",
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'stdlib') == 'local'; enabled and __import__('_distutils_hack').add_shim();",
    "import _virtualenv",
    "import coverage; coverage.process_startup()",
];

/// "import __editable___name_1_0_finder; __editable___name_1_0_finder.install()" (setuptools).
fn editable_line(line: &str) -> bool {
    let Some((name, rest)) = line.strip_prefix("import ").and_then(|l| l.split_once("; ")) else { return false };
    name.starts_with("__editable___")
        && name.ends_with("_finder")
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && rest == format!("{name}.install()")
}

/// The line setuptools writes for a namespace package. The package name and its folder are taken
/// from the line, which must then equal what setuptools writes for them, character for character.
fn namespace_line(line: &str) -> bool {
    let Some((root, rest)) = line.split_once("p = os.path.join(").and_then(|(_, r)| r.split_once(", *(")) else { return false };
    let quoted_path = root.len() > 2 && root.starts_with('\'') && root.ends_with('\'') && !root[1..root.len() - 1].contains(['\'', '\\', '"']);
    if root != "sys._getframe(1).f_locals['sitedir']" && !quoted_path {
        return false;
    }
    let Some((tuple, _)) = rest.split_once("))") else { return false };
    let parts: Option<Vec<&str>> = tuple
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| p.strip_prefix('\'')?.strip_suffix('\'').filter(|n| !n.is_empty() && n.chars().all(|c| c.is_alphanumeric() || c == '_')))
        .collect();
    let Some(parts) = parts.filter(|p| !p.is_empty()) else { return false };
    let tuple = match parts.as_slice() {
        [one] => format!("('{one}',)"),
        many => format!("('{}')", many.join("', '")),
    };
    let pkg = parts.join(".");
    let parent = match parts.split_last() {
        Some((child, parents)) if !parents.is_empty() => format!(";m and setattr(sys.modules['{}'], '{child}', m)", parents.join(".")),
        _ => String::new(),
    };
    // since setuptools 70 and before (with the check for Python 3.5)
    [("", "", ""), ("has_mfs = sys.version_info > (3, 5);", "has_mfs and ", "has_mfs and ")].iter().any(|(has, importlib, found)| {
        line == format!(
            "import sys, types, os;{has}p = os.path.join({root}, *{tuple});importlib = {importlib}__import__('importlib.util');{importlib}__import__('importlib.machinery');m = {found}sys.modules.setdefault('{pkg}', importlib.util.module_from_spec(importlib.machinery.PathFinder.find_spec('{pkg}', [os.path.dirname(p)])));m = m or sys.modules.setdefault('{pkg}', types.ModuleType('{pkg}'));mp = (m or []) and m.__dict__.setdefault('__path__',[]);(p not in mp) and mp.append(p){parent}"
        )
    })
}

/// A `.pth` line that is exactly what setuptools, editable installs, namespace packages,
/// virtualenv or coverage write themselves. Anything added to it makes it unusual.
pub fn usual_pth_line(line: &str) -> bool {
    let line = line.trim_end();
    TOOL_LINES.contains(&line) || editable_line(line) || namespace_line(line)
}

/// The folders Python reads startup files from.
fn python_folders(ctx: &ScanCtx, homes: &Homes) -> BTreeSet<String> {
    let mut folders = BTreeSet::new();
    let mut add_versions = |base: String| {
        for name in ctx.sys.dir_names(&base).into_iter().filter(|n| n.starts_with("python3")) {
            let version = format!("{base}/{name}");
            folders.extend([format!("{version}/site-packages"), format!("{version}/dist-packages"), version]);
        }
    };
    add_versions("/usr/lib".into());
    add_versions("/usr/local/lib".into());
    for (_, _, home) in homes {
        add_versions(format!("{home}/.local/lib"));
    }
    // virtual environments of projects
    for (_, _, home) in homes {
        folders.extend(homeindex::of(ctx, home).site_packages.iter().cloned());
    }
    folders
}

/// The files of a folder that Python imports by itself at every start, as source, package or
/// compiled module.
fn customize_files(ctx: &ScanCtx, folder: &str) -> Vec<String> {
    let names = ctx.sys.dir_names(folder);
    let mut found = Vec::new();
    for module in ["sitecustomize", "usercustomize"] {
        for name in &names {
            let rest = name.strip_prefix(module);
            if rest == Some(".py") || rest == Some(".pyc") || rest.is_some_and(|r| r.starts_with('.') && r.ends_with(".so")) {
                found.push(format!("{folder}/{name}"));
            } else if rest == Some("") && ctx.sys.exists(format!("{folder}/{name}/__init__.py")) {
                found.push(format!("{folder}/{name}/__init__.py"));
            }
        }
    }
    found
}

fn startup_files(ctx: &ScanCtx, homes: &Homes) -> Vec<String> {
    let mut files = Vec::new();
    for folder in python_folders(ctx, homes) {
        files.extend(ctx.sys.dir_names(&folder).into_iter().filter(|n| n.ends_with(".pth")).map(|n| format!("{folder}/{n}")));
        files.extend(customize_files(ctx, &folder));
    }
    files
}

/// The folders the lines of a `.pth` file in `folder` add to Python's search path.
pub fn pth_folders(folder: &str, text: &str) -> Vec<String> {
    text.trim_start_matches('\u{feff}')
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty() && !l.starts_with("import ") && !l.starts_with("import\t"))
        .map(|l| {
            let l = l.trim_end();
            tidy(&if l.starts_with('/') { l.to_string() } else { format!("{folder}/{l}") })
        })
        .collect()
}

/// The user whose home folder holds a path. Homes of system accounts don't count.
fn home_of<'a>(homes: &'a Homes, path: &str) -> Option<&'a (String, u32, String)> {
    homes
        .iter()
        .filter(|(_, uid, home)| (*uid == 0 || (*uid >= 1000 && *uid != 65534) || home.starts_with("/home/")) && home != "/")
        .filter(|(_, _, home)| path.strip_prefix(home.as_str()).is_some_and(|rest| rest.is_empty() || rest.starts_with('/')))
        .max_by_key(|(_, _, home)| home.len())
}

/// The accounts and groups of the scanned system.
#[derive(Default)]
struct Accounts {
    users: HashMap<u32, String>,
    /// Group id → name and the user ids of its members (listed, or as their main group).
    groups: HashMap<u32, (String, BTreeSet<u32>)>,
}

fn accounts(ctx: &ScanCtx) -> Accounts {
    let mut found = Accounts::default();
    let passwd = ctx.sys.read_string("/etc/passwd").unwrap_or_default();
    let group = ctx.sys.read_string("/etc/group").unwrap_or_default();
    let mut ids = HashMap::new();
    let mut main = Vec::new();
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        let (Some(name), Some(Ok(uid)), Some(Ok(gid))) = (f.first(), f.get(2).map(|v| v.parse::<u32>()), f.get(3).map(|v| v.parse::<u32>())) else { continue };
        found.users.entry(uid).or_insert_with(|| name.to_string());
        ids.insert(name.to_string(), uid);
        main.push((gid, uid));
    }
    for line in group.lines() {
        let f: Vec<&str> = line.split(':').collect();
        let (Some(name), Some(Ok(gid))) = (f.first(), f.get(2).map(|v| v.parse::<u32>())) else { continue };
        let entry = found.groups.entry(gid).or_insert_with(|| (name.to_string(), BTreeSet::new()));
        entry.1.extend(f.get(3).into_iter().flat_map(|m| m.split(',')).filter_map(|m| ids.get(m.trim())));
    }
    for (gid, uid) in main {
        found.groups.entry(gid).or_insert_with(|| (gid.to_string(), BTreeSet::new())).1.insert(uid);
    }
    found
}

/// Follow every link in a path, folder by folder, inside the scanned system.
fn real_path(ctx: &ScanCtx, path: &str) -> String {
    let mut rest: VecDeque<String> = path.split('/').filter(|p| !p.is_empty()).map(String::from).collect();
    let mut done = String::new();
    let mut links = 0;
    while let Some(part) = rest.pop_front() {
        if part == "." {
            continue;
        }
        if part == ".." {
            done.truncate(done.rfind('/').unwrap_or(0));
            continue;
        }
        let next = format!("{done}/{part}");
        match ctx.sys.read_link(&next) {
            Some(target) if links < 40 => {
                links += 1;
                if target.starts_with('/') {
                    done.clear();
                }
                for part in target.split('/').filter(|p| !p.is_empty()).rev() {
                    rest.push_front(part.to_string());
                }
            }
            _ => done = next,
        }
    }
    if done.is_empty() { "/".into() } else { done }
}

/// Can someone other than root and the `trusted` users change what is in this folder, through
/// its own rights or those of a folder above it? The check stops at a link (followed apart).
fn writable_by(ctx: &ScanCtx, accounts: &Accounts, trusted: &BTreeSet<u32>, folder: &str) -> Option<String> {
    let mut prefixes = vec!["/".to_string()];
    let mut at = String::new();
    for part in folder.split('/').filter(|p| !p.is_empty()) {
        at = format!("{at}/{part}");
        prefixes.push(at.clone());
    }
    let mut found = Vec::new();
    for prefix in &prefixes {
        match std::fs::symlink_metadata(ctx.sys.path(prefix)) {
            Ok(meta) if meta.is_dir() => found.push((prefix, meta)),
            _ => break,
        }
    }
    // what does not exist yet can be made by whoever may write to the last folder that does
    let last = found.len().checked_sub(1)?;
    for (i, (place, meta)) in found.iter().enumerate() {
        // in a sticky folder others can add files but not replace those of someone else
        let counts = meta.mode() & 0o1000 == 0 || i == last;
        if meta.mode() & 0o002 != 0 && counts {
            return Some(format!("everyone can write to {place}"));
        }
        if meta.mode() & 0o020 != 0 && counts {
            if let Some((group, members)) = accounts.groups.get(&meta.gid()) {
                let others: Vec<&str> = members.iter().filter(|u| **u != 0 && !trusted.contains(u)).map(|u| accounts.users.get(u).map(String::as_str).unwrap_or("?")).collect();
                if !others.is_empty() {
                    return Some(format!("group {group} can write to {place} ({})", others.join(", ")));
                }
            }
        }
        if meta.uid() != 0 && !trusted.contains(&meta.uid()) {
            let owner = accounts.users.get(&meta.uid()).cloned().unwrap_or_else(|| format!("user id {}", meta.uid()));
            return Some(format!("{place} belongs to {owner}, who can change what runs"));
        }
    }
    None
}

/// Why Python should not load code from a folder that the file `pth` adds, if it should not.
/// Links on the way are followed.
fn odd_folder(ctx: &ScanCtx, homes: &Homes, accounts: &Accounts, pth: &str, folder: &str) -> Option<String> {
    let target = real_path(ctx, folder);
    let why = |place: &str| {
        if ctx.cfg.is_temp_path(place) || ["/tmp/", "/var/tmp/", "/dev/shm/"].iter().any(|t| format!("{place}/").starts_with(t)) {
            return Some("a temporary folder, which others can write to".to_string());
        }
        let owner = home_of(homes, place)?;
        (home_of(homes, pth) != Some(owner)).then(|| format!("in the home folder of {}, who can change what runs", owner.0))
    };
    // whoever owns the path file, or the home it lies in, can already change what runs
    let mut trusted: BTreeSet<u32> = home_of(homes, pth).map(|h| h.1).into_iter().collect();
    trusted.extend(std::fs::symlink_metadata(ctx.sys.path(pth)).map(|m| m.uid()));
    why(folder)
        .or_else(|| why(&target))
        .or_else(|| writable_by(ctx, accounts, &trusted, &target))
        .or_else(|| writable_by(ctx, accounts, &trusted, folder))
}

/// Look at the folders `.pth` files add: Python searches them for `sitecustomize` and
/// `usercustomize` too. Returns those files, each with whether its folder is an odd one.
fn added_folders(ctx: &ScanCtx, col: &mut Collector, homes: &Homes, files: &[String]) -> HashMap<String, (String, bool)> {
    let mut reached = HashMap::new();
    let accounts = accounts(ctx);
    for pth in files.iter().filter(|f| f.ends_with(".pth")) {
        // every path file goes into the baseline, also one that only names folders
        record(ctx, col, pth);
        let Ok(bytes) = ctx.sys.read_bytes(pth) else { continue };
        let folder = pth.rsplit_once('/').map(|(f, _)| f).unwrap_or("");
        let mut odd = Vec::new();
        for added in pth_folders(folder, &String::from_utf8_lossy(&bytes)) {
            let why = odd_folder(ctx, homes, &accounts, pth, &added);
            let runs = customize_files(ctx, &added);
            if let Some(why) = &why {
                odd.push(format!("adds {added}: {why}"));
                odd.extend(runs.iter().map(|r| format!("  runs at every start: {r}")));
            }
            for file in runs {
                let entry = reached.entry(file).or_insert((pth.clone(), false));
                entry.1 |= why.is_some();
            }
        }
        if !odd.is_empty() {
            col.push(
                Finding::new(Severity::High, MODULE, "PERS-PYTHON-PATH", format!("A Python path file adds a folder that others control: {pth}"))
                    .evidence(format!("{pth}\n{}", clip(&odd.join("\n"), 800)))
                    .description("Python adds this folder to the places it loads code from and runs a sitecustomize.py or usercustomize.py found there at every start. Whoever can write to the folder runs code in your Python programs.")
                    .verify(format!("cat {}", shq(pth)))
                    .verify(format!("dpkg -S {}", shq(pth))),
            );
        }
    }
    reached
}

pub fn check_python(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let mut files = startup_files(ctx, homes);
    if files.is_empty() {
        return;
    }
    let reached = added_folders(ctx, col, homes, &files);
    files.extend(reached.keys().cloned());
    files.sort();
    files.dedup();
    let has_dpkg = !ctx.sys.dir_names("/var/lib/dpkg/info").is_empty();
    let verdicts = verify_paths(ctx.sys, &files, SystemTime::UNIX_EPOCH);
    for path in files {
        let Ok(bytes) = ctx.sys.read_bytes(&path) else { continue };
        let packaged = match verdicts.get(&path) {
            Some(Verdict::Upgraded { .. } | Verdict::MatchesButNoUpgrade { .. }) => continue,
            Some(Verdict::Differs { package }) => Some(package.clone()),
            _ => None,
        };
        let text = String::from_utf8_lossy(&bytes);
        let pth = path.ends_with(".pth");
        let compiled = path.ends_with(".pyc") || path.ends_with(".so");
        let code: Vec<&str> = if compiled {
            vec!["(a compiled module: its code cannot be read)"]
        } else if pth {
            pth_code(&text)
        } else {
            text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect()
        };
        if code.is_empty() {
            continue;
        }
        record(ctx, col, &path);
        // an ordinary .pth line from a tool, in a file of no package
        if pth && packaged.is_none() && code.iter().all(|l| usual_pth_line(l)) {
            continue;
        }
        let through = reached.get(&path);
        let odd = through.is_some_and(|t| t.1);
        let dangers: Vec<String> = code.iter().filter_map(|l| python_danger(l).map(|why| format!("{}  ← {why}", clip(l, 220)))).collect();
        let severity = if !dangers.is_empty() || odd {
            Severity::High
        } else if packaged.is_some() || has_dpkg {
            Severity::Medium
        } else {
            Severity::Low
        };
        let shown = if dangers.is_empty() { code.iter().take(6).map(|l| clip(l, 220)).collect() } else { dangers };
        let mut origin = packaged.map(|p| format!("differs from what package {p} ships")).unwrap_or_else(|| "from no package".into());
        if let Some((pth, _)) = through {
            origin.push_str(&format!("\nPython finds it through {pth}"));
        }
        col.push(
            Finding::new(severity, MODULE, "PERS-PYTHON-STARTUP", format!("Python runs code from this file at every start: {path}"))
                .evidence(format!("{path}\n{origin}\n{}", clip(&shown.join("\n"), 800)))
                .description("Every Python program, including system tools that use Python, runs this code before its own. Development tools add such files; it is also a quiet way to stay on a machine.")
                .verify(format!("cat {}", shq(&path)))
                .verify(format!("dpkg -S {}", shq(&path))),
        );
    }
}
