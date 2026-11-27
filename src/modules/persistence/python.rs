//! Code that Python runs at every start: `.pth` files (lines starting with `import` are
//! executed) and `sitecustomize.py` / `usercustomize.py`. Looked for in the system folders,
//! `/usr/local`, each user's own packages and virtual environments in home folders.

use super::{record, MODULE};
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, shq};
use crate::modules::{Collector, ScanCtx};
use crate::pkgverify::{verify_paths, Verdict};
use std::collections::BTreeSet;
use std::time::SystemTime;
use walkdir::WalkDir;

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
    text.lines().filter(|l| l.starts_with("import ") || l.starts_with("import\t")).collect()
}

/// A line that setuptools, editable installs, namespace packages, virtualenv or coverage
/// write themselves.
pub fn usual_pth_line(line: &str) -> bool {
    let known = ["_distutils_hack", "__editable___", "has_mfs", "import _virtualenv", "coverage.process_startup"].iter().any(|k| line.contains(k));
    known && python_danger(line).is_none()
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
        const SKIPPED: [&str; 8] = [".cache", "node_modules", ".git", "Trash", "Steam", ".var", "flatpak", "containers"];
        let walk = WalkDir::new(ctx.sys.path(home))
            .max_depth(7)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !(e.file_type().is_dir() && SKIPPED.iter().any(|s| e.file_name() == *s)))
            .filter_map(|e| e.ok())
            .take(60_000);
        folders.extend(walk.filter(|e| e.file_type().is_dir() && e.file_name() == "site-packages").map(|e| ctx.sys.display(e.path())));
    }
    folders
}

fn startup_files(ctx: &ScanCtx, homes: &Homes) -> Vec<String> {
    let mut files = Vec::new();
    for folder in python_folders(ctx, homes) {
        for name in ctx.sys.dir_names(&folder) {
            if name.ends_with(".pth") || name == "sitecustomize.py" || name == "usercustomize.py" {
                files.push(format!("{folder}/{name}"));
            }
        }
    }
    files
}

pub fn check_python(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let files = startup_files(ctx, homes);
    if files.is_empty() {
        return;
    }
    let has_dpkg = !ctx.sys.dir_names("/var/lib/dpkg/info").is_empty();
    let verdicts = verify_paths(ctx.sys, &files, SystemTime::UNIX_EPOCH);
    for path in files {
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        let packaged = match verdicts.get(&path) {
            Some(Verdict::Upgraded { .. } | Verdict::MatchesButNoUpgrade { .. }) => continue,
            Some(Verdict::Differs { package }) => Some(package.clone()),
            _ => None,
        };
        let pth = path.ends_with(".pth");
        let code: Vec<&str> = if pth { pth_code(&text) } else { text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect() };
        if code.is_empty() {
            continue;
        }
        record(ctx, col, &path);
        // an ordinary .pth line from a tool, in a file of no package
        if pth && packaged.is_none() && code.iter().all(|l| usual_pth_line(l)) {
            continue;
        }
        let dangers: Vec<String> = code.iter().filter_map(|l| python_danger(l).map(|why| format!("{}  ← {why}", clip(l, 220)))).collect();
        let severity = if !dangers.is_empty() {
            Severity::High
        } else if packaged.is_some() || has_dpkg {
            Severity::Medium
        } else {
            Severity::Low
        };
        let shown = if dangers.is_empty() { code.iter().take(6).map(|l| clip(l, 220)).collect() } else { dangers };
        let origin = packaged.map(|p| format!("differs from what package {p} ships")).unwrap_or_else(|| "from no package".into());
        col.push(
            Finding::new(severity, MODULE, "PERS-PYTHON-STARTUP", format!("Python runs code from this file at every start: {path}"))
                .evidence(format!("{path}\n{origin}\n{}", clip(&shown.join("\n"), 800)))
                .description("Every Python program, including system tools that use Python, runs this code before its own. Development tools add such files; it is also a quiet way to stay on a machine.")
                .verify(format!("cat {}", shq(&path)))
                .verify(format!("dpkg -S {}", shq(&path))),
        );
    }
}
