//! One walk through each home folder, shared by the checks that look for files anywhere in it:
//! Python environments, VS Code folder tasks, `.env` files and proxy auto-config files. Large
//! home folders are walked once per scan instead of once per check.

use super::common::cut_short;
use super::ScanCtx;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use walkdir::{DirEntry, WalkDir};

/// The files and folders of one home that the checks look at.
#[derive(Debug, Default)]
pub struct HomeIndex {
    /// Folders named `site-packages` (up to 7 levels down).
    pub site_packages: Vec<String>,
    /// `.vscode/tasks.json` of project folders (up to 8 levels down).
    pub vscode_tasks: Vec<String>,
    /// `.env` files of projects (up to 4 levels down).
    pub env_files: Vec<String>,
    /// `*.pac` and `wpad.dat` (up to 3 levels down).
    pub pac_files: Vec<String>,
}

/// Folders none of the checks look in, wherever they are: caches, downloaded libraries, games
/// and containers.
const SKIPPED: [&str; 20] = [
    "node_modules", ".git", ".cache", "Trash", "Steam", ".var", "flatpak", "containers", ".rustup", ".npm", ".gradle", ".m2",
    ".nuget", ".ivy2", ".pub-cache", ".yarn", ".pnpm-store", ".bun", ".sbt", ".stack",
];
/// Package caches at a known place below a home folder, often with hundreds of thousands of files.
const CACHES: [&str; 14] = [
    ".cargo/registry", ".cargo/git", ".conda/pkgs", "miniconda3/pkgs", "anaconda3/pkgs", "miniforge3/pkgs", "mambaforge/pkgs",
    "go/pkg/mod", ".vscode/extensions", ".local/share/pnpm", ".julia/packages", ".julia/artifacts", ".cabal/packages", ".opam",
];
/// Hidden folders that hold Python environments or proxy files. Each is searched on its own, so
/// that nothing else in a big home can push it past the limit.
const NEEDED: [&str; 9] = [
    ".local/lib", ".virtualenvs", ".pyenv/versions", ".conda/envs", ".local/share/virtualenvs", ".local/share/pipx/venvs",
    ".local/pipx/venvs", ".cache/pypoetry/virtualenvs", ".config",
];
/// How far below the home the checks look, and how far inside the needed folders.
const DEPTH: usize = 8;
const NEEDED_DEPTH: usize = 10;
const LIMIT: usize = 1_000_000;

thread_local! {
    /// The homes already walked by the running scan.
    static WALKED: RefCell<HashMap<PathBuf, Rc<HomeIndex>>> = RefCell::default();
}

/// Forget what an earlier scan saw.
pub fn forget() {
    WALKED.with(|w| w.borrow_mut().clear());
}

/// The index of a home folder, made at the first question about it.
pub fn of(ctx: &ScanCtx, home: &str) -> Rc<HomeIndex> {
    let root = ctx.sys.path(home);
    if let Some(known) = WALKED.with(|w| w.borrow().get(&root).cloned()) {
        return known;
    }
    let index = Rc::new(build(ctx, home, LIMIT));
    WALKED.with(|w| w.borrow_mut().insert(root, index.clone()));
    index
}

/// Search a home folder, looking at no more than `limit` files and folders per part: first each
/// of the needed hidden folders, then the rest with ordinary folders before hidden ones.
pub fn build(ctx: &ScanCtx, home: &str, limit: usize) -> HomeIndex {
    let root = ctx.sys.path(home);
    let mut index = HomeIndex::default();
    for part in NEEDED {
        if root.join(part).is_dir() {
            search(ctx, &root, Some(part), limit, &mut index);
        }
    }
    search(ctx, &root, None, limit, &mut index);
    for list in [&mut index.site_packages, &mut index.vscode_tasks, &mut index.env_files, &mut index.pac_files] {
        list.sort();
        list.dedup();
    }
    index
}

/// Search one needed folder of a home (`part`), or the whole home without them.
fn search(ctx: &ScanCtx, root: &Path, part: Option<&str>, limit: usize, index: &mut HomeIndex) {
    let (start, depth_left) = match part {
        Some(part) => (root.join(part), NEEDED_DEPTH - part.split('/').count()),
        None => (root.to_path_buf(), DEPTH),
    };
    let skip = |e: &DirEntry| {
        if e.depth() == 0 || !e.file_type().is_dir() {
            return false;
        }
        if SKIPPED.iter().any(|s| e.file_name() == *s) {
            return true;
        }
        let Ok(below) = e.path().strip_prefix(root) else { return false };
        CACHES.iter().any(|c| below == Path::new(c)) || part.is_none() && NEEDED.iter().any(|n| below == Path::new(n))
    };
    let mut walk = WalkDir::new(&start)
        .max_depth(depth_left)
        .follow_links(false)
        // ordinary folders first: projects are searched before settings and tool folders
        .sort_by(|a, b| {
            let key = |e: &DirEntry| e.file_name().as_encoded_bytes().starts_with(b".");
            key(a).cmp(&key(b)).then_with(|| a.file_name().cmp(b.file_name()))
        })
        .into_iter()
        .filter_entry(|e| !skip(e));
    let mut seen = 0;
    while let Some(entry) = walk.next() {
        let Ok(entry) = entry else { continue };
        seen += 1;
        if seen > limit {
            cut_short(&format!("{} (files and folders)", ctx.sys.display(&start)), limit);
            break;
        }
        let Ok(below) = entry.path().strip_prefix(root) else { continue };
        let depth = below.iter().count();
        let name = entry.file_name().as_encoded_bytes();
        if entry.file_type().is_dir() {
            if name == b"site-packages" && (part.is_some() || depth <= 7) {
                index.site_packages.push(ctx.sys.display(entry.path()));
            }
            // the last level only matters for project tasks, which are never inside hidden folders
            if part.is_none() && depth == DEPTH - 1 && below.iter().any(|f| f.as_encoded_bytes().starts_with(b".") && f != ".vscode") {
                walk.skip_current_dir();
            }
            continue;
        }
        let is_file = entry.file_type().is_file();
        let env = is_file && depth <= 4 && [&b".env"[..], b".env.local", b".env.production"].contains(&name);
        let pac = is_file && depth <= 3 && (name.len() >= 4 && name[name.len() - 4..].eq_ignore_ascii_case(b".pac") || name.eq_ignore_ascii_case(b"wpad.dat"));
        let tasks = is_file && name == b"tasks.json";
        if !(env || pac || tasks) {
            continue;
        }
        // the folders between the home and the file
        let folders: Vec<String> = below.parent().into_iter().flat_map(|p| p.iter()).map(|c| c.to_string_lossy().into_owned()).collect();
        let hidden = |allowed: &str| folders.iter().any(|f| f.starts_with('.') && f != allowed);
        let path = ctx.sys.display(entry.path());
        if env && !hidden("") {
            index.env_files.push(path);
        } else if pac && !hidden(".config") {
            index.pac_files.push(path);
        } else if tasks && folders.last().is_some_and(|f| f == ".vscode") && !hidden(".vscode") && !folders.iter().any(|f| f == "target") {
            index.vscode_tasks.push(path);
        }
    }
}
