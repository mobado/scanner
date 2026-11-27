//! One walk through each home folder, shared by the checks that look for files anywhere in it:
//! Python environments, VS Code folder tasks, `.env` files and proxy auto-config files. Large
//! home folders are walked once per scan instead of once per check.

use super::common::cut_short;
use super::ScanCtx;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;
use walkdir::WalkDir;

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

/// Folders none of the checks look in: caches, downloaded libraries, games and containers.
const SKIPPED: [&str; 8] = ["node_modules", ".git", ".cache", "Trash", "Steam", ".var", "flatpak", "containers"];
const DEPTH: usize = 8;
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
    let mut walk = WalkDir::new(&root)
        .max_depth(DEPTH)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| e.depth() == 0 || !(e.file_type().is_dir() && SKIPPED.iter().any(|s| e.file_name() == *s)));
    let mut index = HomeIndex::default();
    let mut seen = 0;
    while let Some(entry) = walk.next() {
        let Ok(entry) = entry else { continue };
        seen += 1;
        if seen > LIMIT {
            cut_short(&format!("{home} (files and folders)"), LIMIT);
            break;
        }
        let depth = entry.depth();
        let name = entry.file_name().as_encoded_bytes();
        if entry.file_type().is_dir() {
            if name == b"site-packages" && depth <= 7 {
                index.site_packages.push(ctx.sys.display(entry.path()));
            }
            // the last level only matters for project tasks, which are never inside hidden folders
            if depth == DEPTH - 1 {
                let hidden = entry.path().strip_prefix(&root).is_ok_and(|below| below.iter().any(|f| f.as_encoded_bytes().starts_with(b".") && f != ".vscode"));
                if hidden {
                    walk.skip_current_dir();
                }
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
        let Ok(below) = entry.path().strip_prefix(&root) else { continue };
        let folders: Vec<String> = below.parent().into_iter().flat_map(|p| p.iter()).map(|c| c.to_string_lossy().into_owned()).collect();
        let hidden = |allowed: &str| folders.iter().any(|f| f.starts_with('.') && f != allowed);
        let path = ctx.sys.display(entry.path());
        if env && !hidden("") {
            index.env_files.push(path);
        } else if pac && !hidden(".config") {
            index.pac_files.push(path);
        } else if tasks
            && folders.last().is_some_and(|f| f == ".vscode")
            && !hidden(".vscode")
            && !folders.iter().any(|f| f == "target")
            && !folders.windows(2).any(|w| w[0] == ".vscode" && w[1] == "extensions")
        {
            index.vscode_tasks.push(path);
        }
    }
    for list in [&mut index.site_packages, &mut index.vscode_tasks, &mut index.env_files, &mut index.pac_files] {
        list.sort();
    }
    let index = Rc::new(index);
    WALKED.with(|w| w.borrow_mut().insert(root, index.clone()));
    index
}
