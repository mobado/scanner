//! Applications outside apt and ways to see the screen: remote-desktop programs, Flatpak
//! permissions and sources, Snap packages and AppImages.

use super::MODULE;
use crate::finding::{Finding, Severity};
use crate::modules::common::{clip, shq};
use crate::modules::homefiles::download_folders;
use crate::modules::persistence::{parse_unit, record};
use crate::modules::{Collector, ScanCtx};
use std::io::Read;
use std::os::unix::fs::MetadataExt;

type Homes = [(String, u32, String)];

// ---------------------------------------------------------------- remote screens

/// Programs that let someone elsewhere see or control the screen. Runs on any machine.
pub(super) fn check_remote_screens(ctx: &ScanCtx, col: &mut Collector) {
    let mut seen = std::collections::BTreeSet::new();
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread()) {
        let Some(name) = p.candidate_names().into_iter().find(|n| ctx.cfg.remote_desktop_programs.contains(n)) else { continue };
        if !seen.insert(name.clone()) {
            continue;
        }
        let exe = p.exe_path().unwrap_or("");
        let system = ["/usr/", "/opt/", "/snap/", "/app/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
        col.push(
            Finding::new(if system { Severity::Medium } else { Severity::High }, MODULE, "DESK-REMOTE-SCREEN", format!("A remote desktop program is running: {name}"))
                .evidence(format!("PID {} UID {} exe={}\ncmdline=\"{}\"", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 300)))
                .description("It lets another computer see, and usually control, this one – under Wayland too. Support tools like AnyDesk are also what scammers ask people to install. Remove it or switch it off if you do not use it.")
                .verify(format!("ps -o pid,user,lstart,cmd -p {}", p.pid))
                .verify(format!("ss -tunap | grep 'pid={},'", p.pid)),
        );
    }
}

fn check_krfb(ctx: &ScanCtx, col: &mut Collector, home: &str) {
    let path = format!("{home}/.config/krfbrc");
    let Ok(text) = ctx.sys.read_string(&path) else { return };
    if parse_unit(&text).iter().any(|(_, k, v)| k == "allowUnattendedAccess" && v == "true") {
        col.push(
            Finding::new(Severity::Medium, MODULE, "DESK-REMOTE-SCREEN", format!("KDE screen sharing allows access without asking: {path}"))
                .evidence(format!("{path}\nallowUnattendedAccess=true"))
                .description("Someone with the password can see and control the screen while nobody is there. Switch it off in Krfb if you did not set this up.")
                .verify(format!("cat {}", shq(&path))),
        );
    }
}

// ---------------------------------------------------------------- Flatpak

/// What a Flatpak permission file grants beyond the sandbox: (severity, permission).
pub fn flatpak_grants(text: &str) -> Vec<(Severity, String)> {
    let mut out = Vec::new();
    for (section, key, value) in parse_unit(text) {
        if section.ends_with("Bus Policy") {
            // talking to org.freedesktop.Flatpak means running commands outside the sandbox
            if key == "org.freedesktop.Flatpak" && ["talk", "own"].contains(&value.as_str()) {
                out.push((Severity::High, format!("may run programs outside the sandbox ({key}={value})")));
            }
            continue;
        }
        if section != "Context" {
            continue;
        }
        for item in value.split(';').map(str::trim).filter(|v| !v.is_empty() && !v.starts_with('!')) {
            let read_only = item.ends_with(":ro");
            let grant = match (key.as_str(), item.split(':').next().unwrap_or(item)) {
                ("filesystems", "host" | "home" | "~") => Some((if read_only { Severity::Low } else { Severity::Medium }, "files")),
                ("filesystems", p) if p.contains(".config/autostart") || p.contains(".ssh") => Some((Severity::High, "startup or key files")),
                ("filesystems", "host-etc" | "host-os") => Some((Severity::Low, "system files")),
                ("sockets", "session-bus" | "system-bus") => Some((Severity::Medium, "the whole message bus")),
                ("sockets", "x11") => Some((Severity::Low, "the X11 display (can read the keyboard there)")),
                ("sockets", "ssh-auth" | "gpg-agent") => Some((Severity::Low, "your keys")),
                ("devices", "all") => Some((Severity::Low, "every device")),
                _ => None,
            };
            if let Some((severity, what)) = grant {
                out.push((severity, format!("{key}={item} ({what})")));
            }
        }
    }
    out
}

fn check_flatpak(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let mut installs = vec!["/var/lib/flatpak".to_string()];
    installs.extend(homes.iter().map(|(_, _, h)| format!("{h}/.local/share/flatpak")));
    let mut apps = Vec::new();
    for base in installs {
        // permissions someone added on this machine
        for name in ctx.sys.dir_names(format!("{base}/overrides")) {
            let path = format!("{base}/overrides/{name}");
            let Ok(text) = ctx.sys.read_string(&path) else { continue };
            record(ctx, col, &path);
            let grants = flatpak_grants(&text);
            let Some(severity) = grants.iter().map(|g| g.0).max() else { continue };
            let who = if name == "global" { "every Flatpak app".to_string() } else { name.clone() };
            col.push(
                Finding::new(severity, MODULE, "DESK-FLATPAK-OVERRIDE", format!("Extra Flatpak permissions for {who}: {path}"))
                    .evidence(format!("{path}\n{}", grants.into_iter().map(|g| g.1).collect::<Vec<_>>().join("\n")))
                    .description("An override gives an app more than it asked for, past its sandbox. Flatseal and 'flatpak override' do this; check that you meant it.")
                    .verify(format!("cat {}", shq(&path)))
                    .verify("flatpak override --show"),
            );
        }
        for app in ctx.sys.dir_names(format!("{base}/app")) {
            let Ok(text) = ctx.sys.read_string(format!("{base}/app/{app}/current/active/metadata")) else { continue };
            let broad: Vec<String> = flatpak_grants(&text).into_iter().filter(|g| g.0 >= Severity::Medium).map(|g| g.1).collect();
            if !broad.is_empty() {
                apps.push(format!("{app}: {}", broad.join(", ")));
            }
        }
        let config = format!("{base}/repo/config");
        if let Ok(text) = ctx.sys.read_string(&config) {
            let mut remotes: std::collections::BTreeMap<String, (String, bool)> = Default::default();
            for (section, key, value) in parse_unit(&text) {
                if let Some(name) = section.strip_prefix("remote ") {
                    let entry = remotes.entry(name.trim_matches('"').to_string()).or_insert((String::new(), true));
                    if key == "url" {
                        entry.0 = value;
                    } else if key == "gpg-verify" {
                        entry.1 = value != "false";
                    }
                }
            }
            for (name, (url, verified)) in remotes {
                let known = ["https://dl.flathub.org/", "https://flathub.org/", "https://registry.fedoraproject.org/", "oci+https://registry.fedoraproject.org"].iter().any(|k| url.starts_with(k));
                if known && verified {
                    continue;
                }
                col.push(
                    Finding::new(if verified { Severity::Low } else { Severity::Medium }, MODULE, "DESK-FLATPAK-REMOTE", format!("Flatpak source {}: {name}", if verified { "outside Flathub" } else { "without signature check" }))
                        .evidence(format!("{config}\n{name} {url}{}", if verified { "" } else { " (gpg-verify=false)" }))
                        .description("Apps and updates from this source run as you. Check that you added it yourself.")
                        .verify("flatpak remotes --show-details"),
                );
            }
        }
    }
    if !apps.is_empty() {
        apps.sort();
        col.push(
            Finding::new(Severity::Low, MODULE, "DESK-FLATPAK-ACCESS", "Flatpak apps with wide access")
                .evidence(clip(&apps.join("\n"), 1500))
                .description("These apps can reach much of your files or run things outside the sandbox. Many popular apps ask for this; know which ones do.")
                .verify("flatpak list --app")
                .verify("flatpak info --show-permissions <app>"),
        );
    }
}

// ---------------------------------------------------------------- Snap

fn check_snaps(ctx: &ScanCtx, col: &mut Collector) {
    let mut classic = Vec::new();
    let mut odd = Vec::new();
    for name in ctx.sys.dir_names("/snap").into_iter().filter(|n| n != "bin") {
        let current = format!("/snap/{name}/current");
        let Ok(yaml) = ctx.sys.read_string(format!("{current}/meta/snap.yaml")) else { continue };
        // revisions "x1", "x2" … are installed from a local file, without the store's signature
        let local = ctx.sys.read_link(&current).map(|t| crate::procinfo::basename(&t).starts_with('x')).unwrap_or(false);
        let confinement = yaml.lines().find_map(|l| l.strip_prefix("confinement:")).map(str::trim).unwrap_or("strict");
        if local || confinement == "devmode" {
            odd.push(format!("{name}: {}", if local { "installed from a local file (unsigned)" } else { "developer mode, no sandbox" }));
        } else if confinement == "classic" {
            classic.push(name);
        }
    }
    if !odd.is_empty() {
        col.push(
            Finding::new(Severity::Medium, MODULE, "DESK-SNAP", "Snap packages without the store's protection")
                .evidence(odd.join("\n"))
                .description("These snaps were not checked by the store or run without a sandbox. Developers do this; check that you installed them.")
                .verify("snap list"),
        );
    }
    if !classic.is_empty() {
        col.push(
            Finding::new(Severity::Low, MODULE, "DESK-SNAP", "Snap packages with full access (classic)")
                .evidence(classic.join("\n"))
                .description("Classic snaps run like normal programs, with access to everything you have. Editors and developer tools are often classic.")
                .verify("snap list"),
        );
    }
}

// ---------------------------------------------------------------- AppImage

/// Does the file start like an AppImage (an ELF with "AI" and its type at byte 8)?
fn is_appimage(ctx: &ScanCtx, path: &str) -> bool {
    let mut head = [0u8; 11];
    std::fs::File::open(ctx.sys.path(path)).and_then(|mut f| f.read_exact(&mut head)).is_ok() && head.starts_with(b"\x7fELF") && head[8] == b'A' && head[9] == b'I' && (head[10] == 1 || head[10] == 2)
}

fn check_appimages(ctx: &ScanCtx, col: &mut Collector, user: &str, home: &str) {
    let mut folders = download_folders(ctx, home);
    folders.extend(["Applications", "AppImages", ".local/bin", "Desktop", "Skrivbord"].iter().map(|d| format!("{home}/{d}")));
    folders.insert(home.to_string());
    let mut found = Vec::new();
    for folder in folders {
        for name in ctx.sys.dir_names(&folder).into_iter().take(2000) {
            let path = format!("{folder}/{name}");
            let Ok(meta) = std::fs::symlink_metadata(ctx.sys.path(&path)) else { continue };
            if meta.is_file() && meta.mode() & 0o111 != 0 && is_appimage(ctx, &path) {
                found.push(format!("{path} ({} bytes)", meta.size()));
            }
        }
    }
    if found.is_empty() {
        return;
    }
    found.sort();
    let first = found[0].split(" (").next().unwrap_or("").to_string();
    col.push(
        Finding::new(Severity::Low, MODULE, "DESK-APPIMAGE", format!("AppImage programs of {user}"))
            .evidence(clip(&found.join("\n"), 1500))
            .description("AppImages are programs that apt neither installed nor updates, and nothing checks who made them. Keep the ones you fetched from their maker, and update them yourself.")
            .verify(format!("sha256sum {}", shq(&first))),
    );
}

pub(super) fn check_apps(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    check_flatpak(ctx, col, homes);
    check_snaps(ctx, col);
    for (user, _, home) in homes {
        check_krfb(ctx, col, home);
        check_appimages(ctx, col, user, home);
    }
}
