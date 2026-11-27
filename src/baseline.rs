//! Baseline: a JSON snapshot of SUID/SGID files, listening ports and
//! persistence files. A later scan is compared against it and new
//! SUID/SGID files are flagged as `Critical`.

use crate::error::ScanError;
use crate::finding::{Finding, Severity};
use crate::modules::common::shq;
use crate::modules::desktop_session::is_desktop_path;
use crate::modules::firewall::comparable_rule;
use crate::modules::fs_perms::SuidEntry;
use crate::modules::persistence::extra::{is_login_shell, AccountEntry};
use crate::modules::persistence::packages::RETIRED;
use crate::modules::Inventory;
use crate::report::Report;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const MODULE: &str = "baseline";
pub const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ListenerKey {
    pub proto: String,
    pub port: u16,
    pub process: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Baseline {
    pub format_version: u32,
    pub created_at: String,
    pub hostname: String,
    pub kernel: String,
    pub os: String,
    pub scanner_version: String,
    /// Modules that ran when the baseline was created.
    pub modules: Vec<String>,
    pub suid: Vec<SuidEntry>,
    pub listeners: Vec<ListenerKey>,
    pub persistence_files: BTreeMap<String, String>,
    #[serde(default)]
    pub accounts: Vec<AccountEntry>,
    #[serde(default)]
    pub boot: BTreeMap<String, String>,
    /// Signs of a graphical desktop; empty means the machine had none.
    #[serde(default)]
    pub desktop: Option<Vec<String>>,
    #[serde(default)]
    pub ssh_keys: Option<Vec<String>>,
    #[serde(default)]
    pub bluetooth: Option<Vec<String>>,
    #[serde(default)]
    pub peripherals: Option<Vec<String>>,
    #[serde(default)]
    pub addons: Option<Vec<String>>,
    #[serde(default)]
    pub editor_plugins: Option<Vec<String>>,
    #[serde(default)]
    pub local_packages: Option<Vec<String>>,
    #[serde(default)]
    pub firewall_rules: Option<Vec<String>>,
    #[serde(default)]
    pub installed_packages: Option<Vec<String>>,
    #[serde(default)]
    pub package_sums: Option<BTreeMap<String, String>>,
}

/// The parts of a recorded key that identify it: the file and the fingerprint.
fn key_identity(entry: &str) -> (String, String) {
    let words: Vec<&str> = entry.split_whitespace().collect();
    let at = words.iter().position(|w| w.starts_with("SHA256:")).unwrap_or(0);
    // the file name may contain spaces; the key type stands before the fingerprint
    (words[..at.saturating_sub(1)].join(" "), words.get(at).unwrap_or(&"").to_string())
}

/// New SSH keys and new Bluetooth devices: both give someone a way to act as a user.
fn compare_access(base: &Baseline, inv: &Inventory, both: &dyn Fn(&str) -> bool, src: &str, out: &mut Vec<Finding>) {
    if let (true, Some(old), Some(new)) = (both("persistence"), &base.ssh_keys, &inv.ssh_keys) {
        let known: BTreeSet<(String, String)> = old.iter().map(|k| key_identity(k)).collect();
        for key in new.iter().filter(|k| !known.contains(&key_identity(k))) {
            let file = key_identity(key).0;
            out.push(
                Finding::new(Severity::Critical, MODULE, "BASE-SSH-KEY-NEW", format!("New SSH key since the baseline: {file}"))
                    .evidence(format!("{key}\n(compared with {src})"))
                    .description("Whoever holds the private half of this key can log in as this user without a password. Unless you added it, remove the line and treat the machine as broken into.")
                    .verify(format!("ssh-keygen -lf {}", shq(&file)))
                    .verify(format!("ls -l --time-style=full-iso {}", shq(&file))),
            );
        }
    }
    if let (true, Some(old), Some(new)) = (both("fs_perms"), &base.addons, &inv.addons) {
        for addon in new.iter().filter(|a| !old.contains(a)) {
            out.push(
                Finding::new(Severity::Medium, MODULE, "BASE-ADDON-NEW", format!("New browser add-on since the baseline: {}", crate::modules::common::clip(addon.rsplit(": ").next().unwrap_or(addon), 80)))
                    .evidence(format!("{addon}\n(compared with {src})"))
                    .description("Add-ons can read pages and passwords as you type them. Check that you installed this one.")
                    .verify("Open the browser's add-on page and look for it"),
            );
        }
    }
    if let (true, Some(old), Some(new)) = (both("persistence"), &base.editor_plugins, &inv.editor_plugins) {
        for plugin in new.iter().filter(|p| !old.contains(p)) {
            out.push(
                Finding::new(Severity::Low, MODULE, "BASE-EDITOR-NEW", format!("New editor extension since the baseline: {}", crate::modules::common::clip(plugin.rsplit(": ").next().unwrap_or(plugin), 80)))
                    .evidence(format!("{plugin}\n(compared with {src})"))
                    .description("An extension can read your files and run programs. Check that you installed this one.")
                    .verify("Open the editor's extension view and look for it"),
            );
        }
    }
    if let (true, Some(old), Some(new)) = (both("persistence"), &base.local_packages, &inv.local_packages) {
        let name = |p: &str| p.strip_suffix(RETIRED).unwrap_or(p).to_string();
        let known: BTreeSet<String> = old.iter().map(|p| name(p)).collect();
        for entry in new.iter().filter(|p| !known.contains(&name(p))) {
            let package = name(entry);
            // installed in this very version when the baseline was made: only its source is gone
            let installed_then = base.installed_packages.as_ref().zip(inv.installed_packages.as_ref()).is_some_and(|(then, now)| {
                now.iter().filter(|p| p.split(' ').next() == Some(package.as_str())).any(|p| then.contains(p))
            });
            if installed_then {
                continue;
            }
            // apt cannot install what no source offers, so a new package that looks retired is news
            let claims = if entry.ends_with(RETIRED) { " It looks like an old Debian package, but it was not installed like this when the baseline was made." } else { "" };
            out.push(
                Finding::new(Severity::Medium, MODULE, "BASE-LOCAL-PACKAGE", format!("New package from outside the software sources since the baseline: {package}"))
                    .evidence(format!("{package}\n(compared with {src})"))
                    .description(format!("A .deb from a file runs its install scripts as root, and apt never checks or updates it. Check that you installed it.{claims}"))
                    .verify(format!("apt-cache policy {}", shq(&package)))
                    .verify(format!("grep ' install {}:' /var/log/dpkg.log", package)),
            );
        }
    }
    if both("persistence") {
        compare_package_sums(base, inv, src, out);
    }
    // "off" is only recorded when it is certain (as root)
    if both("net_proc") && base.boot.get("firewall").map(String::as_str) == Some("on") && inv.boot.get("firewall").map(String::as_str) == Some("off") {
        out.push(
            Finding::new(Severity::High, MODULE, "BASE-FIREWALL-OFF", "The firewall has been switched off since the baseline")
                .evidence(format!("firewall: on → off\n(compared with {src})"))
                .description("Incoming connections that were refused before are now let through. Switch it on again if you did not switch it off.")
                .verify("nft list ruleset")
                .verify("ufw status verbose"),
        );
    }
    if let (true, Some(old), Some(new)) = (both("net_proc"), &base.firewall_rules, &inv.firewall_rules) {
        let known: BTreeSet<String> = old.iter().map(|r| comparable_rule(r)).collect();
        for (into, severity, title) in [
            (true, Severity::Medium, "New firewall rule(s) that let traffic in since the baseline"),
            (false, Severity::Low, "New firewall rule(s) that accept forwarded or other traffic since the baseline"),
        ] {
            // one line for rules that only differ in a container's address
            let mut shown = BTreeSet::new();
            let fresh: Vec<&str> = new
                .iter()
                .filter(|r| r.starts_with("incoming ") == into)
                .filter(|r| {
                    let form = comparable_rule(r);
                    !known.contains(&form) && shown.insert(form)
                })
                .map(String::as_str)
                .collect();
            if fresh.is_empty() {
                continue;
            }
            out.push(
                Finding::new(severity, MODULE, "BASE-FIREWALL-RULE", title)
                    .evidence(format!("{}\n(compared with {src})", crate::modules::common::clip(&fresh.join("\n"), 1200)))
                    .description("An accept rule opens a way through the firewall. Adding a rule of your own, a VPN, containers or virtual machines do this; check that you know each one. Save a new baseline when they are yours.")
                    .verify("nft list ruleset")
                    .verify("iptables-legacy-save"),
            );
        }
    }
    // boot files built on this machine have no package copy; the baseline remembers them
    if both("integrity") {
        for (key, hash) in inv.boot.iter().filter(|(k, _)| k.starts_with("efi_file ")) {
            if let Some(before) = base.boot.get(key).filter(|b| *b != hash) {
                let path = key.trim_start_matches("efi_file ");
                out.push(
                    Finding::new(Severity::Medium, MODULE, "BASE-EFI-FILE-CHANGED", format!("A boot file built on this computer changed since the baseline: {path}"))
                        .evidence(format!("{path}\nnow sha256 {hash}\npreviously sha256 {before}\n(compared with {src})"))
                        .description("grub-install writes this file again after a GRUB update. If GRUB was not updated, something else changed what starts before the operating system.")
                        .verify(format!("ls -l --time-style=full-iso {}", shq(path)))
                        .verify("grep -E ' (upgrade|install) grub' /var/log/dpkg.log | tail"),
                );
            }
        }
    }
    if let (true, Some(old), Some(new)) = (both("kernel"), &base.peripherals, &inv.peripherals) {
        for device in new.iter().filter(|d| !old.contains(d)) {
            out.push(
                Finding::new(Severity::Medium, MODULE, "BASE-DEVICE-NEW", format!("New hardware since the baseline: {device}"))
                    .evidence(format!("{device}\n(compared with {src})"))
                    .description("A keyboard can type commands and a Thunderbolt device can reach memory. A new dock, keyboard or receiver of your own is normal; anything else is not.")
                    .verify("lsusb; ls /sys/bus/thunderbolt/devices"),
            );
        }
    }
    if let (true, Some(old), Some(new)) = (both("net_proc"), &base.bluetooth, &inv.bluetooth) {
        for device in new.iter().filter(|d| !old.contains(d)) {
            let keyboard = device.ends_with("[keyboard]");
            out.push(
                Finding::new(if keyboard { Severity::High } else { Severity::Medium }, MODULE, "BASE-BLUETOOTH-NEW", format!("New paired Bluetooth device since the baseline: {device}"))
                    .evidence(format!("{device}\n(compared with {src})"))
                    .description("A paired device may connect by itself; a keyboard can type commands. Remove it if it is not yours.")
                    .verify("bluetoothctl devices Paired"),
            );
        }
    }
}

/// Packages whose checksums or scripts changed although their version did not: apt only does that
/// when a source rebuilds a package under the same version. High for packages no source offers.
fn compare_package_sums(base: &Baseline, inv: &Inventory, src: &str, out: &mut Vec<Finding>) {
    let (Some(old), Some(new)) = (&base.package_sums, &inv.package_sums) else { return };
    let (Some(then), Some(now)) = (&base.installed_packages, &inv.installed_packages) else { return };
    let then: BTreeSet<&String> = then.iter().collect();
    // the packages that are installed in the same version as when the baseline was made
    let same: BTreeSet<&str> = now.iter().filter(|p| then.contains(p)).filter_map(|p| p.split(' ').next()).collect();
    let local: BTreeSet<&str> = inv.local_packages.iter().flatten().map(|p| p.strip_suffix(RETIRED).unwrap_or(p)).collect();
    for (key, sum) in new {
        let package = key.split(':').next().unwrap_or(key);
        let Some(before) = old.get(key).filter(|b| *b != sum && same.contains(package)) else { continue };
        let severity = if local.contains(package) { Severity::High } else { Severity::Medium };
        out.push(
            Finding::new(severity, MODULE, "BASE-PACKAGE-REPLACED", format!("A package changed without a new version since the baseline: {package}"))
                .evidence(format!("{key}\nfingerprint now {sum}\nbefore {before}\n(compared with {src})"))
                .description("The list of files or the install scripts that dpkg keeps for this package are different, but the version is the same. Installing another build of the package does this, and so does editing dpkg's records to hide a changed file.")
                .verify(format!("dpkg -V {}", shq(package)))
                .verify(format!("grep -E ' (install|upgrade) {}:' /var/log/dpkg.log", package))
                .verify(format!("sudo apt install --reinstall {}   # restores the source's build, if a source offers it", shq(package))),
        );
    }
}

/// Is this a kind of file that some earlier version did not record yet?
pub fn newly_tracked(path: &str) -> bool {
    // entries starting "/." are folders inside any home folder
    NEWLY_TRACKED.iter().any(|p| if p.starts_with("/.") { path.contains(p) } else { path.starts_with(p) })
        // folders and files that live under different parents
        || ["/pkcs11/modules/", "/p11-kit/modules/", "/pipewire/", "/wireplumber/", "/systemd/linger/", "/EFI/Linux/", "/containers/systemd/", "/kwin/effects/"].iter().any(|p| path.contains(p))
        || path.ends_with("/pkcs11.txt")
        // watched since 0.13: Python startup files, editors, handlers, login and rotation
        // scripts, firewall and proxy settings
        || [".pth", "customize.py", "/.vimrc", "/.gvimrc", "/.exrc", "mimeapps.list", "/.curlrc", "/.wgetrc", "/etc/curlrc", "/etc/wgetrc", ".pac", "/wpad.dat", "/etc/vim/vimrc.local"].iter().any(|e| path.ends_with(e))
        || ["/.vim/", "/.config/nvim/", "/etc/xdg/nvim/"].iter().any(|p| path.contains(p))
        || ["/etc/update-motd.d/", "/etc/logrotate", "/etc/ufw/", "/etc/firewalld/"].iter().any(|p| path.starts_with(p))
        // other files in systemd's folders; units and drop-ins were watched before
        || path.starts_with("/etc/systemd/") && ![".service", ".timer", ".socket", ".path", ".conf"].iter().any(|e| path.ends_with(e))
        // window manager files that live in /etc
        ||["/etc/xdg/openbox/", "/etc/xdg/lxsession/", "/etc/sway/", "/usr/local/share/autostart/"].iter().any(|p| path.starts_with(p))
        || path.contains("-generators/")
        || path.contains("/.git/hooks/")
        // project tasks and a user's own VS Code tasks
        || path.ends_with("/tasks.json")
        // Python startup files as packages or compiled
        || ["customize/__init__.py", "customize.pyc"].iter().any(|e| path.ends_with(e))
        || path.contains("customize.cpython")
        || path == "/etc/kernel/cmdline"
        || path.contains("/NativeMessagingHosts/")
        || path.contains("/native-messaging-hosts/")
        || (path.contains("/systemd/") && path.contains(".d/") && path.ends_with(".conf"))
}

/// Kinds of files that later versions started to track: in a baseline made by an older
/// version they are new to the baseline, not suspicious.
pub const NEWLY_TRACKED: [&str; 76] = [
    "/.local/share/applications/",
    "/.gnupg/",
    "/var/lib/dpkg/diversions",
    "/usr/share/keyrings/",
    "/etc/kernel/",
    "/etc/initramfs/post-update.d/",
    "/etc/greetd/",
    "/etc/sddm.conf.d/",
    "/etc/environment.d/",
    "/usr/local/lib/environment.d/",
    "/.config/environment.d/",
    "/.pam_environment",
    "/.mozilla/native-messaging-hosts/",
    "/etc/default/grub",
    "/etc/grub.d/",
    "/var/lib/flatpak/overrides/",
    "/.local/share/flatpak/overrides/",
    "/.local/share/dbus-1/",
    "/usr/local/share/dbus-1/",
    "/.local/share/xdg-desktop-portal/",
    "/.config/xdg-desktop-portal/",
    "/usr/local/share/xdg-desktop-portal/",
    "/.config/sway/",
    "/.config/swayidle/",
    "/.config/i3/",
    "/.i3/",
    "/.config/openbox/",
    "/.config/lxsession/",
    "/.config/hypr/",
    "/.config/labwc/",
    "/.config/wayfire.ini",
    "/.fluxbox/",
    "/.xscreensaver",
    "/.local/share/kwin/",
    "/.local/share/kglobalaccel/",
    "/.config/xfce4/xinitrc",
    "/.config/gnome-session/",
    "/usr/share/autostart/",
    "/usr/share/gnome/autostart/",
    "/etc/dconf/",
    "/etc/binfmt.d/",
    "/usr/local/lib/binfmt.d/",
    "/etc/initramfs-tools/",
    "/etc/dpkg/",
    "/etc/pip.conf",
    "/etc/xdg/pip/",
    "/etc/npmrc",
    "/usr/local/etc/npmrc",
    "/etc/gitconfig",
    "/etc/nftables.conf",
    "/etc/iptables/",
    "/.local/share/polkit-1/",
    "/.config/polkit-1/",
    "/.xinitrc",
    "/.xsession",
    "/etc/apt/",
    "/etc/X11/",
    "/etc/gdm3/",
    "/etc/sddm",
    "/etc/lightdm/",
    "/etc/NetworkManager/dispatcher.d/",
    "/etc/systemd/system-sleep/",
    "/usr/lib/systemd/system-sleep/",
    "/etc/polkit-1/",
    "/usr/local/share/polkit-1/",
    "/run/polkit-1/",
    "/.config/plasma-workspace/",
    "/.config/autostart-scripts/",
    "/etc/ld.so.conf",
    "/etc/udev/",
    "/etc/modprobe.d/",
    "/etc/modules",
    "/usr/local/share/ca-certificates/",
    "/etc/ssl/private/",
    "/etc/ssh/ssh_host_",
    "/var/spool/cron/atjobs/",
];

pub fn listener_keys(inv: &Inventory) -> Vec<ListenerKey> {
    let set: BTreeSet<ListenerKey> = inv
        .connections
        .iter()
        .filter(|c| c.listening)
        .map(|c| ListenerKey {
            proto: if c.proto.starts_with("tcp") { "tcp".into() } else { "udp".into() },
            port: c.local_port,
            process: c.process.clone().unwrap_or_else(|| "?".into()),
        })
        .collect();
    set.into_iter().collect()
}

impl Baseline {
    pub fn from_report(r: &Report) -> Baseline {
        Baseline {
            format_version: FORMAT_VERSION,
            created_at: r.generated_at.clone(),
            hostname: r.hostname.clone(),
            kernel: r.kernel.clone(),
            os: r.os.clone(),
            scanner_version: r.version.clone(),
            modules: r.modules.clone(),
            suid: r.inventory.suid.clone(),
            listeners: listener_keys(&r.inventory),
            persistence_files: r.inventory.persistence_files.clone(),
            accounts: r.inventory.accounts.clone(),
            boot: r.inventory.boot.clone(),
            desktop: r.inventory.desktop.clone(),
            ssh_keys: r.inventory.ssh_keys.clone(),
            bluetooth: r.inventory.bluetooth.clone(),
            peripherals: r.inventory.peripherals.clone(),
            addons: r.inventory.addons.clone(),
            editor_plugins: r.inventory.editor_plugins.clone(),
            local_packages: r.inventory.local_packages.clone(),
            firewall_rules: r.inventory.firewall_rules.clone(),
            installed_packages: r.inventory.installed_packages.clone(),
            package_sums: r.inventory.package_sums.clone(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), ScanError> {
        let json = serde_json::to_string_pretty(self).map_err(|e| ScanError::Baseline(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| ScanError::io(path, e))
    }

    pub fn load(path: &Path) -> Result<Baseline, ScanError> {
        let text = std::fs::read_to_string(path).map_err(|e| ScanError::io(path, e))?;
        let b: Baseline = serde_json::from_str(&text).map_err(|e| ScanError::Baseline(format!("{}: {e}", path.display())))?;
        if b.format_version > FORMAT_VERSION {
            return Err(ScanError::Baseline(format!("the baseline has a newer version ({}) than the scanner supports", b.format_version)));
        }
        Ok(b)
    }
}

/// Compare the current inventory against the baseline. Only categories scanned
/// both then and now are compared; the others give a note.
pub fn compare(base: &Baseline, inv: &Inventory, modules_now: &[String]) -> (Vec<Finding>, Vec<String>) {
    let mut out = Vec::new();
    let mut notes = Vec::new();
    let both = |m: &str| base.modules.iter().any(|x| x == m) && modules_now.iter().any(|x| x == m);
    let src = format!("baseline from {} ({})", base.created_at, base.hostname);

    if both("fs_perms") {
        let old: BTreeMap<&str, &SuidEntry> = base.suid.iter().map(|e| (e.path.as_str(), e)).collect();
        let new: BTreeMap<&str, &SuidEntry> = inv.suid.iter().map(|e| (e.path.as_str(), e)).collect();
        for (path, e) in &new {
            let ev = format!("{path} mode {} owner {}:{} sha256 {}", e.mode, e.uid, e.gid, e.sha256.as_deref().unwrap_or("?"));
            let verify = vec![
                format!("stat {}", shq(path)),
                format!("dpkg -S {}", shq(path)),
                format!("sha256sum {}", shq(path)),
            ];
            match old.get(path) {
                None => out.push(
                    Finding::new(Severity::Critical, MODULE, "BASE-SUID-NEW", format!("New SUID/SGID file since the baseline: {path}"))
                        .evidence(format!("{ev}\n(missing from {src})"))
                        .description("The file got SUID/SGID after the baseline was created. Unless it comes from a known package installation, this is a strong sign of a root backdoor.")
                        .verify_all(verify),
                ),
                Some(o) if o.sha256.is_some() && e.sha256.is_some() && o.sha256 != e.sha256 => out.push(
                    Finding::new(Severity::Critical, MODULE, "BASE-SUID-CHANGED", format!("SUID/SGID file content changed: {path}"))
                        .evidence(format!("{ev}\npreviously sha256 {}", o.sha256.as_deref().unwrap_or("?")))
                        .description("The content of a SUID/SGID file has changed since the baseline. After a package update that is expected (check with debsums); otherwise the binary may have been replaced.")
                        .verify_all(verify)
                        .verify("grep -E ' (upgrade|install) ' /var/log/dpkg.log | tail -20"),
                ),
                Some(o) if o.mode != e.mode || o.uid != e.uid || o.gid != e.gid => out.push(
                    Finding::new(Severity::High, MODULE, "BASE-SUID-PERMS", format!("SUID/SGID file permissions changed: {path}"))
                        .evidence(format!("now: {} {}:{}  before: {} {}:{}", e.mode, e.uid, e.gid, o.mode, o.uid, o.gid))
                        .description("Permissions or owner have changed since the baseline.")
                        .verify_all(verify),
                ),
                _ => {}
            }
        }
        for path in old.keys().filter(|p| !new.contains_key(*p)) {
            out.push(
                Finding::new(Severity::Low, MODULE, "BASE-SUID-REMOVED", format!("SUID/SGID file gone since the baseline: {path}"))
                    .evidence(format!("{path} was in {src}"))
                    .description("The file was removed or lost SUID/SGID – usually an uninstall.")
                    .verify(format!("ls -l {}", shq(path))),
            );
        }
    } else {
        notes.push("SUID/SGID was not compared with the baseline (fs_perms did not run in both scans)".into());
    }

    if both("net_proc") {
        let old: BTreeSet<(String, u16)> = base.listeners.iter().map(|l| (l.proto.clone(), l.port)).collect();
        // Programs such as KDE Connect, Tailscale or the NFS client pick a random (ephemeral)
        // port at every start. A random port of a program that already listened at baseline
        // time is not news; any other new port is, grouped per program.
        let known: BTreeSet<(String, String)> = base.listeners.iter().map(|l| (l.proto.clone(), l.process.clone())).collect();
        let mut fresh: BTreeMap<String, Vec<ListenerKey>> = BTreeMap::new();
        for l in listener_keys(inv) {
            if old.contains(&(l.proto.clone(), l.port)) {
                continue;
            }
            if l.port >= 32768 && known.contains(&(l.proto.clone(), l.process.clone())) {
                continue;
            }
            fresh.entry(l.process.clone()).or_default().push(l);
        }
        for (process, list) in fresh {
            let fixed = list.iter().any(|l| l.port < 32768);
            let ports: Vec<String> = list.iter().map(|l| format!("{}/{}", l.proto, l.port)).collect();
            out.push(
                Finding::new(
                    if fixed { Severity::High } else { Severity::Medium },
                    MODULE,
                    "BASE-LISTEN-NEW",
                    format!("New listening port(s) since the baseline: {} ({process})", ports.join(", ")),
                )
                .evidence(format!("{} owned by {process}\n(missing from {src})", ports.join(", ")))
                .description(if fixed {
                    "A service listens on a port that did not exist when the baseline was created."
                } else {
                    "A program that did not listen at baseline time now listens on random ports. Check that you know it."
                })
                .verify(format!("ss -tulpn | grep '{process}'")),
            );
        }
    } else {
        notes.push("Listening ports were not compared with the baseline (net_proc did not run in both scans)".into());
    }

    // Desktop files are recorded by desktop_session (by persistence in older versions).
    let now = |m: &str| modules_now.iter().any(|x| x == m);
    let desktop = now("desktop_session") && base.modules.iter().any(|m| m == "desktop_session" || m == "persistence");
    let covered = |path: &str| if is_desktop_path(path) { desktop } else { both("persistence") };
    if both("persistence") || desktop {
        for (path, hash) in inv.persistence_files.iter().filter(|(p, _)| covered(p)) {
            match base.persistence_files.get(path) {
                None => out.push(
                    Finding::new(Severity::High, MODULE, "BASE-PERSIST-NEW", format!("New persistence file since the baseline: {path}"))
                        .evidence(format!("{path} sha256 {hash}\n(missing from {src})"))
                        .description("A file that controls automatic execution (systemd, cron, ssh, pam, shell files …) has appeared.")
                        .verify(format!("cat {}", shq(path)))
                        .verify(format!("dpkg -S {}", shq(path))),
                ),
                Some(old) if old != hash => out.push(
                    Finding::new(Severity::High, MODULE, "BASE-PERSIST-CHANGED", format!("Persistence file changed since the baseline: {path}"))
                        .evidence(format!("{path}\nnow sha256 {hash}\npreviously sha256 {old}"))
                        .description("The file controls automatic execution or login and has changed. Check the change.")
                        .verify(format!("cat {}", shq(path)))
                        .verify(format!("ls -l --time-style=full-iso {}", shq(path))),
                ),
                _ => {}
            }
        }
        for path in base.persistence_files.keys().filter(|p| covered(p) && !inv.persistence_files.contains_key(*p)) {
            out.push(
                Finding::new(Severity::Low, MODULE, "BASE-PERSIST-REMOVED", format!("Persistence file gone since the baseline: {path}"))
                    .evidence(format!("{path} was in {src}"))
                    .description("The file has been removed since the baseline.")
                    .verify(format!("ls -l {}", shq(path))),
            );
        }
    } else {
        notes.push("Persistence files were not compared with the baseline (persistence did not run in both scans)".into());
    }
    if both("persistence") && !base.accounts.is_empty() && !inv.accounts.is_empty() {
        compare_accounts(&base.accounts, &inv.accounts, &src, &mut out);
    }

    // a user's own desktop settings change in daily use; system files and everything else do not
    for f in out.iter_mut().filter(|f| f.rule == "BASE-PERSIST-NEW" || f.rule == "BASE-PERSIST-CHANGED") {
        let path = f.evidence.lines().next().unwrap_or("").split(" sha256 ").next().unwrap_or("");
        let own = path.starts_with("/home/") || path.starts_with("/root/");
        if is_desktop_path(path) && own {
            f.severity = Severity::Medium;
            f.description = "A file that starts things in a desktop session is new or changed. Adding an autostart entry or changing a desktop setting does this; check that it was you.".into();
        } else if own && (path.ends_with("mimeapps.list") || path.ends_with("/.vimrc") || path.contains("/.vim/") || path.contains("/.config/nvim/")) {
            f.severity = Severity::Medium;
            f.description = "Your editor's settings or the list of programs that open your files is new or changed. Using the editor or choosing a default program does this; check that it was you.".into();
        } else if path.ends_with("/tasks.json") && own {
            f.severity = Severity::Medium;
            f.description = "A task that runs when a folder is opened is new or changed. Check the command it runs.".into();
        } else if path.ends_with(".pth") && own {
            f.severity = Severity::Medium;
            f.description = "A Python path file in your home folder is new or changed. Installing or removing a Python package does this; check the folders and lines it names.".into();
        } else if path.ends_with("/pkcs11.txt") && own {
            // browsers and mail programs write these themselves; PERS-KEY-MODULE judges the libraries
            f.severity = Severity::Medium;
            f.description = "The list of key libraries of a browser or mail program is new or changed. The program writes it itself; check that the library= lines name nothing you do not know.".into();
        }
    }
    compare_access(base, inv, &both, &src, &mut out);
    if both("desktop_session") {
        compare_desktop(base.desktop.as_deref(), inv.desktop.as_deref(), &src, &mut out);
    }

    if both("kernel") && !base.boot.is_empty() && !inv.boot.is_empty() {
        compare_boot(&base.boot, &inv.boot, &src, &mut out);
    }

    // A baseline made by an older version did not track every kind of file yet (the library
    // path files /etc/ld.so.conf* were added later). Those are "newly tracked", not suspicious.
    if base.scanner_version != env!("CARGO_PKG_VERSION") {
        for f in out.iter_mut() {
            // the evidence of a new file starts "<path> sha256 <hash>"
            let first = f.evidence.lines().next().unwrap_or("");
            let path = first.rsplit_once(" sha256 ").map(|(p, _)| p).unwrap_or(first);
            if f.rule == "BASE-PERSIST-NEW" && newly_tracked(path) {
                f.severity = Severity::Low;
                f.description = "This kind of file was not tracked yet when the baseline was made by an older scanner version, so it is new to the baseline, not necessarily new on the machine. It is added to the baseline automatically after a clean scan as root.".into();
            }
        }
    }
    (out, notes)
}

/// A graphical desktop on a machine that had none, or a new program that shows the screen to
/// others.
fn compare_desktop(old: Option<&[String]>, new: Option<&[String]>, src: &str, out: &mut Vec<Finding>) {
    let (Some(old), Some(new)) = (old, new) else { return };
    let fresh: Vec<&str> = new
        .iter()
        .filter(|s| !old.contains(s) && (old.is_empty() || ["x11vnc", "Xvnc", "Xvfb"].iter().any(|r| s.ends_with(r))))
        .map(String::as_str)
        .collect();
    if fresh.is_empty() {
        return;
    }
    let (severity, title) = if old.is_empty() {
        (Severity::High, "A graphical desktop appeared on a machine that had none")
    } else {
        (Severity::Medium, "A virtual or remote screen is running that was not there before")
    };
    out.push(
        Finding::new(severity, MODULE, "BASE-DESKTOP-NEW", title)
            .evidence(format!("{}\n(compared with {src})", fresh.join("\n")))
            .description("Servers do not grow a desktop by themselves. Someone installed or started graphical software, which can be a way to control the machine remotely.")
            .verify("grep ' install ' /var/log/dpkg.log | tail -30")
            .verify("ps -e -o pid,user,lstart,cmd | grep -iE 'xorg|vnc|wayland|xvfb'"),
    );
}

/// Secure Boot, lockdown and the firmware's boot entries.
fn compare_boot(old: &BTreeMap<String, String>, new: &BTreeMap<String, String>, src: &str, out: &mut Vec<Finding>) {
    let mut push = |severity: Severity, rule: &str, title: String, evidence: String| {
        out.push(
            Finding::new(severity, MODULE, rule, title)
                .evidence(format!("{evidence}\n(compared with {src})"))
                .description("How the machine starts has changed since the baseline. Firmware updates, new operating systems and changes in the firmware setup do this; a boot-level attack does too.")
                .verify("efibootmgr -v")
                .verify("cat /sys/kernel/security/lockdown; mokutil --sb-state"),
        );
    };
    let get = |m: &BTreeMap<String, String>, k: &str| m.get(k).cloned().unwrap_or_default();
    if get(old, "secure_boot") == "on" && get(new, "secure_boot") == "off" {
        push(Severity::High, "BASE-SECUREBOOT-OFF", "Secure Boot has been switched off since the baseline".into(), "secure_boot: on → off".into());
    }
    if ["integrity", "confidentiality"].contains(&get(old, "lockdown").as_str()) && get(new, "lockdown") == "none" {
        push(Severity::High, "BASE-LOCKDOWN-OFF", "The kernel lockdown is gone since the baseline".into(), format!("lockdown: {} → none", get(old, "lockdown")));
    }
    for (key, name) in [("apparmor", "AppArmor"), ("selinux", "SELinux")] {
        if ["on", "enforcing"].contains(&get(old, key).as_str()) && ["off", "permissive"].contains(&get(new, key).as_str()) {
            push(Severity::High, "BASE-APPARMOR-OFF", format!("{name} stopped protecting since the baseline"), format!("{key}: {} → {}", get(old, key), get(new, key)));
        }
    }
    for (key, value) in new.iter().filter(|(k, _)| k.starts_with("boot_entry ")) {
        let name = key.trim_start_matches("boot_entry ");
        match old.get(key) {
            None => push(Severity::Medium, "BASE-BOOT-ENTRY-NEW", format!("New firmware boot entry since the baseline: Boot{name}"), format!("Boot{name}: {value}")),
            Some(before) if before != value => push(Severity::Medium, "BASE-BOOT-ENTRY-CHANGED", format!("Firmware boot entry changed since the baseline: Boot{name}"), format!("Boot{name}\nnow: {value}\nbefore: {before}")),
            _ => {}
        }
    }
    if !get(old, "boot_order").is_empty() && !get(new, "boot_order").is_empty() && get(old, "boot_order") != get(new, "boot_order") {
        push(Severity::Low, "BASE-BOOT-ORDER", "The firmware boot order changed since the baseline".into(), format!("{} → {}", get(old, "boot_order"), get(new, "boot_order")));
    }
}

fn describe_account(a: &AccountEntry) -> String {
    format!(
        "{}: UID {} shell {} password {} groups [{}]",
        a.name,
        a.uid,
        a.shell,
        match a.password {
            Some(true) => "yes",
            Some(false) => "locked",
            None => "?",
        },
        a.groups.join(", ")
    )
}

/// New, removed and changed accounts since the baseline.
fn compare_accounts(old: &[AccountEntry], new: &[AccountEntry], src: &str, out: &mut Vec<Finding>) {
    let finding = |sev, rule: &str, title: String, evidence: String, text: &str, name: &str| {
        Finding::new(sev, MODULE, rule, title)
            .evidence(format!("{evidence}\n(compared with {src})"))
            .description(text)
            .verify(format!("getent passwd {}; id {}", shq(name), shq(name)))
            .verify("grep -E 'useradd|usermod|groupadd|gpasswd|chsh|passwd' /var/log/auth.log; journalctl -t useradd -t usermod -t groupadd")
    };
    for a in new {
        let Some(o) = old.iter().find(|o| o.name == a.name) else {
            let system = a.uid < 1000 && a.uid != 0 && !is_login_shell(&a.shell) && a.groups.is_empty() && a.password != Some(true);
            let sev = if a.uid == 0 { Severity::Critical } else if system { Severity::Low } else { Severity::High };
            out.push(finding(sev, "BASE-ACCOUNT-NEW", format!("New account since the baseline: {}", a.name), describe_account(a), if system { "A new system account without login – normally created by installing a package." } else { "An account that can log in or has special rights was added. Make sure you created it." }, &a.name));
            continue;
        };
        if o.uid != a.uid {
            let sev = if a.uid == 0 { Severity::Critical } else { Severity::High };
            out.push(finding(sev, "BASE-ACCOUNT-UID", format!("User id changed: {}", a.name), format!("UID {} → {}", o.uid, a.uid), "Changing an account's user id (especially to 0, root) is how hidden root accounts are made.", &a.name));
        }
        if o.shell != a.shell {
            let opened = !is_login_shell(&o.shell) && is_login_shell(&a.shell);
            let sev = if opened && a.uid < 1000 { Severity::Critical } else if opened { Severity::High } else { Severity::Low };
            out.push(finding(sev, "BASE-ACCOUNT-SHELL", format!("Login shell changed: {}", a.name), format!("{} → {}", o.shell, a.shell), if opened { "An account that could not log in now has a shell – a common way to turn a service account into a backdoor." } else { "The shell of the account changed." }, &a.name));
        }
        let gained: Vec<&String> = a.groups.iter().filter(|g| !o.groups.contains(g)).collect();
        if !gained.is_empty() {
            let list: Vec<&str> = gained.iter().map(|s| s.as_str()).collect();
            out.push(finding(Severity::High, "BASE-ACCOUNT-GROUP", format!("Account gained powerful group(s): {}", a.name), format!("{} joined {}", a.name, list.join(", ")), "Membership in these groups gives root or near-root power.", &a.name));
        }
        if a.uid != 0 && a.uid < 1000 && o.password == Some(false) && a.password == Some(true) {
            out.push(finding(Severity::High, "BASE-ACCOUNT-PASSWORD", format!("System account got a password: {}", a.name), describe_account(a), "A service account that was locked can now log in with a password.", &a.name));
        }
    }
    for o in old.iter().filter(|o| !new.iter().any(|a| a.name == o.name)) {
        out.push(finding(Severity::Low, "BASE-ACCOUNT-REMOVED", format!("Account removed since the baseline: {}", o.name), describe_account(o), "The account no longer exists.", &o.name));
    }
}
