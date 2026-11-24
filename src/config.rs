//! Configurable whitelist (TOML or JSON) with known Debian 13 defaults.
//!
//! `scanner --print-config > /etc/scanner/whitelist.toml` prints the defaults as a
//! starting point; then load it with `--config /etc/scanner/whitelist.toml`.

use crate::error::ScanError;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    /// Expected listening ports, like "tcp/22" or "udp/68".
    pub allowed_listen_ports: Vec<String>,
    /// Also report listening ports bound only to loopback (127.0.0.1/::1).
    pub report_loopback_listeners: bool,
    /// Remote ports often used by backdoors and reverse shells.
    pub suspicious_remote_ports: Vec<u16>,
    /// Directories where executables do not belong.
    pub temp_dirs: Vec<String>,
    /// Shells and network tools that are suspicious when they hold network sockets.
    pub shell_names: Vec<String>,
    pub script_interpreters: Vec<String>,
    /// Known malware names (e.g. crypto miners).
    pub known_malware_names: Vec<String>,
    /// Process names that legitimately rewrite their argv[0] (sshd: user@pts/0 etc.).
    pub allowed_argv0_mismatch: Vec<String>,
    /// Known kernel thread name prefixes.
    pub kernel_thread_prefixes: Vec<String>,
    /// Known SUID/SGID files (full path; '*' matches one path segment).
    pub allowed_suid: Vec<String>,
    /// Where the file system walk starts.
    pub fs_roots: Vec<String>,
    /// Paths that are never walked (virtual file systems, snapshots etc.).
    pub fs_exclude_paths: Vec<String>,
    /// Known locally created systemd units (file name, e.g. "myapp.service").
    pub allowed_systemd_units: Vec<String>,
    /// Known cron files (file names in /etc/cron.d and /etc/cron.*), or "crontabs/<user>".
    pub allowed_cron_files: Vec<String>,
    /// Known SSH key comments. Empty list = report all keys as information.
    pub allowed_ssh_key_comments: Vec<String>,
    /// Known PAM modules (without .so).
    pub allowed_pam_modules: Vec<String>,
    /// Known harmless LD_PRELOAD libraries (substring of the path), e.g. Firefox sandbox and Flatpak.
    pub allowed_ld_preload: Vec<String>,
    /// Timeout in seconds for external tools.
    pub external_tool_timeout_secs: u64,
    /// Ignore findings with these rule ids entirely.
    pub ignore_rules: Vec<String>,
    /// Ignore findings whose evidence contains any of these snippets.
    pub ignore_evidence_containing: Vec<String>,
}

fn s(list: &[&str]) -> Vec<String> {
    list.iter().map(|x| x.to_string()).collect()
}

impl Default for Config {
    fn default() -> Self {
        Config {
            allowed_listen_ports: s(&[
                "tcp/22", "udp/68", "udp/546", "udp/123", "udp/5353", "tcp/631", "udp/631",
                "udp/323", "tcp/25", "tcp/53", "udp/53", "tcp/5355", "udp/5355",
            ]),
            report_loopback_listeners: false,
            suspicious_remote_ports: vec![
                1337, 31337, 4444, 4445, 5555, 6666, 6667, 6668, 6669, 7777, 9001, 12345, 54321,
            ],
            temp_dirs: s(&["/tmp", "/var/tmp", "/dev/shm", "/run/shm", "/run/user", "/run/lock"]),
            shell_names: s(&[
                "sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "busybox", "nc",
                "ncat", "netcat", "nc.openbsd", "nc.traditional", "socat", "telnet", "rbash",
            ]),
            script_interpreters: s(&[
                "python", "python2", "python3", "perl", "ruby", "php", "lua", "node", "nodejs",
                "awk", "gawk", "mawk", "tclsh", "expect", "openssl",
            ]),
            known_malware_names: s(&[
                "xmrig", "kinsing", "kdevtmpfsi", "kthreaddi", "watchbog", "xmr-stak", "minerd",
                "cpuminer", "dbused", "kerberods", "tsunami",
                "mirai", "gafgyt", "kaiten",
            ]),
            allowed_argv0_mismatch: s(&[
                "sshd", "sshd-session", "sshd-auth", "postgres", "postmaster", "nginx", "apache2",
                "httpd", "php-fpm", "php-fpm8.4", "systemd", "(sd-pam)", "sd-pam", "dovecot",
                "postfix", "master", "qmgr", "pickup", "exim4", "chrome", "chromium", "firefox",
                "firefox-esr", "electron", "code", "Xorg", "Xwayland", "gnome-shell", "plasmashell",
                "kdeinit5", "kdeinit6", "mysqld", "mariadbd", "redis-server", "uwsgi", "gunicorn",
                "unicorn", "puma", "java", "dbus-daemon", "dbus-broker", "dbus-broker-launch",
                "login", "agetty", "gdm-session-worker", "lightdm", "sddm-helper", "cron",
                "containerd-shim", "runc", "spamd", "amavisd", "clamd", "fail2ban-server",
                "python3", "perl", "ruby", "node", "bwrap", "flatpak", "steam", "wine",
                "wineserver", "pipewire", "wireplumber", "snapd", "rsyslogd", "polkitd",
                "systemd-executor",
            ]),
            kernel_thread_prefixes: s(&[
                "kthreadd", "kworker", "ksoftirqd", "migration", "rcu_", "rcub", "rcuc", "rcuo",
                "rcuog", "rcuop", "cpuhp", "idle_inject", "kdevtmpfs", "netns", "kauditd",
                "khungtaskd", "oom_reaper", "writeback", "kcompactd", "ksmd", "khugepaged",
                "kintegrityd", "kblockd", "blkcg_punt_bio", "tpm_dev_wq", "ata_sff", "md",
                "edac-poller", "devfreq_wq", "watchdogd", "kswapd", "ecryptfs", "kthrotld",
                "irq/", "scsi_", "acpi_thermal_pm", "ipv6_addrconf", "kstrp", "zswap",
                "charger_manager", "jbd2/", "ext4-rsv-conver", "card", "nvme", "xfs", "btrfs",
                "dm", "kverityd", "cryptd", "ttm", "gfx", "i915", "amdgpu", "nv_", "psimon",
                "hwrng", "khvcd", "pool_workqueue_release", "kmpath", "kaluad", "mld",
                "inet_frag_wq", "krfcommd", "napi/", "kipmi", "iprt", "spl_", "z_", "loop",
                "mm_percpu_wq", "sugov", "kdmflush", "kcryptd", "dmcrypt_write", "kstrp",
                "ext4", "usb-storage", "uas", "hci", "cfg80211", "iwlwifi", "ath", "mt76",
                "rtw", "brcmf", "kvm", "vhost", "virtio", "vfio", "nfsiod", "nfsd", "lockd",
                "rpciod", "xprtiod", "cifsd", "cifsiod", "smb", "fsnotify", "kintegrity",
                "ksgxd", "kpktgend", "tls-strp", "erofs", "f2fs", "nvidia", "UVM", "kmemleak",
                "khidpd", "kcompactd", "slub_flushwq", "events", "krdsd", "ib", "rdma",
                "bond", "wg-crypt", "wireguard", "kthrotld", "scsi_eh", "scsi_tmf", "dio/",
                "sdma", "mlx", "ice", "i40e", "ixgbe", "bnxt", "tg3", "r8169", "e1000",
                "gve", "ena", "hv_", "storvsc", "vmw", "vmbus", "xen", "kxen", "ttm_swap",
                "pr/", "rcu_tasks", "rcu_exp", "rcu_par", "torture", "kunit", "drbd",
                "bch", "bcachefs", "zfs", "arc_", "dbu", "txg", "mmp", "l2arc", "z_",
                "spl", "kdamond", "khugepaged", "kfence", "irq_work", "edac", "intel_",
                "amd_", "ccp-", "NFSv4", "nfsv4", "lockd", "nfsd", "sev", "psp", "qat", "nitro", "tpm", "kpsmoused", "ipmi",
                "acpi", "kacpi", "kacpid", "kacpi_notify", "kacpi_hotplug", "kmmpd", "jfs",
                "reiserfs", "gfs2", "ocfs2", "dlm", "kafs", "ceph", "rbd", "nbd", "md_",
                "raid", "bioset", "kdmremove", "kvub300", "ksgx", "kgraft", "livepatch",
                "kprobe", "uprobe", "bpf", "kcs", "vdpa", "nvmet", "target_", "iscsi",
                "ksmbd", "kthread", "swapper",
            ]),
            allowed_suid: s(&[
                // util-linux, shadow, sudo
                "/usr/bin/su", "/usr/bin/mount", "/usr/bin/umount", "/usr/bin/sudo",
                "/usr/bin/passwd", "/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/gpasswd",
                "/usr/bin/newgrp", "/usr/bin/expiry", "/usr/bin/chage", "/usr/sbin/unix_chkpwd",
                "/usr/bin/newuidmap", "/usr/bin/newgidmap", "/usr/bin/sudoedit",
                // cron, at, mail, tty
                "/usr/bin/crontab", "/usr/bin/at", "/usr/bin/dotlockfile", "/usr/bin/wall",
                "/usr/bin/write", "/usr/bin/bsd-write", "/usr/bin/write.ul", "/usr/bin/ssh-agent",
                "/usr/bin/mlocate", "/usr/bin/plocate", "/usr/bin/locate",
                // fuse, polkit, dbus, openssh
                "/usr/bin/fusermount", "/usr/bin/fusermount3", "/usr/bin/pkexec",
                "/usr/lib/polkit-1/polkit-agent-helper-1", "/usr/libexec/polkit-agent-helper-1",
                "/usr/lib/dbus-1.0/dbus-daemon-launch-helper", "/usr/lib/openssh/ssh-keysign",
                "/usr/libexec/openssh/ssh-keysign",
                // desktop and other common Debian 13 packages
                "/usr/lib/xorg/Xorg.wrap", "/usr/sbin/pppd", "/usr/bin/ntfs-3g",
                "/usr/lib/chromium/chrome-sandbox", "/usr/sbin/mount.cifs", "/usr/sbin/mount.nfs",
                "/usr/lib/snapd/snap-confine", "/usr/bin/vmware-user-suid-wrapper",
                "/usr/sbin/exim4", "/usr/lib/eject/dmcrypt-get-device", "/usr/bin/staprun",
                "/usr/sbin/postdrop", "/usr/sbin/postqueue", "/usr/lib/x86_64-linux-gnu/utempter/utempter",
                "/usr/lib/utempter/utempter", "/usr/bin/screen", "/usr/sbin/mount.ecryptfs_private",
                "/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper",
                "/usr/libexec/spice-client-glib-usb-acl-helper", "/usr/lib/kde4/libexec/kcheckpass",
                "/usr/lib/x86_64-linux-gnu/libexec/kf6/kcheckpass", "/usr/bin/kismet_cap_linux_wifi",
                "/usr/sbin/userhelper", "/usr/bin/firejail", "/usr/lib/virtualbox/VBoxHeadless",
                "/usr/lib/virtualbox/VBoxNetAdpCtl", "/usr/lib/virtualbox/VBoxNetDHCP",
                "/usr/lib/virtualbox/VBoxNetNAT", "/usr/lib/virtualbox/VBoxSDL",
                "/usr/lib/virtualbox/VirtualBoxVM", "/usr/bin/X", "/usr/sbin/sensible-mda",
                "/usr/bin/procmail", "/usr/bin/lockfile", "/usr/bin/mutt_dotlock",
                "/usr/libexec/Xorg.wrap", "/usr/sbin/pam_extrausers_chkpwd", "/usr/bin/bwrap",
                "/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic", "/usr/lib/qemu/qemu-bridge-helper",
                "/usr/libexec/qemu-bridge-helper", "/usr/lib/opera/opera_sandbox",
                "/usr/share/code/chrome-sandbox", "/opt/google/chrome/chrome-sandbox",
                "/usr/bin/traceroute6.iputils", "/usr/bin/ping", "/usr/bin/fping", "/usr/bin/xiterm+thai",
                // Electron/Chromium apps ship their own SUID sandbox ('*' matches one directory level)
                "/usr/lib/*/chrome-sandbox", "/opt/*/chrome-sandbox", "/usr/share/*/chrome-sandbox",
            ]),
            fs_roots: s(&["/"]),
            fs_exclude_paths: s(&[
                "/proc", "/sys", "/dev", "/run", "/var/lib/docker/overlay2",
                "/var/lib/containers/storage/overlay", "/snap", "/var/lib/lxcfs", "/media",
                "/mnt", "/var/lib/flatpak/repo", "/timeshift", "/.snapshots", "/var/lib/snapper",
                "/var/lib/docker/btrfs", "/var/lib/lxc/*/rootfs",
            ]),
            allowed_systemd_units: Vec::new(),
            allowed_cron_files: s(&[
                "e2scrub_all", "php", "popularity-contest", "sysstat", "anacron", "apt-compat",
                "dpkg", "logrotate", "man-db", "exim4-base", "bsdmainutils", "passwd", "mlocate",
                "plocate", "locate", "apache2", "aptitude", "debsums", "rkhunter", "chkrootkit",
                "certbot", "ntp", "spamassassin", "0anacron", "dlocate", "mdadm", "quota",
                "apt-show-versions", "clamav-freshclam", "samba", "texlive-base", "tmpreaper",
                "unattended-upgrades", "zfsutils-linux", "lynis", ".placeholder",
                "fake-hwclock", "raspi-config", "btrfsmaintenance", "smartmontools", "timeshift-hourly",
                "timeshift-boot", "sendmail", "ntpsec", "chrony", "vnstat", "needrestart",
            ]),
            allowed_ssh_key_comments: Vec::new(),
            allowed_pam_modules: s(&[
                "pam_unix", "pam_deny", "pam_permit", "pam_env", "pam_limits", "pam_systemd",
                "pam_loginuid", "pam_keyinit", "pam_selinux", "pam_motd", "pam_mail", "pam_lastlog",
                "pam_lastlog2", "pam_securetty", "pam_nologin", "pam_rootok", "pam_succeed_if",
                "pam_umask", "pam_xauth", "pam_wheel", "pam_faildelay", "pam_cap",
                "pam_gnome_keyring", "pam_kwallet5", "pam_kwallet6", "pam_fprintd", "pam_sss",
                "pam_winbind", "pam_ldap", "pam_krb5", "pam_mkhomedir", "pam_systemd_home",
                "pam_pwquality", "pam_cracklib", "pam_faillock", "pam_shells", "pam_listfile",
                "pam_time", "pam_access", "pam_group", "pam_namespace", "pam_tty_audit",
                "pam_echo", "pam_exec", "pam_ecryptfs", "pam_google_authenticator", "pam_u2f",
                "pam_timestamp", "pam_issue", "pam_ftp", "pam_localuser", "pam_pwhistory",
                "pam_userdb", "pam_warn", "pam_setquota", "pam_sepermit", "pam_gdm",
                "pam_fscrypt", "pam_mount", "pam_env_conf", "pam_systemd_loadkey", "pam_debug",
                "pam_filter", "pam_rhosts", "pam_stress", "pam_unix2", "pam_oath", "pam_yubico",
                "pam_ssh_agent_auth", "pam_cgfs", "pam_sm3", "pam_extrausers", "pam_snapper",
                "pam_tally2", "pam_mysql", "pam_radius_auth", "pam_script", "pam_pkcs11",
                "pam_p11", "pam_ccreds", "pam_smbpass", "pam_chroot", "pam_abl", "pam_afs_session",
            ]),
            allowed_ld_preload: s(&[
                "libmozsandbox.so", "libzypak-preload", "gameoverlayrenderer.so", "libgtk3-nocsd",
                "libjemalloc", "libtcmalloc", "libmimalloc", "libfakeroot", "libeatmydata", "libstdbuf",
                "vgpreload", "libgamemodeauto", "libMangoHud", "libvkbasalt", "libsnoopy", "libfaketime",
                "libsteam", "steamclient",
            ]),
            external_tool_timeout_secs: 900,
            ignore_rules: Vec::new(),
            ignore_evidence_containing: Vec::new(),
        }
    }
}

impl Config {
    /// Load from a file. `.json` is read as JSON, everything else as TOML.
    /// Fields missing from the file get their default value.
    pub fn load(path: &Path) -> Result<Self, ScanError> {
        let text = std::fs::read_to_string(path).map_err(|e| ScanError::io(path, e))?;
        let is_json = path
            .extension()
            .map(|e| e.eq_ignore_ascii_case("json"))
            .unwrap_or(false);
        if is_json {
            serde_json::from_str(&text)
                .map_err(|e| ScanError::Config(format!("{}: {e}", path.display())))
        } else {
            toml::from_str(&text).map_err(|e| ScanError::Config(format!("{}: {e}", path.display())))
        }
    }

    pub fn to_toml(&self) -> Result<String, ScanError> {
        toml::to_string_pretty(self).map_err(|e| ScanError::Config(e.to_string()))
    }

    /// Is the path in allowed_suid? '*' matches a name (not '/').
    pub fn is_suid_allowed(&self, path: &str) -> bool {
        self.allowed_suid.iter().any(|p| glob_match(p, path))
    }

    /// Should the path be skipped during the file system walk? Supports '*' like is_suid_allowed.
    pub fn is_fs_excluded(&self, path: &str) -> bool {
        self.fs_exclude_paths.iter().any(|x| {
            glob_match(x, path)
                || (!x.contains('*') && path.starts_with(&format!("{x}/")))
        })
    }

    pub fn is_listen_allowed(&self, proto: &str, port: u16) -> bool {
        let key = format!("{proto}/{port}");
        self.allowed_listen_ports.iter().any(|p| p == &key)
    }

    pub fn is_temp_path(&self, path: &str) -> bool {
        self.temp_dirs
            .iter()
            .any(|d| path == d || path.starts_with(&format!("{d}/")))
    }

    pub fn is_shell(&self, name: &str) -> bool {
        self.shell_names.iter().any(|s| s == name)
    }

    /// Script interpreter: exact name or name with a version suffix (python3.13, perl5.40).
    pub fn is_interpreter(&self, name: &str) -> bool {
        self.script_interpreters.iter().any(|s| {
            name == s
                || (name.starts_with(s.as_str())
                    && name[s.len()..]
                        .chars()
                        .all(|c| c.is_ascii_digit() || c == '.'))
        })
    }

    /// Should the finding be hidden according to the whitelist?
    pub fn suppresses(&self, f: &crate::finding::Finding) -> bool {
        self.ignore_rules.iter().any(|r| r == &f.rule)
            || self
                .ignore_evidence_containing
                .iter()
                .any(|needle| !needle.is_empty() && f.evidence.contains(needle.as_str()))
    }
}

/// Simple glob: '*' matches any characters except '/'.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    fn rec(p: &[u8], t: &[u8]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some(b'*') => (0..=t.len()).take_while(|i| *i == 0 || t[i - 1] != b'/').any(|i| rec(&p[1..], &t[i..])),
            Some(c) => t.first() == Some(c) && rec(&p[1..], &t[1..]),
        }
    }
    rec(pattern.as_bytes(), text.as_bytes())
}
