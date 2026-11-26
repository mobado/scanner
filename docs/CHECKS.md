# What scanner checks

Every finding has a stable **rule id**. Use it in `ignore_rules` (whitelist) to switch a
whole rule off, or look it up here. Severities are the usual level; some rules go up or down
depending on the evidence (for example a binary deleted from `/usr` is Low, from `/home` High).

## Network and hidden processes (`net_proc`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `NET-REVSHELL` | Critical | A shell or `nc`/`socat` with an established connection, or stdin/stdout tied to a socket |
| `NET-BINDSHELL` | Critical–Medium | A shell/interpreter that listens on a port |
| `NET-INTERP-CONN` | Medium/Low | A script interpreter with an outgoing connection |
| `NET-SUSP-PORT` | High | A connection to a typical backdoor port (4444, 1337, 31337 …) |
| `NET-TMP-SOCKET` | Critical | A program from `/tmp`, `/var/tmp`, `/dev/shm` or `/run` holds a network socket |
| `NET-DELETED-SOCKET` | Medium/Critical | A deleted binary holds a network socket |
| `NET-LISTEN-UNKNOWN` | Medium/Low | A listening port that is not in the whitelist (grouped per program) |
| `NET-ORPHAN-LISTEN` | High/Low | A listening socket without any owner process (Low when the NFS client explains it) |
| `NET-SS-MISMATCH` | High | `ss` sees a listening port that `/proc/net` hides |
| `NET-HIDDEN-PID` | High | A PID the scheduler knows but `/proc` does not list |
| `NET-KTHREAD-FAKE` | Critical | A normal process disguised as a kernel thread (`[kworker/…]`) |
| `NET-KTHREAD-NAME` | Low | A kernel thread with an unknown name |
| `NET-ARGV0-MASK` | High/Medium | `argv[0]` does not match the real binary in `/proc/<pid>/exe` |
| `NET-OUTBOUND-UNUSUAL` | Medium/Low | An outgoing internet connection on a port that is not in `common_remote_ports` |
| `NET-DNS-DIRECT` | Medium | A program talks DNS to a server that is not the system resolver (possible tunnelling) |
| `NET-RESOLVER` | High/Medium | `resolv.conf` writable or linked oddly, or an unknown public DNS server (`trusted_resolvers`) |
| `NET-HOSTS-OVERRIDE` | High | `/etc/hosts` redirects Debian, GitHub or security sites |
| `NET-ARP-DUPLICATE` | High/Low | Several addresses with one hardware address (High when it includes the gateway) |
| `NET-ROUTE-DEFAULT` | Medium | Two default gateways with the same priority |
| `NET-TUNNEL-IFACE` | Medium/Low | A WireGuard, TUN/TAP, GRE or IP tunnel interface that no network configuration declares (Low without root; Tailscale, Docker, libvirt and similar are skipped) |
| `NET-WG-PEER` | Medium | A running WireGuard peer that no configuration file lists (root, `wg` installed) |
| `NET-TUNNEL-PROGRAM` | High/Medium | A running tunnel tool from `tunnel_programs` (ngrok, cloudflared, chisel, frpc …) |
| `NET-SSH-REVERSE` | High–Low | A running `ssh -R` tunnel, or `RemoteForward` in SSH settings |
| `NET-HIDDEN-PS` | High | `ps` and the `/proc` listing disagree about which processes exist |
| `NET-LOCAL-SERVER` | Low | A script serves something that only this computer can reach (not a bind shell) |
| `NET-SSH-AGENT` | Medium/Low | SSH settings forward the key agent (Medium for every host) |
| `NET-BLUETOOTH` | Low | Paired Bluetooth keyboards; an adapter that is visible to everyone (paired devices need root) |
| `NET-SHARE` | Medium | NFS exports with `no_root_squash` or open to all, Samba folders where guests may write |
| `NET-DNS-CONFIG` | High/Medium | Unknown DNS servers in systemd-resolved or NetworkManager settings; dnsmasq redirects of update and developer sites |
| `NET-DNS-HANDED` | Low | DNS servers handed out by the network or VPN that are not well known |
| `NET-DNS-LEAK` | Low | Traffic goes through a VPN but a DNS server sits on the local network |
| `NET-PROMISC` | Medium | A network card in promiscuous (sniffing) mode (`IFF_PROMISC`) |
| `NET-SNIFFER` | High–Low | A raw packet socket for all protocols (`/proc/net/packet`), mapped to its program; network services such as NetworkManager are skipped, tcpdump and Wireshark are Medium |
| `NET-NAT-REDIRECT` | Low/Medium | Firewall rules (`nft`; Medium for old `iptables-legacy`) that redirect or forward traffic; Docker/libvirt rules are skipped (needs root; `nft` not in the timer service) |

`NET-LISTEN-UNKNOWN` says who can reach the port, and the notes count how many ports are open to
every network, to one address, or only to this computer.

## Kernel and modules (`kernel`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `KERN-MODULE-HIDDEN` | High | A module in `/sys/module` that `/proc/modules` (lsmod) hides |
| `KERN-ROOTKIT-NAME` | Critical | A known rootkit module name |
| `KERN-MODULE-UNTRUSTED` | Medium | Out-of-tree, unsigned or forced modules not in `allowed_out_of_tree_modules` |
| `KERN-SYSCTL` | Critical–Low | Dangerous settings: `kernel.modprobe`, `core_pattern`, `hotplug`, ASLR off, link protection off … |
| `KERN-MODPROBE-CMD` | Critical/High | A suspicious `install`/`remove` command in `modprobe.d` |
| `KERN-EBPF` / `-PINNED` | Medium/Low | Loaded eBPF programs that can watch system calls or traffic (Medium when the holder is unfamiliar or none); pinned objects in `/sys/fs/bpf`. Complete with root and the `bpftool` package, otherwise only programs held by processes |
| `KERN-TAINTED` | High–Low | Why the kernel is "tainted", bit by bit; Medium when the module that caused it is no longer loaded, High after a forced removal |
| `KERN-SECUREBOOT` | Medium/Low | Secure Boot off, or on without kernel lockdown (with `sig_enforce` and `modules_disabled`) |
| `KERN-BOOT-ENTRY` | Low | UEFI boot entries that start another loader than Debian's, Windows' or the default one |
| `KERN-APPARMOR-OFF` / `-PROFILES` | Medium / Low | AppArmor is not active; profiles that only complain or are disabled (listing them needs root) |
| `KERN-SELINUX` | Medium | SELinux is in permissive mode |
| `KERN-USB-BADUSB` | High | A connected USB device is both a keyboard and a drive (BadUSB, Rubber Ducky) |
| `KERN-USB-HISTORY` | Medium | The kernel log (last `log_days` days, running system only) shows one USB port registering both |
| `KERN-THUNDERBOLT-OPEN` / `KERN-THUNDERBOLT` | Medium / Low | Thunderbolt security level `none` without IOMMU protection; approved Thunderbolt devices that are connected |

## Web files and containers (`services`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `SVC-WEBSHELL` | Critical/High | A script in a web folder (`web_roots`) that runs what a visitor sends |
| `SVC-CONTAINER-SOCKET` | Critical | The Docker/Podman/containerd socket is writable by everyone |
| `SVC-DOCKER-API` | High | The Docker API listens unencrypted on port 2375 |
| `SVC-CONTAINER-PRIVILEGED` | High | Processes in a privileged container |
| `SVC-CONTAINER-SOCKET-MOUNT` | High | The container engine socket is mounted into a container |

## Logs and clock (`integrity`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `INT-LOG-DEVNULL` | High/Medium | A log or shell history linked to `/dev/null` |
| `INT-LOG-EMPTY` | Medium | A log empty for days although older logs have content |
| `INT-WTMP` | Medium/Low | Damaged or blanked login records |
| `INT-TIME-BACKWARDS` | Medium | Log time jumps back more than an hour; lists logins and administrator actions within 10 minutes of the jump |
| `INT-BOOT-OPTIONS` | High–Low | Kernel options (running, `/etc/default/grub`, `grub.cfg`) such as `init=`, `apparmor=0`, `nokaslr`, `mitigations=off` |
| `INT-GRUB-SCRIPT` | Critical–Medium | An executable boot menu script that no package installed |
| `INT-KERNEL-FILE` | Critical/Low | `vmlinuz`/`System.map` differs from its package, or a kernel from no package |
| `INT-DISK-ERRORS` | Low | ext4 error counters and disk I/O errors in the kernel log, which can look like tampering |
| `INT-JOURNAL-CORRUPT` / `-VOLATILE` | Medium/Low | Journal fails verification (root, full scan only, at most `journal_verify_secs` = 90 s) / not kept across reboots |
| `INT-CLOCK` | Medium/Low | Automatic time setting off or clock not synchronised |

## Processes and run paths (`proc_audit`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `PROC-TMP-EXE` | High/Critical | A process runs from a temporary directory |
| `PROC-DELETED` | Low–Critical | The binary was deleted while running (several Low ones become one "restart needed" finding); Critical when it ran from a temporary folder such as `/dev/shm` |
| `PROC-APP-SPAWN` | High/Medium | A document viewer started a shell or download tool, or a browser or mail program started one (browser helpers and `xdg-open` are skipped) |
| `PROC-MEMFD` | Critical | A fileless process running from a memfd |
| `PROC-LD-PRELOAD` | Medium–Critical | A process with `LD_PRELOAD` set (Firefox's sandbox, Flatpak etc. are whitelisted) |
| `PROC-MALWARE-NAME` | Critical | A known malware name (miners …) |
| `PROC-SHM-CWD` | Medium | A process works in `/dev/shm` |
| `PROC-ROOT-ODD-PATH` | Medium/Low | A root process from outside the package folders |
| `PROC-HIGH-CPU` | Medium/Low | At least `high_cpu_percent` (70) CPU on average (a miner sign): after 10 minutes for programs outside the system folders, after `high_cpu_minutes` (60) for installed ones; `cpu_heavy_programs` (browsers, compilers, players, indexers) are skipped |
| `PROC-HOME-EXE` | Medium/Low | A process started from the download folder, the wastebasket or a hidden file (Low from a cache folder) |
| `PROC-APPIMAGE` | Low | A program running from a mounted AppImage |
| `PROC-TRACED` | Critical–Low | A process is being traced (`TracerPid`): Critical when an unknown program traces sshd, sudo, a browser, a key agent …; Low for an installed debugger on an ordinary program |
| `PROC-HIDDEN-MOUNT` | Critical–Medium | A mount over `/proc/<pid>` (hides a process), or over parts of `/etc`, `/usr/bin`, libraries … |
| `PROC-LD-LIBRARY-PATH` | High/Low | `LD_LIBRARY_PATH` points to a temporary (High) or relative folder (AppImages are skipped) |
| `PROC-SECRET-ACCESS` | Critical–Low | A program other than the browser (or wallet program) has saved passwords or cookies (`Cookies`, `Login Data`, `logins.json`, `key4.db` …) or a keyring/KWallet file open. Low for backup, search and antivirus programs; Critical from a temporary, download or hidden folder |
| `PROC-ENV-INJECT` | High–Low | A running program has a variable that loads code: `NODE_OPTIONS=--require`, `PYTHONSTARTUP`, `BASH_ENV`, `LD_AUDIT`, `PERL5OPT`, `RUBYOPT`, `-javaagent`, library paths in temporary folders … |
| `PROC-SSH-SOCKET` | Medium | `SSH_AUTH_SOCK` points somewhere key agents do not normally put their socket |
| `PROC-ENV-SECRETS` | Medium/Low | Programs carry API keys, tokens or passwords in their environment (**names only**, values are never reported); Medium when a browser, viewer or temporary program has one |
| `PROC-SECRET-CALL` | Critical–Low | A program asked the password wallet (Secret Service, GNOME Keyring, KWallet) for secrets while the scanner listened: full scan (`wallet_watch_secs` = 15) or `--watch-wallet SECS`. Medium for scripts and command line tools, High/Critical from odd folders; installed programs are only named in the notes. Passwords never pass through the scanner (`dbus-monitor --profile` shows who asked for what) |
| `PROC-IO-URING` | High–Low | A program outside the system folders uses io_uring, which sidesteps system call monitoring |
| `PROC-NAMESPACE` | High/Medium | Processes in their own user, network or mount namespace that no known sandbox (Flatpak, bubblewrap, browsers, Electron apps, Steam), container, Snap or system service explains. A mount namespace alone only counts for programs in home or temporary folders |

## File permissions (`fs_perms`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `FS-SUID-UNKNOWN` | Medium/Low | A SUID/SGID file that is not in `allowed_suid` |
| `FS-SUID-NONROOT` | High | A SUID file owned by someone other than root |
| `FS-SUID-TEMP` | Critical | A SUID/SGID file in `/tmp`, `/dev/shm`, `/home` or `/var/www` |
| `FS-SUID-WRITABLE` | Critical | A world-writable SUID/SGID file |
| `FS-WORLD-WRITABLE` | High | A world-writable file or folder in a system location |
| `FS-SENSITIVE-PERMS` | Critical/High | Wrong permissions on `passwd`, `shadow`, `sudoers` … |
| `FS-SUID-SHELL` | Critical | A shell, interpreter, `find`, `vim` … with SUID root |
| `FS-TMP-EXEC` | High–Low | Executable programs or scripts in `temp_dirs`, grouped per folder (High in `/dev/shm` or hidden); also when `/tmp` is held in memory |
| `FS-CAPABILITY` | Critical–Low | A file with capabilities that is not in `allowed_capability_files`; Critical for root-level rights on a shell/interpreter or in a temporary or home folder |
| `FS-IMMUTABLE` | High/Low | A locked (`chattr +i`) file in `/etc`, system program folders, `/root`, cron or `.ssh` (Low for `resolv.conf`) |
| `FS-SYSTEM-CHANGED` | Critical | `su`, `sudo`, `sshd`, systemd, `pkexec`, `ps`, `ls`, a PAM module, libpam, libc … differs from the checksum its package ships (dpkg records MD5) |
| `FS-PACKAGE-CHANGED` | Critical | Any program in `/usr/bin` or `/usr/sbin` rewritten after its package was installed and no longer matching it |
| `FS-TIMESTAMP` | Medium/Low | Times that do not fit (timestomping): a modification time later than the change time, or a file from no package in `/usr/bin`, `/usr/sbin` or startup folders in `/etc` dated long before it last changed |
| `FS-SYSTEM-UNPACKAGED` | High | A PAM module that no package installed |
| `FS-DOWNLOAD-PROGRAM` | Low | Files in the download folder that are allowed to run (one finding per folder; `download_dirs` and the XDG setting) |
| `FS-DOWNLOAD-DISGUISED` | Medium | A download that looks like a document but runs (`invoice.pdf.desktop`) |
| `FS-SCRIPT-SUSPICIOUS` | High | A script in the download folder or `~/.local/bin` with a command typical of a break-in |
| `FS-HOME-HIDDEN-PROGRAM` | Medium | A compiled program with a hidden name, or loose in `.cache`, `.config` or `.local/share` |
| `FS-BROWSER-ADDON` | High/Medium | A Firefox or Chrome/Chromium/Brave/Edge/Vivaldi/Opera add-on that did not come from the store (unsigned, from a file or folder, forced) |
| `FS-BROWSER-SETTING` | High–Low | Proxy, remote control, unsigned add-ons allowed, unfamiliar search engine or DNS server, dangerous start options in launchers, browser policies |
| `FS-BROWSER-NATIVE` | Critical–Low | A native messaging host (a program browser add-ons can start) in an odd place, from no package, or your own; Critical when it is a script with a break-in command. The host descriptions are also recorded in the baseline |
| `FS-SECRET-PERMS` | High–Low | Files in home folders that other users can read: private keys (`~/.ssh`, `~/.gnupg`) High; `.aws/credentials`, `.kube/config`, `gh`, Docker, `.netrc`, npm and PyPI tokens and `.env` files Medium; Low when the files are open but a closed folder keeps others out |

## Persistence (`persistence`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `PERS-SYSTEMD-EXEC` | Critical–Medium | A systemd unit/timer starts a suspicious command |
| `PERS-SYSTEMD-LOCAL` / `-USER` / `-LINK` / `-PERMS` | Low–High | A locally made unit, a user unit, a link to an odd place, loose permissions |
| `PERS-CRON-CMD` / `-REBOOT` / `-USER` / `-UNKNOWN` / `-PERMS` | Critical–Low | Suspicious cron jobs and unknown cron files |
| `PERS-AT-JOBS` | Medium | Pending `at` jobs |
| `PERS-RC-LOCAL` | Medium+ | `/etc/rc.local` contains commands |
| `PERS-LDPRELOAD` | Critical | `/etc/ld.so.preload` is filled in |
| `PERS-LDCONF` | High | A library search path in `/etc/ld.so.conf*` points to a temporary or home folder |
| `PERS-SSHD-*` | Critical–Low | Unsafe sshd settings (`PermitRootLogin yes`, changed `AuthorizedKeysFile`, odd subsystem …) |
| `PERS-SSH-COMMAND` / `-ENV` / `-TUNNEL` / `-WEAK` / `-NOCOMMENT` / `-UNKNOWN-KEY` / `-KEYS` / `-RC` / `-PERMS` | High–Low | Suspicious `authorized_keys` entries and `~/.ssh/rc` |
| `PERS-PAM-PERMIT` | Critical | `pam_permit.so` as `sufficient` in auth/account |
| `PERS-PAM-EXEC` / `-PATH` / `-UNKNOWN` / `-PERMS` | Critical–Medium | Odd PAM modules and permissions |
| `PERS-SHELLRC` | High+ | Suspicious shell start files |
| `PERS-SESSION-SCRIPT` | Critical–Low | Network (NetworkManager) and sleep scripts: suspicious commands, or not installed by a package |
| `PERS-POLKIT` | Critical–Low | polkit rules that no package installed (above all ones that allow actions without a password), polkit files in home folders |
| `PERS-UDEV` | Critical–Medium | A udev rule runs a suspicious command or a program outside the system folders |
| `PERS-SYSTEMD-GENERATOR` | Critical/High | A systemd generator that no package installed |
| `PERS-SYSTEMD-DROPIN` | Critical–Medium | A `*.d/*.conf` drop-in with a suspicious command, or one from no package that adds `Exec…=` or `LD_PRELOAD` to a unit |
| `PERS-BINFMT` | Critical–Medium | A registered binary format (`binfmt_misc`) whose interpreter is in an odd place or from no package |
| `PERS-GIT-HOOK` | Critical–Low | Git hooks in repositories in system folders (etckeeper's own is skipped); `core.hooksPath`, `fsmonitor` or `sshCommand` in git settings |
| `PERS-PKG-CONFIG` | High–Low | pip or npm set to use another package server, skip certificate checks or run a script (tokens are never shown) |
| `PERS-DPKG-HOOK` | Critical–Medium | dpkg runs a command at installations |
| `PERS-INITRAMFS-HOOK` | Critical–Medium | A boot image (initramfs) hook or script that no package installed |
| `PERS-INITRAMFS-UNKNOWN` | Medium | Scripts or programs inside a boot image that nothing on the system explains (full scan as root) |
| `PERS-INITRAMFS-REBUILT` | Low | A boot image written without any package activity around that time |
| `PERS-AT-CMD` | Critical/High | A queued `at` job with a suspicious command |
| `PERS-CA-ADDED` | Low | A locally added certificate authority |
| `PERS-KEY-PERMS` | High | A private SSH host or TLS key readable by others |
| `PERS-UID0` | Critical | A second account with UID 0 |
| `PERS-DUP-ID` | High/Medium | Two accounts share a UID, two groups a GID, or a name appears twice |
| `PERS-APT-UNSIGNED` | Medium | A software source with `trusted=yes` or `allow-insecure=yes` |
| `PERS-APT-THIRDPARTY` | Low | A software source whose host is not in `trusted_apt_hosts` (`*.debian.org`) |
| `PERS-APT-HOOK` | Critical/High | apt runs a suspicious command (`apt.conf.d` hooks) |
| `PERS-HISTORY` | High–Low | Suspicious commands in a shell history (reverse shells, history switched off, logs deleted, download-and-run …); only those lines are shown |
| `PERS-TRANSIENT-UNIT` | Critical–Medium | A service created on the fly (`systemd-run`) with a suspicious command |
| `PERS-ENV-INJECT` | High–Low | `/etc/environment`, `environment.d`, `.pam_environment` or a shell start file sets a variable that loads code (as `PROC-ENV-INJECT`) |
| `PERS-SYSACCT-SHELL` / `PERS-EMPTY-PASSWORD` / `PERS-SUDO-NOPASSWD` | High–Low | Account and sudo settings |

## Desktop session (`desktop_session`)

Everything tied to a graphical session. Each title starts with a label: `[xdg]` (shared
standards), `[kde]`, `[gnome]`, `[xfce]`, `[wm]` (sway, i3 and other window managers),
`[login]` (login screen), `[x11]`, `[input]`, `[remote]`, `[flatpak]`, `[snap]` and
`[appimage]`.

**Servers.** If the machine has no desktop session, login screen or X server installed and no
graphical program running, only the keyboard check runs and the report notes it. A baseline
made then reports `BASE-DESKTOP-NEW` (High) when a desktop appears.

**How findings are graded**

| Level | Meaning | Examples |
|-------|---------|----------|
| Critical / High | What runs is itself suspicious | download-and-run, reverse shell, program in `/tmp`, unknown keyboard reader outside the system folders |
| Medium | It works, but changes what runs or who sees your data | program no package installed, entry replacing a system one, proxy, remote desktop, `xhost +`, own portal |
| Low (information) | Your own ordinary things, worth knowing | own session scripts, installed programs in autostart, extensions, screen lock off |
| Baseline difference | A startup file is new or changed | Medium in a home folder, High for system files; state that changes at every logout is not recorded |

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `PERS-AUTOSTART` | Critical–Low | `[xdg]` autostart (`/etc/xdg`, `/usr/share/autostart`, GNOME and user folders): suspicious commands; own scripts, programs no package installed, or a user entry that replaces a system entry (Medium); installed programs in a user's autostart (Low) |
| `PERS-SESSION-SCRIPT` | Critical–Low | X11 and login-screen scripts, `~/.xprofile`, `~/.xinitrc`, `~/.xsessionrc`, Plasma `env` and `shutdown`, XFCE `xinitrc` |
| `PERS-DM-SCRIPT` | Critical–Medium | `[login]` LightDM, SDDM or GDM settings that run an unusual command |
| `PERS-DBUS-SERVICE` | Critical–Low | Session D-Bus services in home folders or `/usr/local` (Medium when they replace a system service, such as a portal) |
| `PERS-PORTAL` | Medium | A desktop portal that no package installed |
| `PERS-DESKTOP-COMMAND` | Critical–Medium | A command from a desktop's own settings that is suspicious or runs from an odd place: KDE saved session, notification actions and shortcuts; GNOME shortcuts and saved session; XFCE session, shortcuts, saved session and panel; sway, i3, Hyprland, swayidle, openbox, LXDE, labwc, wayfire, fluxbox, xscreensaver |
| `PERS-KWIN-SCRIPT` / `-RULE` | Medium/Low | `[kde]` an own KWin script is on (Medium when it can start programs); window rules that make windows invisible |
| `PERS-DESKTOP-PROXY` | Medium | KDE or GNOME settings send traffic through a proxy (passwords are not shown) |
| `PERS-REMOTE-DESKTOP` / `PERS-SCREEN-LOCK` | Medium / Low | GNOME remote desktop is on / the screen lock is off (GNOME or KDE) |
| `DESK-REMOTE-SCREEN` | High/Medium | A remote desktop program from `remote_desktop_programs` is running (also on servers), or KDE screen sharing allows unattended access |
| `DESK-FLATPAK-OVERRIDE` / `-REMOTE` / `-ACCESS` | High–Low | Extra permissions added to Flatpak apps; sources outside Flathub or without signature check; apps with wide access |
| `DESK-SNAP` | Medium/Low | Snaps installed from a local file or in developer mode; classic snaps |
| `DESK-APPIMAGE` | Low | AppImage programs in home folders (nothing verifies or updates them) |
| `PERS-GNOME-EXTENSION` | Low | Own GNOME Shell extensions that are switched on (read from the dconf database) |
| `PERS-X11-OPEN` | Medium | `xhost +` opens the X11 display to others |
| `PROC-INPUT-READER` | High/Medium | A program that reads `/dev/input` directly and is not a known compositor, key or mouse tool (High from outside the system folders), known keyloggers, or `xinput test`. The report's notes also say whether each session is Wayland or X11 |

## Pending updates (`updates`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `UPD-SECURITY` | Medium | Security updates are waiting (from `apt-get -s upgrade`, a simulation) |
| `UPD-AVAILABLE` | Low | Other updates are waiting |
| `UPD-REBOOT` | Medium/Low | A reboot is needed to finish installed updates |
| `UPD-STALE-LISTS` | Low | The package lists are more than a week old |
| `UPD-NO-SECURITY-REPO` | Medium | No software source provides security updates |
| `UPD-OLD-REPO` | Low | A Debian source for an older release |
| `UPD-MICROCODE` | Medium | `intel-microcode`/`amd64-microcode` is not installed (real machines only) |
| `UPD-FIRMWARE` | Low | `fwupd` missing, or its list of firmware updates older than 90 days |

## Login attempts (`auth_logs`)

Reads the systemd journal, or `/var/log/auth.log*` when the journal is not available (for
example on a mounted disk), and never further back than `log_days` days (default 28, four
weeks; for a mounted disk counted from its newest log line). "Many" means at least
`login_fail_threshold` (default 10).

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `AUTH-SSH-SUCCESS-AFTER-FAIL` | **Critical** | An address made 5 or more failed SSH attempts and then logged in |
| `AUTH-SSH-ROOT-PASSWORD` | High | root logged in over SSH with a password |
| `AUTH-SSH-PUBLIC` | Medium/Low | A successful SSH login from an internet address (Low with a key) |
| `AUTH-SSH-BRUTEFORCE` | Medium | Many failed SSH logins from one address |
| `AUTH-SSH-FAILED` | Low | A few failed SSH logins (all addresses in one finding) |
| `AUTH-SSH-INVALID-USER` | Medium/Low | SSH attempts with user names that do not exist |
| `AUTH-SUDO-FAILED` | Medium/Low | Wrong sudo password |
| `AUTH-SUDO-DENIED` | Medium | A user who may not use sudo (for that command) tried to |
| `AUTH-SU-FAILED` | Medium/Low | Wrong password with `su` |
| `AUTH-LOCAL-FAILED` | Medium/Low | Wrong password at the console, display manager (SDDM, GDM, LightDM), screen lock or password dialog; the evidence says where |
| `AUTH-PKEXEC-DENIED` | Medium/Low | A request to run something as root through `pkexec` was refused |
| `AUTH-POLKIT-FAILED` | Medium/Low | Wrong password in an administrator dialog (polkit) |
| `AUTH-ADMIN-ACTIONS` | Medium/Low | What was run with `pkexec` and approved in polkit dialogs (Medium for programs from a temporary or home folder) |
| `AUTH-NEW-USER` | Low | An account was created (from the logs) |
| `AUTH-GROUP-ADD` | Medium | A user was added to a powerful group (sudo, docker …) |

## Baseline comparison (`baseline`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `BASE-SUID-NEW` | **Critical** | A new SUID/SGID file since the baseline (Low when apt installed it and it matches the package) |
| `BASE-SUID-CHANGED` | Critical/Medium | A SUID/SGID file changed. Not reported when verified as an apt upgrade; Medium if it matches its package but apt did not touch it; Critical if it differs or no package owns it |
| `BASE-SUID-PERMS` / `-REMOVED` | High/Low | Changed permissions / file gone |
| `BASE-LISTEN-NEW` | High/Medium | A new listening port (random ports of known programs are ignored) |
| `BASE-ACCOUNT-NEW` / `-UID` / `-SHELL` / `-GROUP` / `-PASSWORD` / `-REMOVED` | Critical–Low | New accounts, changed user id or shell, new powerful group, a locked system account got a password |
| `BASE-PERSIST-NEW` / `-CHANGED` / `-REMOVED` | High–Low | A persistence file appeared / changed / disappeared |
| `BASE-SSH-KEY-NEW` | **Critical** | A new key in an `authorized_keys` file |
| `BASE-BLUETOOTH-NEW` | High/Medium | A new paired Bluetooth device (High for a keyboard) |
| `BASE-DEVICE-NEW` | Medium | A USB keyboard or Thunderbolt device that was not connected before |
| `BASE-APPARMOR-OFF` | High | AppArmor or SELinux stopped protecting |
| `BASE-DESKTOP-NEW` | High/Medium | A graphical desktop appeared on a machine that had none; a virtual or remote screen (Xvnc, x11vnc, Xvfb) started running |
| `BASE-SECUREBOOT-OFF` / `BASE-LOCKDOWN-OFF` | High | Secure Boot or the kernel lockdown was switched off |
| `BASE-BOOT-ENTRY-NEW` / `-CHANGED` / `BASE-BOOT-ORDER` | Medium/Low | UEFI boot entries or their order changed |

### How an apt upgrade is verified

A changed (or new) SUID or persistence file is accepted as an upgrade only when **all** hold:
a package owns it (`/var/lib/dpkg/info/*.md5sums`, or a conffile in `/var/lib/dpkg/status`),
its content equals that package's checksum, and `/var/log/dpkg.log` shows an install/upgrade of
the package after the baseline (or its file list was rewritten since). This uses dpkg's own
MD5 records, like `debsums`; a root attacker who also rewrites those records and the log could
fool it, so run `debsums` or scan from trusted media when in doubt.

## External tools (`external:*`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `EXT-DEBSUMS-CHANGED` / `-MISSING` | Critical–Low | A package file differs from its `.deb` / is missing |
| `EXT-CHKROOTKIT-INFECTED` / `-WARN` / `-WTMP` | High–Low | chkrootkit findings, a second opinion rather than proof (a login-record gap is Low) |
| `EXT-RKHUNTER-WARN` / `-KNOWN` | Medium/Low | rkhunter warnings, also a second opinion; known Debian false alarms are Low with a command to silence them |
| `EXT-LYNIS-WARN` / `-SUGGEST` | Medium/Low | Lynis warnings and hardening suggestions |

## What it cannot see

* A **kernel rootkit** can lie to every user-space program. `ss` ↔ `/proc/net` and
  `sched_debug` ↔ `/proc` catch simple ones; for certainty, scan the disk from trusted boot
  media with `--root /mnt/disk`.
* Without **root**, other users' processes, `/root`, `/var/spool/cron` and debugfs are
  unreadable. The report says what was skipped.
* A scan is a short moment: the password wallet is only heard while the scanner listens, and a
  program that read a password file and closed it before the scan leaves nothing open. A program
  that ends right after asking the wallet may not be identified.
* A **baseline** only shows change. If the machine was already compromised when it was made,
  the intrusion looks normal – which is why it is not saved automatically when the first scan
  has critical or high findings.
