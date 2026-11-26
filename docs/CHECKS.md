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
| `NET-PROMISC` | Medium | A network card in promiscuous (sniffing) mode |
| `NET-NAT-REDIRECT` | Low | Firewall rules (`nft`) that redirect or forward traffic; Docker/libvirt rules are skipped (needs root; not in the timer service) |

## Kernel and modules (`kernel`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `KERN-MODULE-HIDDEN` | High | A module in `/sys/module` that `/proc/modules` (lsmod) hides |
| `KERN-ROOTKIT-NAME` | Critical | A known rootkit module name |
| `KERN-MODULE-UNTRUSTED` | Medium | Out-of-tree, unsigned or forced modules not in `allowed_out_of_tree_modules` |
| `KERN-SYSCTL` | Critical–Low | Dangerous settings: `kernel.modprobe`, `core_pattern`, `hotplug`, ASLR off, link protection off … |
| `KERN-MODPROBE-CMD` | Critical/High | A suspicious `install`/`remove` command in `modprobe.d` |

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
| `INT-TIME-BACKWARDS` | Medium | Log time jumps back more than an hour |
| `INT-JOURNAL-CORRUPT` / `-VOLATILE` | Medium/Low | Journal fails verification (root, full scan only, at most `journal_verify_secs` = 90 s) / not kept across reboots |
| `INT-CLOCK` | Medium/Low | Automatic time setting off or clock not synchronised |

## Processes and run paths (`proc_audit`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `PROC-TMP-EXE` | High/Critical | A process runs from a temporary directory |
| `PROC-DELETED` | Low/High | The binary was deleted while running (several Low ones become one "restart needed" finding) |
| `PROC-MEMFD` | Critical | A fileless process running from a memfd |
| `PROC-LD-PRELOAD` | Medium–Critical | A process with `LD_PRELOAD` set (Firefox's sandbox, Flatpak etc. are whitelisted) |
| `PROC-MALWARE-NAME` | Critical | A known malware name (miners …) |
| `PROC-SHM-CWD` | Medium | A process works in `/dev/shm` |
| `PROC-ROOT-ODD-PATH` | Medium/Low | A root process from outside the package folders |
| `PROC-HIGH-CPU` | Medium/Low | At least `high_cpu_percent` (70) CPU on average (a miner sign): after 10 minutes for programs outside the system folders, after `high_cpu_minutes` (60) for installed ones; `cpu_heavy_programs` (browsers, compilers, players, indexers) are skipped |
| `PROC-HOME-EXE` | Medium/Low | A process started from the download folder, the wastebasket or a hidden file (Low from a cache folder) |
| `PROC-APPIMAGE` | Low | A program running from a mounted AppImage |
| `PROC-LD-LIBRARY-PATH` | High/Low | `LD_LIBRARY_PATH` points to a temporary (High) or relative folder (AppImages are skipped) |

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
| `FS-SYSTEM-CHANGED` | Critical | `su`, `sudo`, `sshd`, `ps`, `ls`, a PAM module … differs from the checksum its package ships |
| `FS-SYSTEM-UNPACKAGED` | High | A PAM module that no package installed |
| `FS-DOWNLOAD-PROGRAM` | Low | Files in the download folder that are allowed to run (one finding per folder; `download_dirs` and the XDG setting) |
| `FS-DOWNLOAD-DISGUISED` | Medium | A download that looks like a document but runs (`invoice.pdf.desktop`) |
| `FS-SCRIPT-SUSPICIOUS` | High | A script in the download folder or `~/.local/bin` with a command typical of a break-in |
| `FS-HOME-HIDDEN-PROGRAM` | Medium | A compiled program with a hidden name, or loose in `.cache`, `.config` or `.local/share` |
| `FS-BROWSER-ADDON` | High/Medium | A Firefox or Chrome/Chromium/Brave/Edge/Vivaldi/Opera add-on that did not come from the store (unsigned, from a file or folder, forced) |
| `FS-BROWSER-SETTING` | High/Medium | Proxy, remote control, unsigned add-ons allowed, dangerous start options in launchers, browser policies |

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
| `PERS-AUTOSTART` | Critical–Low | XDG autostart: suspicious commands; own scripts or unknown programs (Medium); installed programs in a user's autostart (Low); entries for all users that no package installed (Medium) |
| `PERS-SESSION-SCRIPT` | Critical–Low | Login, logout, sleep and network scripts (X11, GDM, SDDM, NetworkManager, system-sleep, Plasma): suspicious commands, or not installed by a package |
| `PERS-DM-SCRIPT` | Critical–Medium | LightDM/SDDM/GDM settings that run an unusual command |
| `PERS-POLKIT` | Critical–Low | polkit rules that no package installed (above all ones that allow actions without a password), polkit files in home folders |
| `PERS-UDEV` | Critical–Medium | A udev rule runs a suspicious command or a program outside the system folders |
| `PERS-AT-CMD` | Critical/High | A queued `at` job with a suspicious command |
| `PERS-CA-ADDED` | Low | A locally added certificate authority |
| `PERS-KEY-PERMS` | High | A private SSH host or TLS key readable by others |
| `PERS-UID0` | Critical | A second account with UID 0 |
| `PERS-DUP-ID` | High/Medium | Two accounts share a UID, two groups a GID, or a name appears twice |
| `PERS-APT-UNSIGNED` | Medium | A software source with `trusted=yes` or `allow-insecure=yes` |
| `PERS-APT-THIRDPARTY` | Low | A software source whose host is not in `trusted_apt_hosts` (`*.debian.org`) |
| `PERS-APT-HOOK` | Critical/High | apt runs a suspicious command (`apt.conf.d` hooks) |
| `PERS-HISTORY` | High–Low | Suspicious commands in a shell history (reverse shells, history switched off, logs deleted, download-and-run …); only those lines are shown |
| `PERS-SYSACCT-SHELL` / `PERS-EMPTY-PASSWORD` / `PERS-SUDO-NOPASSWD` | High–Low | Account and sudo settings |

## Pending updates (`updates`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `UPD-SECURITY` | Medium | Security updates are waiting (from `apt-get -s upgrade`, a simulation) |
| `UPD-AVAILABLE` | Low | Other updates are waiting |
| `UPD-REBOOT` | Medium/Low | A reboot is needed to finish installed updates |
| `UPD-STALE-LISTS` | Low | The package lists are more than a week old |

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
* A **baseline** only shows change. If the machine was already compromised when it was made,
  the intrusion looks normal – which is why it is not saved automatically when the first scan
  has critical or high findings.
