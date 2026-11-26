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

## File permissions (`fs_perms`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `FS-SUID-UNKNOWN` | Medium/Low | A SUID/SGID file that is not in `allowed_suid` |
| `FS-SUID-NONROOT` | High | A SUID file owned by someone other than root |
| `FS-SUID-TEMP` | Critical | A SUID/SGID file in `/tmp`, `/dev/shm`, `/home` or `/var/www` |
| `FS-SUID-WRITABLE` | Critical | A world-writable SUID/SGID file |
| `FS-WORLD-WRITABLE` | High | A world-writable file or folder in a system location |
| `FS-SENSITIVE-PERMS` | Critical/High | Wrong permissions on `passwd`, `shadow`, `sudoers` … |

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
| `PERS-SHELLRC` / `PERS-AUTOSTART` | High–Low | Suspicious shell start files and desktop autostart |
| `PERS-UID0` | Critical | A second account with UID 0 |
| `PERS-SYSACCT-SHELL` / `PERS-EMPTY-PASSWORD` / `PERS-SUDO-NOPASSWD` | High–Low | Account and sudo settings |

## Pending updates (`updates`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `UPD-SECURITY` | Medium | Security updates are waiting (from `apt-get -s upgrade`, a simulation) |
| `UPD-AVAILABLE` | Low | Other updates are waiting |
| `UPD-REBOOT` | Medium/Low | A reboot is needed to finish installed updates |
| `UPD-STALE-LISTS` | Low | The package lists are more than a week old |

## Login attempts (`auth_logs`)

Reads the systemd journal (the last `login_days` days, default 7), or `/var/log/auth.log*`
when the journal is not available (for example on a mounted disk). "Many" means at least
`login_fail_threshold` (default 10).

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `AUTH-SSH-SUCCESS-AFTER-FAIL` | **Critical** | An address made 5 or more failed SSH attempts and then logged in |
| `AUTH-SSH-ROOT-PASSWORD` | High | root logged in over SSH with a password |
| `AUTH-SSH-BRUTEFORCE` | Medium | Many failed SSH logins from one address |
| `AUTH-SSH-FAILED` | Low | A few failed SSH logins (all addresses in one finding) |
| `AUTH-SSH-INVALID-USER` | Medium/Low | SSH attempts with user names that do not exist |
| `AUTH-SUDO-FAILED` | Medium/Low | Wrong sudo password |
| `AUTH-SUDO-DENIED` | Medium | A user who may not use sudo (for that command) tried to |
| `AUTH-SU-FAILED` | Medium/Low | Wrong password with `su` |
| `AUTH-LOCAL-FAILED` | Medium/Low | Wrong password at the console, desktop login, screen lock or password dialog |

## Baseline comparison (`baseline`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `BASE-SUID-NEW` | **Critical** | A new SUID/SGID file since the baseline (Low when apt installed it and it matches the package) |
| `BASE-SUID-CHANGED` | Critical/Medium | A SUID/SGID file changed. Not reported when verified as an apt upgrade; Medium if it matches its package but apt did not touch it; Critical if it differs or no package owns it |
| `BASE-SUID-PERMS` / `-REMOVED` | High/Low | Changed permissions / file gone |
| `BASE-LISTEN-NEW` | High/Medium | A new listening port (random ports of known programs are ignored) |
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
| `EXT-CHKROOTKIT-INFECTED` / `-WARN` / `-WTMP` | Critical–Low | chkrootkit findings (a login-record gap is Low) |
| `EXT-RKHUNTER-WARN` / `-KNOWN` | High–Low | rkhunter warnings; known Debian false alarms are Low with a command to silence them |
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
