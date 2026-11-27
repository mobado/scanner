# Changelog

## 0.12.0
* New level **Info** for ordinary desktop activity: one line each, never changes the verdict,
  hidden in the window until switched on. Findings about your own files are marked user level.
* Every finding about a process or file says parent process, user, package and time.
* Desktop: automatic login, lingering users, remote and root sessions, weakened KDE screen
  lock, open X servers, KDE's X11 key access, programs that type for you, the input group,
  menu entries in home folders.
* Sound and screen: PipeWire/WirePlumber commands and network audio, programs recording,
  camera and microphone devices, portal permissions.
* Keys: GnuPG helper programs, PKCS#11 and p11-kit libraries, libraries loaded into key
  programs, who answers as the password wallet and desktop portal.
* Network: services that should only listen locally (debuggers, databases, AI and development
  servers), LLMNR, separate routing tables.
* Containers: Podman Quadlets, rootless sockets and the Podman API; scripts in `~/bin`.
* Debian: merged `/usr` links, hand-made diversions, apt download settings and signing keys,
  kernel installation hooks, unified kernel images.
* Baseline: new browser add-ons.

## 0.11.1
Fewer false alarms:
* KDE screen lock: the password box closing after a fingerprint or smart card unlock is no
  longer counted as a failed login.
* rkhunter "file properties have changed": files that match their package and were updated by
  apt become one Low finding; files that do not match are High.
* Lynis "apt-get check failed" is tried again; Low when the package system is fine.
* Journal files set aside after an unclean shutdown are Low.
* The same gap in the login records is reported once.
* AppArmor profiles shipped in complain mode and systemd's own eBPF filter are no longer listed.

Publishing: releases were missing because tags without a message were not pushed. The publish
script now sends the version tag by name, and GitHub also releases a new version when only
`main` is pushed.

## 0.11.0
* Password stores: programs other than the browser or wallet that have saved passwords,
  cookies or wallet files open.
* Keys and logins that other users can read (`~/.ssh`, `~/.gnupg`, cloud, Kubernetes, GitHub,
  Docker and package tokens, `.netrc`, `.env`).
* Environment variables that load code, in running programs and in environment files; SSH agent
  sockets in unusual places; tokens carried by programs (names only).
* Password wallet: the full scan listens 15 s for programs asking the Secret Service or
  KWallet for secrets (`--watch-wallet SECS`, setting `wallet_watch_secs`).
* io_uring in programs outside the system folders; user, network and mount namespaces that no
  known sandbox explains.
* Hardware: USB devices that are both keyboard and drive (now and in the kernel log),
  Thunderbolt security and devices; raw packet sockets that read all traffic.
* Browser helper scripts with break-in commands are Critical; helper descriptions are recorded.
* Baseline: new USB keyboards and Thunderbolt devices.

## 0.10.0
* Desktop apps: running remote desktop programs, KDE unattended screen sharing and screen lock,
  Flatpak permissions and sources, unsigned and classic snaps, AppImages, Hyprland plugins,
  files and icons on the desktop, services created on the fly.
* Browsers: native messaging hosts, replaced search engine, unfamiliar DNS-over-HTTPS server.
* Network: Bluetooth keyboards and visibility, shared folders, DNS settings and VPN leaks,
  SSH agent forwarding, who can reach each port; a script's server on this computer only is
  Low instead of a bind shell.
* Shells and download tools started by browsers or document viewers.
* Integrity: kernel start options, GRUB scripts, the kernel file against its package, disk
  errors, logins near time jumps. AppArmor and SELinux.
* Logins and updates: pkexec and polkit approvals and failures, missing security source, old
  sources, processor microcode, firmware updates.
* Baseline: new SSH keys (Critical), new Bluetooth devices, AppArmor switched off. A program
  deleted while running from a temporary folder is Critical.
* New setting `remote_desktop_programs`.

## 0.9.1
* `--screenshot` also works when the screen is locked or the window cannot be painted: after
  20 seconds the same content is drawn without a screen and saved.

## 0.9.0
* New module `desktop_session`: all desktop checks (autostart, session and login-screen
  scripts, D-Bus services, portals, KDE, GNOME, XFCE, window managers, keyboard readers,
  Wayland/X11) are gathered there, with titles labelled `[xdg]`, `[kde]`, `[gnome]` and so on.
  Findings you hid earlier stay hidden. `persistence` keeps network and sleep scripts and
  polkit rules.
* Servers without a graphical desktop skip the desktop checks; the baseline reports a desktop
  that appears (`BASE-DESKTOP-NEW`).
* A new or changed desktop startup file in a home folder is a Medium difference from the
  baseline (system files stay High).
* The baseline now needs `desktop_session` too; older automatic baselines are completed after
  the next clean root scan.

## 0.8.0
* Autostart: more system folders, programs that no package installed, and user entries that
  replace system entries.
* All desktops: session D-Bus services, portals, `xhost +`.
* KDE Plasma: saved session, notification actions (lock and login hooks), shortcuts, KWin
  scripts and window rules, proxy. GNOME: dconf settings (shortcuts, proxy, remote desktop,
  screen lock, extensions) and saved session. XFCE: session, shortcuts, panel and saved
  session. sway, i3, Hyprland, openbox, LXDE, labwc, wayfire, fluxbox and idle/lock daemons.
* Programs that read the keyboard directly, keyloggers; the report says whether a session is
  Wayland or X11.

## 0.7.0
* `--baseline-diff [FILE]` (and a checkbox in the window) shows only what changed since the
  baseline. The baseline now also records Secure Boot, lockdown and UEFI boot entries.
* Startup: systemd generators and drop-ins, `binfmt_misc`, git hooks, dpkg/pip/npm settings,
  initramfs hooks, unexplained files inside boot images and boot images rebuilt on their own.
* Processes and network: traced processes, mounts that hide processes or replace files, `ps`
  compared with `/proc`, undeclared tunnels and WireGuard peers, tunnel tools, reverse SSH,
  old-style iptables redirects.
* Kernel: eBPF programs, decoded taint marks, Secure Boot, lockdown, boot entries.
* Files: programs rewritten after installation, timestamps that do not fit, more system files
  (systemd, polkit, `pkexec`, libpam, libc) compared with their packages.
* New setting `tunnel_programs`.

## 0.6.0
* Desktop startup: XDG autostart is judged by what it runs, plus login, sleep and network
  scripts, login-screen settings and polkit rules (all part of the baseline).
* Home folders: downloads (programs, disguised files, suspicious scripts), hidden programs, and
  browser add-ons, proxy and remote-control settings, launchers and policies.
* Fewer false alarms on desktops: users' own services, scripts and cron jobs may point into
  their home folder; sockets under `/run/user` are normal; AppImages are Low; high CPU needs an
  hour for installed programs and skips browsers, compilers and indexers; more cloud sync, music,
  Bluetooth and printing programs are trusted; link-local listeners are not reported.
* `chkrootkit` and `rkhunter` findings are a second opinion: at most High and Medium.
* Login messages say where it happened (display manager, screen lock …); refused `pkexec`.
* New settings `high_cpu_minutes`, `cpu_heavy_programs`, `download_dirs`.

## 0.5.0
* Files: executable programs in temporary folders (also when `/tmp` is held in memory, including
  SUID files there), file capabilities, locked (immutable) files, SUID shells and interpreters,
  and system programs and PAM modules compared with their package checksums.
* Processes: long-running high CPU use, `LD_LIBRARY_PATH` into temporary folders.
* Persistence: apt software sources (unsigned, outside Debian) and apt hooks, suspicious
  commands in shell histories, accounts or groups that share an ID or name. The apt files are
  part of the baseline.
* Logins and network: SSH logins from the internet, firewall port forwarding.
* New settings `allowed_capability_files`, `trusted_apt_hosts`, `high_cpu_percent`.

## 0.4.2
* The log checks look back four weeks (28 days) and no further, for the journal and for
  `auth.log`/`syslog` files. The setting is now called `log_days` (it replaces `login_days`).

## 0.4.1
* Fixed: the scan seemed to hang at *Logs and clock*. Verifying the whole system journal (which
  can take minutes) now runs only in the full scan, stops after `journal_verify_secs` (90 s) and
  says so while it runs. Large log files are only read at the end.

## 0.4.0
* Network: unusual outgoing connections, direct DNS (tunnelling), unknown resolvers,
  `/etc/hosts` redirects, ARP duplicates, default routes, promiscuous interfaces.
* New **Kernel and modules** check: hidden/rootkit/out-of-tree modules, dangerous sysctls,
  modprobe commands.
* New **Web files and containers** check: web shells, container socket/API, privileged containers.
* New **Logs and clock** check: silenced/empty logs, login records, journal verification,
  clock and time jumps.
* Persistence: udev rules, `at` job contents, added certificate authorities, private key rights.
* Accounts: the baseline records accounts and powerful groups (new accounts, UID/shell/group/
  password changes); account creation and group additions are read from the logs.
* Quoted commands (`sh -c 'curl … | sh'`) are recognised.

## 0.3.4
* New check **Login attempts** (`auth_logs`): reads the journal (or `auth.log`) for SSH password
  guessing, unknown user names, a login that succeeded after many failures (Critical), root
  password logins, and wrong or refused sudo, su, console, desktop and screen-lock passwords.
  New settings `login_days` (7) and `login_fail_threshold` (10).

## 0.3.3
* The whitelist follows new versions: new default entries apply when the file is loaded and are
  written into it by `scanner --update-config` (run by the `.deb` on every install and upgrade).
  Own entries and comments are kept, a `.bak` copy is saved, and removed entries stay removed.
  `add_new_defaults = false` switches this off.

## 0.3.2
* Changed files are verified against apt: if the file matches its package and apt installed or
  upgraded that package after the baseline, it is no longer flagged (listed in the notes and taken
  into the automatic baseline). Everything else is still flagged, with what was checked.
* Lynis suggestions are listed; several changed documentation files from debsums are grouped.
* The *Scan again* button is removed – *Start scan* does the same thing.
* README, rule reference (`docs/CHECKS.md`) and changelog.

## 0.3.1
* A baseline made by an older version no longer gives High findings for kinds of files it did not
  track yet (`/etc/ld.so.conf*`); they are Low and added to the baseline automatically.
* Browsers and libvirt's dnsmasq are recognised as normal listeners; new ports of whitelisted
  programs are not "new since the baseline".

## 0.3.0
* **Automatic baseline**: saved by the scanner after the first clean complete scan as root and
  used automatically afterwards; completed automatically when it lacks a part. Not saved when the
  scan has critical/high findings.
* **Pending updates** check (security updates, other updates, reboot needed, old package lists).
* **Full scan** runs everything including the deep PID scan (`--full`, and the window button).
* Verification commands that need root are shown with `sudo`.
* Ports of one program and the NFS client's sockets are grouped into one finding; several
  "updated on disk" programs become one restart finding.
* Known Debian false alarms handled (rkhunter, chkwtmp, `pam_wtmpdb`, `nvidia-modprobe`, …).
* New: `--summary` (one line for monitoring), `--html` / *Export HTML*, *Scan again*, `ld.so.conf`
  check, Lynis suggestions listed, manual page.
* The `.deb` enables the nightly timer on first install and runs it once to create the baseline.

## 0.2.0
* Debian package (`scripts/build-deb.sh`), menu entry and icon, nightly systemd timer.
* Window: plain-language verdict, clickable severity cards, list + detail view, *Hide this
  finding* / *Trust all ports of …* saved in the whitelist, port ranges and trusted programs.
* GitHub Actions: build, tests, static binary, self-test; a version tag builds the `.deb`.
* Everything in English.

## 0.1.0
* First version: four modules (`net_proc`, `proc_audit`, `fs_perms`, `persistence`), external
  tools (debsums, chkrootkit, rkhunter, lynis), baselines, JSON and text reports, window and CLI,
  sandbox self-test, integration tests.
