# Changelog

## 0.19.3
* Chrome and browsers like it load the Widevine video module from the profile in the home
  folder, which 0.19.2 would have reported as Critical code in the process holding the cookies.
  It is now accepted at exactly that path, for that browser and user, and listed as
  `PROC-BROWSER-MODULE` (Info). Not yet tried on a computer where Chrome has downloaded it.
* A program whose memory maps cannot be read no longer counts as clean (its finding says it
  could not be checked); key programs that could not be read are listed as **NOT CHECKED**.
* Qt's `JITCode:` memory files are only accepted in installed programs known to compile QML,
  never for key programs or the password wallet.

## 0.19.2
* An installed program with foreign code in it no longer gets its exception in the sensitive
  checks (saved passwords and cookies, who answers as the wallet, keyboard readers, the virtual
  keyboard): code from a temporary or home folder, `/run/user` or memory. The finding weighs
  more and lists the code. Installed programs asking the wallet are reported then too.
* `PROC-KEY-LIBRARY` counts every executable mapping, not only files named `.so`, also from
  `/run/user` and `memfd`.
* New `KERN-PTRACE-SCOPE` (Low): `kernel.yama.ptrace_scope = 0` lets your programs write code
  into each other; set it to 1.

## 0.19.1
Programs were approved by names they choose themselves: `exec -a firefox sqlite3 …/cookies.sqlite`
or a Python script renaming itself passed as the browser, as the password wallet and more.
* Wherever a name earns an exception, only the program file now counts, never `comm` or
  `argv[0]`, and never an interpreter, shell or loader: saved passwords and cookies, who answers
  as the wallet or portal, keyboard readers, typing tools, camera and microphone, CPU use,
  root-like rights, packet sniffers, direct DNS, trusted listening ports (also in baseline
  comparisons), debuggers and Wine's server, sandboxes and namespaces, Steam, eBPF holders,
  OpenVPN and the renamed-process list.
* Chromium's `--type=` option explains a sandbox only for a program whose folder holds
  Chromium's files.
* Tools written in a script language (for example `solaar` or `input-remapper`) can no longer
  be recognised and may show up; hide the finding if it is yours.
* Without root, services whose program file cannot be read are listed as **NOT CHECKED**.
* `BASE-LISTEN-NEW` says how sockets without a readable program file are matched.

## 0.19.0
What others write can no longer pose as something else, and checks that fail say so.
* Login logs: anyone could add lines with `logger` to raise a Critical alarm, or flood the
  journal so that real lines were never read. Lines now count only when the journal's own
  fields show that the right program sent them, and each group of programs is read by itself.
  Others are listed in `AUTH-LOG-UNCONFIRMED` (Low). Findings from `auth.log` say that they
  may be forged. The suggested `journalctl` commands filter the same way.
* Control and direction characters in file names, command lines and process names are written
  out (`\x1b`, `‮`) in the terminal, the HTML and JSON reports, the window and copied text,
  so a name cannot erase its finding or run pasted text. Commands to copy quote such names
  with `$'…'`; quoting also works in fish now.
* A command in `BASE-LISTEN-NEW` put the program's own name into the shell unquoted.
* Random ports are only ignored for a program known by its full path, so a back door named
  like `kdeconnectd` is seen. Older baselines get the paths of installed programs after a clean
  scan as root.
* The nightly timer may now list the firewall rules (`CAP_NET_ADMIN`) and ask sessions and
  sound servers (`CAP_SETUID`, `CAP_SETGID`). Checks that could not ask (firewall, port
  forwarding, eBPF, session bus, portal, recording) say **NOT CHECKED** in the notes, and an
  unreadable firewall is no longer recorded as switched off.
* systemd units and drop-ins are also looked for in `system.control`, `user.control`,
  `/etc/xdg/systemd/user`, `/usr/local/lib/systemd/user`, `/usr/local/share/systemd/user`,
  `/run/systemd/user` and `/run/user/<uid>/systemd/user`.

## 0.18.5
* As root, a baseline that others can change is no longer used. Since 0.18.4 a baseline saved
  to your home folder with `sudo` belongs to you, so a program of yours could add its own
  service, package or firewall rule to it and a later comparison would take it as always
  there. `--baseline-compare`, `--baseline-diff` and *Compare with* in the window now refuse
  such a file and say how to keep one in `/var/lib/scanner/`; saving one elsewhere warns.
  The automatic baseline is not affected.
* `scripts/sandbox-vm-test.sh` works again: it keeps its files in a folder only root can change.

## 0.18.4
Another program of yours could get root through files the scanner saved as root:
* A link planted as `~/scanner-report.json` (or any report, baseline, screenshot or whitelist
  path) made root overwrite the file it pointed to, and the window then gave it to you, so
  `/etc/passwd` could be taken over. Root now writes only where root alone can change the whole
  path; everything else is written by a child process that has dropped to your user first, and
  nothing is handed over with `chown` any more.
* `--update-config` on a file in such a place runs entirely as that user.
* As root, a whitelist that others can change is no longer read (for example your personal one
  when `/etc/scanner/whitelist.toml` is missing): the defaults are used with a warning, and
  `--config` with such a file is an error.
* Files in your home folder that an older version left owned by root are not overwritten;
  remove them first.

## 0.18.3
Another program of yours could use the root question to steal your password or get root:
* sudo is only `/usr/bin/sudo`, checked to be owned by root, set-uid and not writable by others.
  A fake `sudo` in `~/.local/bin` (first in Debian's `PATH`) is never started.
* Root rights are only asked for when only root can change the scanner and every folder above
  it. A copy in `target/release/` or a download folder now runs without root and says why;
  install the `.deb` package.
* External tools (`ss`, `journalctl`, `debsums` …) are only taken from the system folders, also
  in scans without root, so a fake one cannot hide what it does. `PATH` is set to those folders.

## 0.18.2
* The Steam exceptions of 0.18.1 were too wide: Steam's folder can be written by any program of
  yours. Ports and connections are now Low (visible), only for `steam`/`steamwebhelper` started
  by Steam's main program; Steam's containers and games are listed as Low instead of hidden.
  A program that merely lies in Steam's folder gets no exception.
* `/proc/self/exe` is only accepted when the process shows `exe` or its own name, or is
  installed; a home program posing as another is reported again.
* The Python permission warning only mentions root for system folders; the package change
  warning explains what a moved or restored system looks like.

## 0.18.1
Fewer false alarms on a gaming desktop:
* Steam's helpers started as `/proc/self/exe` are no longer "disguised process names".
* The Steam Linux Runtime container (`srt-bwrap`, `pv-adverb`) and Steam's own browser sandbox
  explain their namespaces.
* Steam's game and Remote Play ports are Info.
* NVIDIA's kernel thread `vidmem lazy free` is known while the driver is loaded.
* `sshd_config` and other settings that still are what their package put there are no longer
  reported for keeping the package's date.
* A login attempt without a user name says "(none given)".

## 0.18.0
* Packages stay protected after updates: a new version that apt installed from a source (shown
  by its history, with dpkg's files untouched since) is written into the automatic baseline with
  its fingerprint. Other changes are reported (`BASE-PACKAGE-CHANGED`), including `.deb` files
  installed by hand.
* The package fingerprint also covers the debconf script (`config`) and `triggers`; older
  baselines are completed without false alarms.
* Python: others being able to write to Python's own folders, `.pth` or `sitecustomize` files is
  High (`PERS-PYTHON-WRITABLE`); access lists (`setfacl`) are read.
* The home folder search only skips caches, games and containers at their usual place; project
  folders with such names are searched.

## 0.17.0
* The home folder search reaches your projects first: package caches are skipped, ordinary
  folders come before hidden ones, and the hidden folders with Python environments are searched
  on their own.
* `PERS-PYTHON-PATH` now looks at who can write: a folder added by a `.pth` file, or one above
  it, that everyone, a group with other members or another user can change is High, wherever it
  is.
* Packages installed by the Debian installer or aptitude are recognised (`/var/log/installer/status`,
  `/var/log/aptitude*`), so they no longer show as local.
* The baseline keeps a fingerprint of dpkg's checksums and scripts for each package; a package
  that changed without a new version is reported (`BASE-PACKAGE-REPLACED`).

## 0.16.0
Fixes:
* A planted `.deb` could hide by naming a Debian maintainer. A package now only counts as an old
  Debian package (or old kernel) when apt's records show that apt installed it, and the baseline
  reports every package no source offers that was not installed in that version when it was made.
* Python: `.pth` files that only add folders are recorded too; `sitecustomize`/`usercustomize`
  are looked for in the added folders; a folder in `/tmp`, `/dev/shm` or another user's home is
  High (`PERS-PYTHON-PATH`).
* A GRUB (or fwupd) update that writes its boot file again is Info, not Medium.
* Docker and libvirt rules that only differ in container addresses or interface names no longer
  count as new firewall rules.

Improvements:
* Home folders are walked once per scan for Python environments, VS Code tasks, `.env` and proxy
  auto-config files.
* VS Code: the user's own `tasks.json` is checked; `task.allowAutomaticTasks: "on"` makes folder
  tasks High and is reported (`PERS-VSCODE-AUTOTASKS`).

## 0.15.0
Fixes:
* Firewall: a rule that lets an internet address in is flagged also when it names a port or a
  set; chains reached by `jump` count. `iptables-legacy` rules are read too, so they no longer
  give a false "No firewall". Every accept rule is kept in the baseline, and new ones are
  reported (`BASE-FIREWALL-RULE`).
* Python: a `.pth` line is only skipped when it is exactly what setuptools, virtualenv or
  coverage write; searching for words let obfuscated code through.
* Boot files: a `grubx64.efi` built by `grub-install` (without the signed GRUB package) is no
  longer reported as High; the baseline remembers it instead.
* Capabilities: rights a program holds but has switched off (`CapPrm`) count, and so does
  `cap_fowner`.
* Proxies: only this computer's exact names and addresses count as local
  (`localhost.evil.example` no longer does).
* Debian packages that the sources no longer carry (after an upgrade) are one Info line.
* Editors: lazy.nvim plugins and `vim.cmd("!…")` are checked; a folder named like an extension
  with another ending no longer hides.
* Searches that stop at a limit now say so in the notes. Two remaining Swedish messages are in
  English.

New checks:
* Kernel options: `systemd.debug_shell`, `lsm=` without AppArmor, `intel_iommu=off`,
  `amd_iommu=off`, `kgdboc=`, `kgdbwait`, `rd.shell`, `rd.break`, `break`; also in
  `/etc/default/grub.d/*.cfg` and `/etc/kernel/cmdline`.
* VS Code tasks that run when a project folder is opened.
* JetBrains plugins.
* Packed apt package lists (`.lz4`, `.gz`, `.xz` …).

## 0.14.1
* Fixed a false High alarm `NET-SS-MISMATCH` for short-lived sockets (for example a UDP socket on a
  random port): `/proc/net` was read well before `ss` ran. Now `/proc/net` is read just before and
  just after `ss`, and a port is only reported when it is missing in three comparisons in a row.
  Ports that differ only for a moment are mentioned in a note.

## 0.14.0
* `chkrootkit` and `rkhunter` are removed: the scanner no longer runs them or suggests them.
  The full scan runs `debsums` and `lynis`.

## 0.13.1
* Fixed a false High alarm: `/var/lib/dpkg/diversions` was only recorded by the file permission
  module, which the window's ordinary scan leaves out. That scan still marked the automatic
  baseline as up to date, so the next full scan reported the file as new. Files the baseline
  compares are now always recorded by `persistence`, and the baseline is only marked as updated
  after a scan with both `persistence` and `desktop_session`.

## 0.13.0
* Python code that runs at every start: `.pth` files, `sitecustomize.py`, `usercustomize.py`,
  also in virtual environments.
* Packages no software source offers, and versions newer than the sources.
* `/etc/update-motd.d` and logrotate scripts; `.path` and `.socket` triggers, also ones created
  on the fly; stronger check of `/etc/ssh/sshrc`.
* Proxy variables, curl, wget and git proxies, PAC files.
* Programs of no package in `/usr/lib` and other files of no package in `/etc/systemd`.
* MIME and link handlers; Vim, Neovim and VS Code-family plugins.
* Firewall: whether anything refuses incoming connections, and rules that let single internet
  addresses in.
* shim and GRUB on the EFI partition compared with their packages.
* Root-like capabilities of running programs.
* Baseline: new editor extensions, new local packages, firewall switched off.

## 0.12.1
* Fixed false alarms after upgrading from an older version: browser and mail key lists
  (`pkcs11.txt`) were reported as new High changes, and unchanged package files (kernel hooks,
  signing keys, p11-kit modules) as Medium. Package files are now checked, including links to
  them; other files unchanged since before the baseline become one Info line, and the
  baseline takes them in.
* A changed `pkcs11.txt` in a home folder is Medium.
* Accounts without a login made by packages and the kernel NFS client's sockets are Info.

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
