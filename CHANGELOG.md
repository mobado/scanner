# Changelog

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
