# scanner – read-only intrusion and backdoor scanner for Debian 13 ("Trixie")

[![CI](https://github.com/mobado/scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/mobado/scanner/actions/workflows/ci.yml)

`scanner` looks for signs of intrusion, backdoors and persistence mechanisms on
Debian 13. It is **strictly read-only**: it reads `/proc`, `/etc`, systemd files and
the file system, but never changes, stops or removes anything. The only files it
writes are reports and baselines you ask for (`--output`, `--baseline-save`, the
export buttons).

## What it checks

| Module | Looks for |
|--------|-----------|
| `net_proc` | Reverse/bind shells, unknown listening ports (mapped to PID, UID and command line), unusual outgoing connections, direct DNS, resolvers and `/etc/hosts`, ARP/routing anomalies, sniffing (promiscuous cards and raw packet sockets), port forwarding, undeclared tunnels, tunnel tools and reverse SSH, hidden processes, disguised process names, Bluetooth, shared folders, DNS settings and VPN leaks, local-only services open to the network, LLMNR, separate routing tables, whether a firewall (nftables or iptables-legacy) refuses incoming connections and which addresses it lets in |
| `kernel` | Hidden, rootkit or out-of-tree modules, dangerous kernel settings (`core_pattern`, `modprobe`), modprobe commands, eBPF programs, taint marks, Secure Boot, lockdown and UEFI boot entries, AppArmor and SELinux, USB devices that are both keyboard and drive, Thunderbolt devices |
| `services` | Web shells in web folders, container socket and Docker API exposure, privileged containers, rootless sockets and the Podman API |
| `integrity` | Cleared or silenced logs, damaged login records, journal verification, clock and time jumps, kernel start options, GRUB scripts, the kernel file against its package, disk errors, shim and GRUB on the EFI partition |
| `proc_audit` | Programs running from `/tmp`, `/dev/shm`, deleted from disk or from memory, `LD_PRELOAD`, `LD_LIBRARY_PATH`, long-running high CPU use (miners), traced processes, mounts that hide or replace files, shells and download tools started by browsers or document viewers, other programs holding saved passwords, cookies or wallets open, environment variables that load code, who asks the password wallet (listens briefly), SSH agent sockets, tokens in environments, io_uring and unexplained namespaces, libraries loaded into key programs, who answers as the wallet and desktop portal, root-like capabilities, proxy variables |
| `fs_perms` | SUID/SGID files, file capabilities, locked (immutable) files, programs in temporary folders, replaced system programs and PAM modules, dangerous permissions, downloads and hidden programs in home folders, browser add-ons, settings and helper programs (native messaging), private keys, logins and `.env` files that others can read, rewritten programs and backdated files, the merged /usr links and diversions |
| `persistence` | systemd units and timers (system and user), cron, `at`, udev rules, `rc.local`, `ld.so.preload`/`ld.so.conf`, SSH keys (all home folders) and `sshd_config`, TLS keys and added CAs, PAM, shell files, accounts, groups and sudoers, apt software sources and hooks, shell command histories, network and sleep scripts, polkit rules, systemd generators and drop-ins, binfmt_misc, git hooks, dpkg/pip/npm settings, environment files that load code, the boot image (initramfs), kernel hooks and unified kernel images, Podman Quadlets, GnuPG helpers and PKCS#11 libraries, apt settings and signing keys, Python startup files, login and rotation scripts, proxies, files of no package in system folders, local packages, editor plugins (Vim, Neovim, VS Code, JetBrains) and project tasks that run when a folder is opened |
| `desktop_session` | Autostart, session and login-screen scripts, session D-Bus services and portals, settings of KDE Plasma, GNOME, XFCE and window managers, programs reading the keyboard, remote desktop programs, Flatpak, Snap and AppImage, Wayland or X11, automatic login and sessions, open X servers, typing tools, menu entries, PipeWire, recording, camera and microphone, portal permissions, programs that open links and files. Findings are labelled `[xdg]`, `[kde]`, `[gnome]` …; skipped on servers without a desktop |
| `updates` | Pending security updates, other updates, reboot needed, old package lists, missing security source, processor microcode and firmware updates |
| `auth_logs` | Failed logins in the journal (only lines from the programs that write them) / `auth.log`: SSH guessing, unknown users, a success after many failures, logins from the internet, wrong sudo/su/desktop passwords, pkexec and polkit approvals, forged-looking lines |
| external tools | `debsums` and `lynis` (if installed) |

Every rule is listed in [docs/CHECKS.md](docs/CHECKS.md). What changed between versions is in
[CHANGELOG.md](CHANGELOG.md).

The same code comes in two forms:

| Form | Build | Use |
|------|-------|-----|
| Window + CLI | `cargo build --release` | Opens a window when a screen is available, otherwise terminal mode |
| Static CLI binary | `scripts/build-static.sh` | A single file without dependencies for servers and the systemd timer |

## Architecture

```
src/
├── lib.rs              the library (all detection)
├── main.rs             CLI with clap (+ the window with the "gui" feature)
├── gui.rs              the window (eframe/egui) and the sudo password window
├── offscreen.rs        draws the window's picture without a screen (--screenshot when locked)
├── elevate.rs          asks for the sudo password and restarts as root
├── finding.rs          Finding { severity, module, rule, title, evidence, description, verify }
├── display.rs          control and direction characters written out before anything is shown
├── error.rs            ScanError (thiserror); anyhow is only used in main
├── config.rs           whitelist in TOML/JSON with Debian 13 defaults
├── sys.rs              all file access goes through a selectable root (/ or a test directory)
├── procinfo.rs         reads /proc/<pid>/{stat,status,cmdline,exe,fd,environ}
├── modules/
│   ├── net_proc.rs     /proc/net/{tcp,tcp6,udp,udp6} ↔ socket inodes ↔ PID/UID/command line,
│   │                   reverse/bind shells, ss comparison, hidden PIDs, disguised names
│   ├── proc_audit.rs   run paths in /tmp,/var/tmp,/dev/shm,/run, "(deleted)", memfd, LD_PRELOAD
│   ├── fs_perms.rs     SUID/SGID (0o4000/0o2000) on local file systems (st_dev), dangerous permissions
│   ├── filemarks.rs    capabilities, immutable files, programs in temp folders, system program checksums
│   ├── homefiles.rs    download folder, ~/.local/bin, hidden programs in home folders
│   ├── browsers.rs     Firefox and Chromium-family add-ons, settings, launchers, policies
│   ├── procwatch.rs    traced processes, mounts that hide or replace files
│   ├── tunnels.rs      tunnel interfaces, WireGuard peers, tunnel tools, reverse SSH
│   ├── kernelstate.rs  eBPF, taint marks, Secure Boot, lockdown, UEFI boot entries, AppArmor
│   ├── netlocal.rs     Bluetooth, shared folders, DNS settings, DNS around a VPN
│   ├── secrets.rs      open password stores, readable keys, environment variables
│   ├── sandboxes.rs    io_uring, namespaces no known sandbox explains
│   ├── wallet.rs       listens for programs asking the password wallet
│   ├── hardware.rs     USB keyboard-and-drive devices, Thunderbolt
│   ├── bootchain.rs    kernel start options, GRUB scripts, kernel file, disk errors
│   ├── debianfs.rs     merged /usr links, diversions
│   ├── firewall.rs     whether incoming connections are refused, odd allow rules
│   ├── journal.rs      login messages in the journal, only from the programs that write them
│   ├── procrights.rs   root-like capabilities of running programs
│   ├── desktop_session/    the desktop module (labels, server detection)
│   │   ├── xdg.rs      autostart, session and login-screen scripts
│   │   ├── environments.rs  D-Bus services, portals, KDE, GNOME, XFCE and window managers
│   │   ├── gvdb.rs     reader for GNOME's dconf settings database
│   │   ├── input.rs    keyboard readers, Wayland or X11
│   │   ├── session.rs  automatic login, sessions, open X servers, typing tools
│   │   └── media.rs    PipeWire, recording, camera and microphone, portal permissions
│   ├── persistence.rs  systemd units and timers, cron, at, rc.local, ld.so.preload
│   │   ├── keys.rs     GnuPG programs, PKCS#11 libraries
│   │   ├── python.rs   .pth, sitecustomize, usercustomize
│   │   ├── startup.rs  login and rotation scripts, proxies, files of no package
│   │   ├── editors.rs  Vim, Neovim and VS Code plugins
│   │   ├── packages.rs packages no software source offers
│   │   ├── ssh.rs      sshd_config (with Include) and authorized_keys
│   │   ├── system.rs   PAM, shell files, UID 0, shared IDs, sudo NOPASSWD
│   │   ├── rules.rs    network and sleep scripts, polkit rules
│   │   ├── hooks.rs    systemd generators/drop-ins, binfmt, git and installer hooks, initramfs
│   │   ├── apt.rs      software sources (.list and .sources) and apt hooks
│   │   └── history.rs  suspicious commands in shell histories
│   └── common.rs       assessment of command lines (base64, /dev/tcp, curl|sh, nc -e …)
├── external_tools.rs   debsums -c and lynis; tools only from system folders, with a timeout
├── trust.rs            only root may be able to change sudo, what runs as root and its whitelist
├── saving.rs           root writes only where root alone can; elsewhere as the person
├── baseline.rs         baseline in JSON and diff (new SUID/SGID files = Critical)
├── autobaseline.rs     the automatic baseline: save, complete, take in verified upgrades
├── pkgverify.rs        was a changed file changed by apt? (dpkg checksums + dpkg.log)
├── second_look.rs      runs Lynis' failed package check again
├── context.rs          Info level, user level, who and which package behind a finding
├── report.rs           sorted final report (Critical first), verdict, JSON and readable text
├── html.rs             self-contained HTML report
├── scan.rs             orchestration (run_scan, run_scan_auto)
└── sandbox.rs          safe self-test in a temporary directory
tests/integration_test.rs   tests with made-up /proc and systemd files (tempfile)
packaging/              systemd service + timer, example whitelist, deb/ (control files, man page, icon)
scripts/                static build, .deb build, publish to GitHub, test in a disposable VM
docs/CHECKS.md         every rule and what it means
.github/workflows/     CI: build, tests, static binary, .deb on version tags
```

The module list above also has `modules/net_group.rs` (groups per-port findings) and
`modules/updates.rs` (apt simulation, reboot needed).

No code uses `.unwrap()`: missing `/proc` files, processes that disappear mid-scan
and unreadable files become notes in the report, never a crash.

## Install on Debian 13 (.deb)

Download `scanner_<version>-1_amd64.deb` from the
[Releases page](https://github.com/mobado/scanner/releases) and install it:

```sh
sudo apt install ./scanner_0.19.1-1_amd64.deb
```

You then find **Scanner** in the application menu, `scanner` works in the terminal and
`man scanner` explains the options.
The package creates the whitelist `/etc/scanner/whitelist.toml` (and adds new default entries
to it on upgrades, keeping your changes) and
the nightly timer. On first installation the timer is switched on and runs once right
away: that first scan saves the **baseline of the machine by itself** (`/var/lib/scanner/baseline.json`),
and every later scan compares against it. You do not have to do anything.

Remove with `sudo apt remove scanner` (`sudo apt purge scanner` also removes baselines and reports).

### Build the .deb yourself

```sh
sh scripts/build-deb.sh          # → dist/scanner_<version>-1_amd64.deb
```

GitHub builds the package inside Debian 13, installs it, runs the self-test and puts it on
the Releases page – when a version tag (`v0.11.1` …) is pushed, or when `main` is pushed with
a version in `Cargo.toml` that has no release yet.

### Releasing a new version

```sh
# 1. bump `version` in Cargo.toml and add a section to CHANGELOG.md
cargo test && git commit -am "Release 0.12.0"
sh scripts/publish-to-github.sh        # tags the version, pushes it; CI builds the .deb
```

## Build

```sh
sudo apt install build-essential pkg-config libxkbcommon-dev libgl1-mesa-dev   # for the window
cargo build --release                       # window + CLI: target/release/scanner
scripts/build-static.sh                     # static CLI: target/static/.../scanner
sudo install -m 0755 target/static/x86_64-unknown-linux-gnu/release/scanner /usr/local/sbin/scanner
```

## Usage

```sh
scanner                                       # window (asks for the sudo password first)
scanner --cli                                 # readable report in the terminal
scanner --json --output report.json           # JSON to a file
scanner --modules net_proc,persistence        # only some modules
scanner --tools debsums,lynis                 # external tools too ("all" = both)
scanner --deep-pid-scan                       # walk the whole PID range for hidden processes
scanner --watch-wallet 60                     # listen 60 s for programs asking the password wallet
scanner --min-severity high                   # only high and critical
scanner --min-severity low                    # leave out the Info lines (ordinary activity)
scanner --html --output report.html          # a self-contained, colourful report page
scanner --summary                             # one line: OK / NOTICE / ATTENTION / ALARM (for monitoring)
scanner --full                                # everything: all modules, deep PID scan, all tools
scanner --list-tools                          # which external tools are installed?
scanner --print-config                        # print the default whitelist
scanner --self-test                           # safe self-test in a sandbox
scanner --root /mnt/disk --cli                # scan a mounted disk (e.g. from a rescue system)
```

**sudo at start:** started as a normal user, the program asks for your sudo password
(in a small window, or in the terminal in terminal mode) and restarts itself with
sudo. If you cancel, it runs without root, and the *Restart with sudo* button in the
window asks again. `--no-sudo` (or `SCANNER_NO_SUDO=1`) turns the question off.

Before asking for a password the program checks two things, and runs without root
(telling you why) if either fails:

- sudo is `/usr/bin/sudo` and nothing else: owned by root, set-uid, and not writable
  by others. A `sudo` found in `$PATH`, such as one in `~/.local/bin`, is never used.
- only root can change the scanner itself and every folder above it, so no other
  program of yours can swap it and get root next time. The `.deb` package
  (`/usr/bin/scanner`) and the `install` line above meet this; a copy run from
  `target/release/` or a download folder does not.

External tools (`ss`, `journalctl`, `debsums` and the others) are only taken from
`/usr/sbin`, `/usr/bin`, `/sbin` and `/bin`, also in a scan without root, and `$PATH`
is set to those folders when the program starts.

**What root writes and obeys:**

- Reports, baselines, pictures and whitelists are written as root only where root alone
  can change the whole path (such as `/var/log/scanner`). Anywhere else, such as your
  home folder or `/tmp`, a link planted there could point at `/etc/passwd`, so the file is
  written by a child process that has dropped to your user first: it belongs to you, and
  the kernel's ordinary permissions apply. Your user is the one who ran `sudo`, otherwise
  the owner of the folder. An old file there that belongs to root is not overwritten;
  remove it first.
- As root a whitelist is only read if nobody but root can change it. If
  `/etc/scanner/whitelist.toml` is missing, your personal one is left alone (the defaults
  are used, with a warning), and `--config` with such a file is an error. Check what it
  says, then install it: `sudo install -m 0644 my.toml /etc/scanner/whitelist.toml`.
- The same goes for a baseline: whatever it lists counts as having been there all along,
  so as root `--baseline-compare`, `--baseline-diff` and *Compare with* in the window
  refuse a file that others can change. Keep baselines in `/var/lib/scanner/`.

`sh scripts/root-write-test.sh target/release/scanner` tries these attacks in a private
user namespace, without real root.

**Exit codes:** `0` no high/critical findings · `1` at least one high · `2` at least one critical · `3` error.

Every finding has *evidence* (paths, command lines, file lines) and *concrete
commands for manual verification*, e.g. `ls -l /proc/1234/exe`, `dpkg -S`,
`debsums -s`, `systemctl cat`, `ssh-keygen -lf`.

## In the window

* **Verdict** at the top: a plain-language conclusion (no signs of intrusion / worth a
  look / should be checked / possible intrusion). The text report has the same `VERDICT:` line.
* **Summary cards**: click a severity to show only those findings (click again for all).
  *Info* (ordinary activity) is hidden until you click it.
* **Findings**: a compact list on the left and the selected finding on the right – what it
  means, the evidence and the commands to check it yourself, each with a *Copy* button.
* **Hide what is fine on your machine**: *Hide this finding*, *Trust all ports of …*
  (listening ports of a program installed under `/usr`) or *Hide every … finding*.
  The choice is saved in the whitelist – `/etc/scanner/whitelist.toml` when running as
  root (also used by the nightly timer), otherwise `~/.config/scanner/whitelist.toml` –
  and *Show hidden findings again* undoes it.
* **Full scan + save report** runs everything (all modules, the deep PID scan and every
  installed tool) and saves the report as JSON and text.
* **Export** as text, JSON or a self-contained **HTML** page.
* The **Baseline** box shows whether the automatic baseline is in use; *Save baseline* replaces
  it with the latest scan (for example after updates).

Run as **root** – otherwise the scanner cannot read other users' processes,
`/var/spool/cron/crontabs`, `/root/.ssh` or `/sys/kernel/debug/sched/debug`.
What was skipped is listed under *Notes*.

## Whitelist (fewer false alarms)

```sh
sudo mkdir -p /etc/scanner
scanner --print-config | sudo tee /etc/scanner/whitelist.toml
```

`/etc/scanner/whitelist.toml` is read automatically if it exists, otherwise
`~/.config/scanner/whitelist.toml` (or pass `--config`). As root only a whitelist that
nobody but root can change is read, so a personal one is not used then.

**The whitelist follows new versions.** New default entries (a newly recognised harmless
program, a new PAM module …) apply as soon as the newer program loads your file, and
`scanner --update-config [FILE]` writes them into it (the `.deb` does this on every install
and upgrade). Your own entries, settings and comments are kept, the previous file is saved as
`whitelist.toml.bak`, and entries you remove stay removed (remembered in
`whitelist.defaults.json`). Set `add_new_defaults = false` to use exactly your own lists.
Important fields: `allowed_listen_ports` (`"tcp/22"` or a range `"udp/1714-1764"`),
`allowed_listen_processes` (trusted programs under `/usr`, by the name of the program file;
never an interpreter), `allowed_suid` (supports `*`),
`allowed_capability_files`, `trusted_apt_hosts`, `high_cpu_percent` (0 = off),
`high_cpu_minutes`, `cpu_heavy_programs`, `download_dirs`, `tunnel_programs`, `remote_desktop_programs`,
`allowed_systemd_units`, `allowed_cron_files`, `allowed_ssh_key_comments`,
`allowed_ld_preload`, `allowed_argv0_mismatch`, `fs_exclude_paths`,
`log_days` (how far back the log checks look, 28) and `login_fail_threshold` (login check), `common_remote_ports`,
`trusted_resolvers`, `allowed_out_of_tree_modules`, `known_rootkit_modules`, `web_roots`,
`ignore_rules` (rule ids), `ignore_findings` (single findings hidden in the window)
and `ignore_evidence_containing`.

On GitHub, every push runs the tests, builds the static binary and runs the self-test;
the static binary can be downloaded from the run's *Artifacts*.

## The automatic baseline

**A baseline from a freshly installed, trusted computer helps the most**, above all on a
desktop, where your own files and apps give much ordinary noise: later scans then point at what
changed. A new SSH key is *Critical*; a new file in a download folder is *Low*.

The scanner makes the baseline itself: the first complete scan **as root** (all five core
modules, `desktop_session` included) saves `/var/lib/scanner/baseline.json` (folder mode 0700), and every later scan,
in the window, on the command line and from the nightly timer, compares against it
automatically. New SUID/SGID files since then are *Critical*.

* It is **not** saved when the first scan has critical or high findings – a baseline taken
  on a compromised system would make the intrusion look normal. Check the findings, then
  use *Save baseline* in the window (or `--baseline-save`).
* **apt upgrades are checked automatically.** For every changed or new SUID/persistence file the
  scanner looks up the owning package in dpkg's records, compares the file with the package's
  checksum, and checks `/var/log/dpkg.log` for an install/upgrade after the baseline. Verified
  upgrades are **not flagged** (they are listed under *Notes* and added to the baseline). Files
  that do not match their package, that no package owns, or that apt did not touch (for example
  a SUID bit set by hand) are still flagged. A new SUID program installed by apt is shown as Low.
* `--no-auto-baseline` turns the automatic baseline off; `--baseline-compare FILE` compares
  with another file. As root it has to be a file only root can change:
  `sudo scanner --cli --baseline-save /var/lib/scanner/saved-before.json`, later
  `sudo scanner --cli --baseline-compare /var/lib/scanner/saved-before.json`. A baseline in
  your home folder is yours (also when saved with `sudo`), so root refuses it.

The steps below are the manual way, for a machine you want to verify more strictly:

```sh
# 1. Install the program and (optionally) the external tools
sudo apt install debsums lynis
sudo install -m 0755 scanner /usr/local/sbin/scanner
sudo mkdir -p /etc/scanner /var/lib/scanner /var/log/scanner
scanner --print-config | sudo tee /etc/scanner/whitelist.toml >/dev/null

# 2. Check that the package files are untouched and nothing is already wrong
sudo debsums -c                      # should print nothing
sudo scanner --cli --tools debsums   # review the findings, adjust the whitelist

# 3. Save the baseline (all modules must run for everything to be compared)
sudo scanner --cli --baseline-save /var/lib/scanner/baseline.json --output /var/log/scanner/first-report.txt

# 4. Protect the baseline: make it read-only and keep a copy off the machine
sudo chmod 0400 /var/lib/scanner/baseline.json
sha256sum /var/lib/scanner/baseline.json   # write the sum down somewhere else
```

After `apt upgrade` nothing needs to be done: verified upgrades are recognised (see above).

## Show only what changed

```sh
sudo scanner --baseline-diff                         # against the automatic baseline
sudo scanner --baseline-diff /var/lib/scanner/saved-before.json   # against one you saved there
scanner --no-sudo --baseline-diff my-baseline.json   # against your own file, without root
```

Only the differences are listed (new SUID files, new or changed services and startup files,
new users and groups, new listening ports, Secure Boot and boot entries), the exit code follows
them, and the baseline is not touched. In the window, tick *Only changes since the baseline*.

## Updates

The *Pending updates* check runs `apt-get -s upgrade` (a simulation – nothing is installed)
and reports **security updates** (Medium), other updates (Low), a needed **reboot**, and
package lists that are more than a week old. Install updates with
`sudo apt update && sudo apt upgrade`.

## Full scan

`scanner --full` (the window's *Full scan + save report* button) runs everything: all modules,
the deep PID scan and every installed external tool.

## Regular diff runs with a read-only systemd timer

```sh
sudo install -m 0644 packaging/scanner-diff.service packaging/scanner-diff.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now scanner-diff.timer
systemctl list-timers scanner-diff.timer
sudo systemctl start scanner-diff.service     # run once right away
journalctl -u scanner-diff.service
ls /var/log/scanner/
```

With the `.deb` all of this is already set up: the timer is enabled on first install and
the first run saves the baseline. The unit needs no baseline file to exist – the scanner makes
and uses it itself (`StateDirectory=scanner`, `LogsDirectory=scanner`), and runs with the deep PID scan.

The service runs with `ProtectSystem=strict` (the whole file system read-only except
`/var/lib/scanner` and `/var/log/scanner`), `ProtectHome=read-only`, `NoNewPrivileges=yes` and only these
capabilities: `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE` and `CAP_SYS_PTRACE` to read, `CAP_NET_ADMIN` to list
the firewall rules, and `CAP_SETUID`/`CAP_SETGID` to ask a person's session bus and sound server as that
person. Listing every eBPF program would also need `CAP_SYS_ADMIN`, nearly all of root, which is left out:
add it to `CapabilityBoundingSet` if you want it. A check that could not ask is listed in the notes as
**NOT CHECKED**, so that an empty check does not look like a clean one.
`PrivateTmp=no` is deliberate: otherwise the service would not see the real `/tmp`.
Critical findings give exit code 2 and the service is marked as failed – add
`OnFailure=` for e-mail or alerts.

## Testing

```sh
cargo test                     # unit and integration tests (mocked /proc and systemd files)
scanner --self-test            # builds a made-up system in a temporary directory, 36 rules
```

For a test against a real system, use a **disposable VM or container** with Debian 13:

```sh
sudo SCANNER=/usr/local/sbin/scanner sh scripts/sandbox-vm-test.sh --i-am-in-a-test-machine
```

The script saves a baseline, creates harmless test artefacts (a systemd service
pointing to `/tmp`, a cron file, a deleted running binary in `/tmp`, a SUID copy of
`/bin/true` and a python server on 127.0.0.1:31337), checks that the rules fire and
removes everything afterwards. It refuses to run without the flag and warns on physical hardware.

## Contributing and licence

Issues and pull requests are welcome at <https://github.com/mobado/scanner>. Please keep the
scanner **read-only** (it must never change the system), run `cargo test` and add a test with
made-up `/proc`/`/etc` files for every new rule. New false alarms are best fixed in the
default whitelist (`src/config.rs`) with a short comment on why the thing is normal.

Licensed under the **GNU General Public License v3.0** – see [LICENSE](LICENSE).

## Limitations

* A kernel rootkit can lie to every user-space program. The comparisons
  `ss` ↔ `/proc/net` and `sched_debug` ↔ `/proc` catch simpler variants; for full
  certainty, scan the disk from trusted boot media with `--root /mnt/disk`.
* `/sys/kernel/debug/sched/debug` needs root and a mounted debugfs.
* Shell histories are read to find suspicious commands. Matching lines appear in the report,
  so treat saved reports as private (a typed password could be on such a line).
* A scan is a short moment: the password wallet is only heard while the scanner listens (15 s in
  the full scan), and a program that read a password file and closed it again is not seen.
* lynis writes its own log and report in `/var/log` – the scanner itself writes nothing.
* The window version cannot be linked statically; the static binary is CLI-only.
