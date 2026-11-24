# scanner – read-only intrusion and backdoor scanner for Debian 13 ("Trixie")

[![CI](https://github.com/mobado/scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/mobado/scanner/actions/workflows/ci.yml)

`scanner` looks for signs of intrusion, backdoors and persistence mechanisms on
Debian 13. It is **strictly read-only**: it reads `/proc`, `/etc`, systemd files and
the file system, but never changes, stops or removes anything. The only files it
writes are reports and baselines you ask for (`--output`, `--baseline-save`, the
export buttons).

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
├── elevate.rs          asks for the sudo password and restarts as root
├── finding.rs          Finding { severity, module, rule, title, evidence, description, verify }
├── error.rs            ScanError (thiserror); anyhow is only used in main
├── config.rs           whitelist in TOML/JSON with Debian 13 defaults
├── sys.rs              all file access goes through a selectable root (/ or a test directory)
├── procinfo.rs         reads /proc/<pid>/{stat,status,cmdline,exe,fd,environ}
├── modules/
│   ├── net_proc.rs     /proc/net/{tcp,tcp6,udp,udp6} ↔ socket inodes ↔ PID/UID/command line,
│   │                   reverse/bind shells, ss comparison, hidden PIDs, disguised names
│   ├── proc_audit.rs   run paths in /tmp,/var/tmp,/dev/shm,/run, "(deleted)", memfd, LD_PRELOAD
│   ├── fs_perms.rs     SUID/SGID (0o4000/0o2000) on local file systems (st_dev), dangerous permissions
│   ├── persistence.rs  systemd units and timers, cron, at, rc.local, ld.so.preload
│   │   ├── ssh.rs      sshd_config (with Include) and authorized_keys
│   │   └── system.rs   PAM, shell files, XDG autostart, UID 0, sudo NOPASSWD
│   └── common.rs       assessment of command lines (base64, /dev/tcp, curl|sh, nc -e …)
├── external_tools.rs   debsums -c, chkrootkit, rkhunter, lynis (PATH check and timeout)
├── baseline.rs         baseline in JSON and diff (new SUID/SGID files = Critical)
├── report.rs           sorted final report (Critical first), JSON and readable text
├── scan.rs             orchestration
└── sandbox.rs          safe self-test in a temporary directory
tests/integration_test.rs   tests with made-up /proc and systemd files (tempfile)
packaging/              systemd service + timer, example whitelist
scripts/                static build, test in a disposable VM
```

No code uses `.unwrap()`: missing `/proc` files, processes that disappear mid-scan
and unreadable files become notes in the report, never a crash.

## Install on Debian 13 (.deb)

Download `scanner_<version>-1_amd64.deb` from the
[Releases page](https://github.com/mobado/scanner/releases) and install it:

```sh
sudo apt install ./scanner_0.2.0-1_amd64.deb
```

You then find **Scanner** in the application menu, and `scanner` works in the terminal.
The package installs the whitelist in `/etc/scanner/whitelist.toml` (kept on upgrades) and
the nightly timer. On first installation the timer is switched on and runs once right
away: that first scan saves the **baseline of the machine by itself** (`/var/lib/scanner/baseline.json`),
and every later scan compares against it. You do not have to do anything.

Remove with `sudo apt remove scanner` (`sudo apt purge scanner` also removes baselines and reports).

### Build the .deb yourself

```sh
sh scripts/build-deb.sh          # → dist/scanner_<version>-1_amd64.deb
```

On GitHub every version tag (`v0.2.0` …) builds the package inside Debian 13 and attaches it to the release.

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
scanner --tools debsums,chkrootkit            # external tools too ("all" = all four)
scanner --deep-pid-scan                       # walk the whole PID range for hidden processes
scanner --min-severity high                   # hide low/medium
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

**Exit codes:** `0` no high/critical findings · `1` at least one high · `2` at least one critical · `3` error.

Every finding has *evidence* (paths, command lines, file lines) and *concrete
commands for manual verification*, e.g. `ls -l /proc/1234/exe`, `dpkg -S`,
`debsums -s`, `systemctl cat`, `ssh-keygen -lf`.

## In the window

* **Verdict** at the top: a plain-language conclusion (no signs of intrusion / worth a
  look / should be checked / possible intrusion). The text report has the same `VERDICT:` line.
* **Summary cards**: click a severity to show only those findings (click again for all).
* **Findings**: a compact list on the left and the selected finding on the right – what it
  means, the evidence and the commands to check it yourself, each with a *Copy* button.
* **Hide what is fine on your machine**: *Hide this finding*, *Trust all ports of …*
  (listening ports of a program installed under `/usr`) or *Hide every … finding*.
  The choice is saved in the whitelist – `/etc/scanner/whitelist.toml` when running as
  root (also used by the nightly timer), otherwise `~/.config/scanner/whitelist.toml` –
  and *Show hidden findings again* undoes it.
* **Full scan + save report** runs everything and saves the report as JSON and text.

Run as **root** – otherwise the scanner cannot read other users' processes,
`/var/spool/cron/crontabs`, `/root/.ssh` or `/sys/kernel/debug/sched/debug`.
What was skipped is listed under *Notes*.

## Whitelist (fewer false alarms)

```sh
sudo mkdir -p /etc/scanner
scanner --print-config | sudo tee /etc/scanner/whitelist.toml
```

`/etc/scanner/whitelist.toml` is read automatically if it exists, otherwise
`~/.config/scanner/whitelist.toml` (or pass `--config`).
Important fields: `allowed_listen_ports` (`"tcp/22"` or a range `"udp/1714-1764"`),
`allowed_listen_processes` (trusted programs under `/usr`), `allowed_suid` (supports `*`),
`allowed_systemd_units`, `allowed_cron_files`, `allowed_ssh_key_comments`,
`allowed_ld_preload`, `allowed_argv0_mismatch`, `fs_exclude_paths`,
`ignore_rules` (rule ids), `ignore_findings` (single findings hidden in the window)
and `ignore_evidence_containing`.

On GitHub, every push runs the tests, builds the static binary and runs the self-test;
the static binary can be downloaded from the run's *Artifacts*.

## The automatic baseline

The scanner makes the baseline itself: the first complete scan **as root** (all four core
modules) saves `/var/lib/scanner/baseline.json` (folder mode 0700), and every later scan,
in the window, on the command line and from the nightly timer, compares against it
automatically. New SUID/SGID files since then are *Critical*.

* It is **not** saved when the first scan has critical or high findings – a baseline taken
  on a compromised system would make the intrusion look normal. Check the findings, then
  use *Save baseline* in the window (or `--baseline-save`).
* After package updates, changed SUID/persistence files are lowered to *Medium* with a note
  (the update itself is the likely reason); confirm with `debsums -s` and save a fresh
  baseline (*Save baseline*).
* `--no-auto-baseline` turns the automatic baseline off; `--baseline-compare FILE` compares
  with another file.

The steps below are the manual way, for a machine you want to verify more strictly:

```sh
# 1. Install the program and (optionally) the external tools
sudo apt install debsums chkrootkit rkhunter lynis
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

After `apt upgrade`, SUID binaries and configuration change legitimately. Then run
`sudo debsums -c` (should be empty) and save a **new** baseline.

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

The service runs with `ProtectSystem=strict` (the whole file system read-only except
`/var/log/scanner`), `ProtectHome=read-only`, `NoNewPrivileges=yes` and only the read
capabilities `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE` and `CAP_SYS_PTRACE`.
`PrivateTmp=no` is deliberate: otherwise the service would not see the real `/tmp`.
Critical findings give exit code 2 and the service is marked as failed – add
`OnFailure=` for e-mail or alerts.

## Testing

```sh
cargo test                     # unit and integration tests (mocked /proc and systemd files)
scanner --self-test            # builds a made-up system in a temporary directory, 28 rules
```

For a test against a real system, use a **disposable VM or container** with Debian 13:

```sh
sudo SCANNER=/usr/local/sbin/scanner sh scripts/sandbox-vm-test.sh --i-am-in-a-test-machine
```

The script saves a baseline, creates harmless test artefacts (a systemd service
pointing to `/tmp`, a cron file, a deleted running binary in `/tmp`, a SUID copy of
`/bin/true` and a python server on 127.0.0.1:31337), checks that the rules fire and
removes everything afterwards. It refuses to run without the flag and warns on physical hardware.

## Limitations

* A kernel rootkit can lie to every user-space program. The comparisons
  `ss` ↔ `/proc/net` and `sched_debug` ↔ `/proc` catch simpler variants; for full
  certainty, scan the disk from trusted boot media with `--root /mnt/disk`.
* `/sys/kernel/debug/sched/debug` needs root and a mounted debugfs.
* rkhunter and lynis write their own logs in `/var/log` – the scanner itself writes nothing.
* The window version cannot be linked statically; the static binary is CLI-only.
