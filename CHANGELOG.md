# Changelog

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
