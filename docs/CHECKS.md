# What scanner checks

Every finding has a stable **rule id**. Use it in `ignore_rules` (whitelist) to switch a
whole rule off, or look it up here. Severities are the usual level; some rules go up or down
depending on the evidence (for example a binary deleted from `/usr` is Low, from `/home` High).

## Levels and context

| Level | Meaning |
|-------|---------|
| Critical / High | What was found is itself suspicious |
| Medium | It works, but changes what runs or who sees your data |
| Low | Worth a look |
| Info | Ordinary desktop activity, listed on one line each; it never changes the verdict. Hidden in the window until you switch it on (`--min-severity low` leaves it out of reports) |

* Findings about files in a home folder, Medium or lower, are marked **user level**: yours to
  review, not a change to the system.
* Low findings that are everyday life become Info, for example autostart entries for installed
  programs, own session scripts, AppImages, downloads that can run, administrator actions,
  busy programs, accounts without a login that packages create and the sockets of the kernel's
  NFS client; outgoing connections, listening ports and similar are Info when the program
  comes from a package.
* A finding about a process ends with a `context:` line: PID, parent, user, package and start
  time. A finding about a file says its package (for system folders) and when it changed.

## Network and hidden processes (`net_proc`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `NET-REVSHELL` | Critical | A shell or `nc`/`socat` with an established connection, or stdin/stdout tied to a socket |
| `NET-BINDSHELL` | Critical–Medium | A shell/interpreter that listens on a port |
| `NET-INTERP-CONN` | Medium/Low | A script interpreter with an outgoing connection |
| `NET-SUSP-PORT` | High | A connection to a typical backdoor port (4444, 1337, 31337 …) |
| `NET-TMP-SOCKET` | Critical | A program from `/tmp`, `/var/tmp`, `/dev/shm` or `/run` holds a network socket |
| `NET-DELETED-SOCKET` | Medium/Critical | A deleted binary holds a network socket |
| `NET-LISTEN-UNKNOWN` | Medium–Info | A listening port that is not in the whitelist (grouped per program). Info for the Steam client in a home folder on Steam's ports (27000–27100, 4380) |
| `NET-ORPHAN-LISTEN` | High/Low | A listening socket without any owner process (Low when the NFS client explains it) |
| `NET-SS-MISMATCH` | High | `ss` sees a listening port that `/proc/net` hides, in three comparisons in a row (short-lived sockets only get a note) |
| `NET-HIDDEN-PID` | High | A PID the scheduler knows but `/proc` does not list |
| `NET-KTHREAD-FAKE` | Critical | A normal process disguised as a kernel thread (`[kworker/…]`) |
| `NET-KTHREAD-NAME` | Low | A kernel thread with an unknown name (NVIDIA's `vidmem lazy free` is known while its driver is loaded) |
| `NET-ARGV0-MASK` | High/Medium | `argv[0]` does not match the real binary in `/proc/<pid>/exe` (`/proc/self/exe`, as Chromium, Electron and Steam start helpers, is no disguise) |
| `NET-OUTBOUND-UNUSUAL` | Medium–Info | An outgoing internet connection on a port that is not in `common_remote_ports`; Info for the Steam client in a home folder on Steam's ports |
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
| `NET-NO-FIREWALL` | Low/Info | Nothing refuses incoming connections: no `drop`/`reject` in the loaded nftables and `iptables-legacy` rules (root), or ufw, nftables and firewalld all off (Info without root). Lists the ports open to every network. The old tables are only asked for when they are loaded, so nothing is loaded into the kernel |
| `NET-FIREWALL-ALLOW` | Medium | A rule in an incoming chain (also one reached by `jump`) accepts connections from an address on the internet, with or without a port, also through a named set (root). Replies to your own connections do not count |
| `NET-LOCAL-EXPOSED` | High/Medium | A service meant for this computer listens to the network: debuggers (High), databases, AI model and agent (MCP) servers, development servers, sync and torrent control pages |
| `NET-LLMNR` | Info | Names are looked up by asking the local network (LLMNR, or mDNS by systemd-resolved) |
| `NET-ROUTE-TABLE` | Low | Routes in separate tables, which the ordinary route list does not show (Tailscale's and wg-quick's are only noted) |
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
| `KERN-EBPF` / `-PINNED` | Medium/Low | Loaded eBPF programs that can watch system calls or traffic (Medium when the holder is unfamiliar or none; systemd's own file system filter is not listed); pinned objects in `/sys/fs/bpf`. Complete with root and the `bpftool` package, otherwise only programs held by processes |
| `KERN-TAINTED` | High–Low | Why the kernel is "tainted", bit by bit; Medium when the module that caused it is no longer loaded, High after a forced removal |
| `KERN-SECUREBOOT` | Medium/Low | Secure Boot off, or on without kernel lockdown (with `sig_enforce` and `modules_disabled`) |
| `KERN-BOOT-ENTRY` | Low | UEFI boot entries that start another loader than Debian's, Windows' or the default one |
| `KERN-APPARMOR-OFF` / `-PROFILES` | Medium / Low | AppArmor is not active; profiles that only complain or are disabled (listing them needs root). Profiles an unchanged package file ships in complain mode are only counted in the notes |
| `KERN-SELINUX` | Medium | SELinux is in permissive mode |
| `KERN-USB-BADUSB` | High | A connected USB device is both a keyboard and a drive (BadUSB, Rubber Ducky) |
| `KERN-USB-HISTORY` | Medium | The kernel log (last `log_days` days, running system only) shows one USB port registering both |
| `KERN-THUNDERBOLT-OPEN` / `KERN-THUNDERBOLT` | Medium / Low | Thunderbolt security level `none` without IOMMU protection; approved Thunderbolt devices that are connected |

## Web files and containers (`services`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `SVC-WEBSHELL` | Critical/High | A script in a web folder (`web_roots`) that runs what a visitor sends |
| `SVC-CONTAINER-SOCKET` | Critical | The Docker/Podman/containerd socket (also a user's rootless one) is writable by everyone |
| `SVC-PODMAN-API` | High | Podman's control service listens on the network |
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
| `INT-BOOT-OPTIONS` | High–Low | Kernel options (running, `/etc/default/grub`, `grub.d/*.cfg`, `/etc/kernel/cmdline`, `grub.cfg`) such as `init=`, `apparmor=0`, `lsm=` without AppArmor, `systemd.debug_shell`, `kgdboc=`/`kgdbwait`, `break`/`rd.break`/`rd.shell`, `intel_iommu=off`/`amd_iommu=off`, `nokaslr`, `mitigations=off` |
| `INT-EFI-FILE` | High–Info | shim, GRUB, MokManager, fallback and fwupd files on the EFI partition compared byte for byte with the signed copies the packages installed. High when a newer file differs, Medium when it is older than the package (run `grub-install`), Low for the fallback `EFI/BOOT`. Without the signed GRUB package `grub-install` builds its own `grubx64.efi`; that is listed as Info and remembered in the baseline (`BASE-EFI-FILE-CHANGED`) |
| `INT-GRUB-SCRIPT` | Critical–Medium | An executable boot menu script that no package installed |
| `INT-KERNEL-FILE` | Critical/Low | `vmlinuz`/`System.map` differs from its package, or a kernel from no package |
| `INT-DISK-ERRORS` | Low | ext4 error counters and disk I/O errors in the kernel log, which can look like tampering |
| `INT-JOURNAL-CORRUPT` / `-VOLATILE` | Medium/Low | Journal fails verification (root, full scan only, at most `journal_verify_secs` = 90 s; Low when only the `.journal~` files journald set aside after an unclean shutdown are damaged) / not kept across reboots |
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
| `PROC-CAPABILITIES` | High–Low | A running program that is not root holds root-like capabilities (`CapEff`/`CapAmb`, and `CapPrm`, which it can switch on at any time: sys_admin, sys_ptrace, sys_module, dac_override, fowner, net_raw …). Known services, set-uid programs and sandboxes with a user namespace of their own are skipped; shells and programs from home or temporary folders are High |
| `PROC-ENV-PROXY` | Medium/Low | Running programs started with `http_proxy`/`https_proxy`/`all_proxy` (Low for a proxy on this computer; passwords are hidden) |
| `PROC-SECRET-SERVICE` | High/Medium | Another program than the usual one answers as the password wallet (`org.freedesktop.secrets`, KWallet) or as the desktop portal on the session bus |
| `PROC-KEY-LIBRARY` | High | SSH, GnuPG, sudo, OpenVPN or a wallet has loaded a library from a temporary or home folder |
| `PROC-SECRET-CALL` | Critical–Low | A program asked the password wallet (Secret Service, GNOME Keyring, KWallet) for secrets while the scanner listened: full scan (`wallet_watch_secs` = 15) or `--watch-wallet SECS`. Medium for scripts and command line tools, High/Critical from odd folders; installed programs are only named in the notes. Passwords never pass through the scanner (`dbus-monitor --profile` shows who asked for what) |
| `PROC-IO-URING` | High–Low | A program outside the system folders uses io_uring, which sidesteps system call monitoring |
| `PROC-NAMESPACE` | High/Medium | Processes in their own user, network or mount namespace that no known sandbox (Flatpak, bubblewrap, browsers, Electron apps, Steam and its Steam Linux Runtime), container, Snap or system service explains. A mount namespace alone only counts for programs in home or temporary folders |

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
| `FS-TIMESTAMP` | Medium/Low | Times that do not fit (timestomping): a modification time later than the change time, or a file from no package in `/usr/bin`, `/usr/sbin` or startup folders in `/etc` dated long before it last changed. A settings file that still is what its package put there (the checksum `ucf` recorded, or `sshd_config` equal to its template) keeps that date and is not listed |
| `FS-SYSTEM-UNPACKAGED` | High | A PAM module that no package installed |
| `FS-USRMERGE` | High | `/bin`, `/sbin`, `/lib` or `/lib64` is not the link into `/usr` that Debian 13 uses |
| `FS-DIVERSION` | Medium | A system program or library diverted by hand with `dpkg-divert` |
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
| `PERS-PYTHON-STARTUP` | High–Low | A `.pth` file with `import` lines, or `sitecustomize.py`/`usercustomize.py`, from no package or changed (system folders, `/usr/local`, `~/.local`, virtual environments). High when it runs text as code, starts programs or uses the network; a `.pth` file is only skipped when every code line is exactly what setuptools, editable installs, namespace packages, virtualenv or coverage write. `sitecustomize`/`usercustomize` (source, package or compiled) are also looked for in the folders that `.pth` files add. Every `.pth` file is recorded in the baseline |
| `PERS-PYTHON-PATH` | High | A `.pth` file adds a folder that others control (also through a link): in a temporary folder or another user's home, or where the folder or one above it is writable by everyone, writable by a group with other members, or owned by someone other than root and the owner of the `.pth` file (or of the home it lies in), also through an access list (`setfacl`). A sticky folder above an existing folder does not count |
| `PERS-PYTHON-WRITABLE` | High | Others can change what Python runs: a `site-packages`, `dist-packages` or version folder, a `.pth` file or a `sitecustomize`/`usercustomize` file (or a folder above) writable by everyone, by a group with other members or through an access list, or owned by someone other than root and the owner of the home it lies in |
| `PERS-MOTD` | Critical–Medium | A script in `/etc/update-motd.d` from no package or changed; it runs as root at every login |
| `PERS-LOGROTATE` | Critical–Low | A `postrotate`/`prerotate` script in a logrotate file from no package, changed, or with a suspicious command |
| `PERS-ENV-PROXY` | Medium/Low | A proxy set in environment files, `curlrc`, `wgetrc` or git settings (desktop, browser, apt and pip proxies have their own rules) |
| `PERS-PAC-FILE` | Low | Proxy auto-config files (`*.pac`, `wpad.dat`) in `/etc` or home folders |
| `PERS-SSH-RC` | Critical–Medium | `/etc/ssh/sshrc` or a user's `~/.ssh/rc` runs at every SSH login |
| `PERS-SYSTEMD-LOCAL` (triggers) | Medium/Low | Local `.path` and `.socket` units show what they wait for; Medium when enabled path triggers or sockets open to the network |
| `PERS-TRIGGER-UNIT` | Medium/Low | A path or socket unit created on the fly (`systemd-run`) |
| `PERS-UNOWNED-LIB` | High/Medium | Programs and libraries in `/usr/lib` that no package lists or ships (copies and links of packaged files are skipped; Python packages and kernel modules have other checks). High among PAM and systemd files or with hidden names |
| `PERS-UNOWNED-SYSTEM` | Medium/Low | Other files of no package in `/etc/systemd` (mount units, targets, scripts) |
| `PERS-LOCAL-PACKAGE` | Low | Installed packages that no software source offers (a `.deb` from a file, or a removed source); old Debian kernels are only noted. Packed package lists (`.lz4`, `.gz`, `.xz` …) are read with apt's `apt-helper` |
| `PERS-RETIRED-PACKAGE` | Info | Packages with a Debian maintainer (`debian.org` or a Debian team list) that the sources no longer carry **and that apt installed**: named in `/var/lib/apt/extended_states`, or with the same version in `/var/log/apt/history.log*` (from a command that names no `.deb` file), `/var/log/aptitude*` or the installer's `/var/log/installer/status`. One line. The maintainer is what the package says about itself, and `dpkg -i` writes in none of these. Old kernels need the same proof. A package apt installed more than a year ago, after the installation, may have no record left (logs are kept 12 months) and is then listed as local |
| `PERS-PKG-NEWER` | Medium/Low | A version newer than anything the sources offer (Medium for central system packages) |
| `PERS-EDITOR-SCRIPT` | High/Medium | A Vim or Neovim script (also lazy.nvim plugins, `vim.cmd("!…")`) that runs a command typical of a break-in |
| `PERS-EDITOR-EXTENSION` | Medium/Low | VS Code, VSCodium or Cursor extensions installed from a file, loaded from elsewhere, or in a folder the editor does not list (a folder must be the extension's id followed by its version) |
| `PERS-VSCODE-TASK` | High/Medium | A project's `.vscode/tasks.json`, or a user's own `tasks.json` (VS Code, VSCodium, Cursor, profiles), runs a task when a folder is opened (`runOn: folderOpen`); High when the command is typical of a break-in or `task.allowAutomaticTasks` is `"on"`. Recorded in the baseline |
| `PERS-VSCODE-AUTOTASKS` | Low | The user's settings run folder tasks without asking (`task.allowAutomaticTasks: "on"`) |
| `PERS-JETBRAINS-PLUGIN` | Info | Plugins added to IntelliJ, PyCharm and other JetBrains editors (`~/.local/share/JetBrains/*/`); new ones show as `BASE-EDITOR-NEW` |
| `PERS-KERNEL-HOOK` | Critical–Medium | A script in `/etc/kernel/*.d` or `initramfs/post-update.d` that no package installed; it runs as root at every kernel installation |
| `PERS-UKI` | Info | Unified kernel images on the EFI partition (recorded, so the baseline notices a change) |
| `PERS-QUADLET` | Critical–Info | A Podman Quadlet starts a container; Medium with host folders, host network or full privileges, higher with a suspicious command |
| `PERS-GPG-PROGRAM` | High/Medium | GnuPG is set to run a pinentry, smart card or other program from an odd place or from no package |
| `PERS-KEY-MODULE` | Critical–Medium | A PKCS#11 / p11-kit library (also in browser, SSH and OpenVPN settings) from an odd place or from no package, or a module that runs a command |
| `PERS-APT-CONFIG` | Medium/Low | apt accepts unsigned or old lists, skips certificate checks, or uses a proxy (passwords are not shown) |
| `PERS-APT-KEY` | Medium/Info | Signing keys from no package: trusted for every source (`trusted.gpg.d`), or only for the sources that name them |
| `PERS-TRANSIENT-UNIT` | Critical–Medium | A service created on the fly (`systemd-run`) with a suspicious command |
| `PERS-ENV-INJECT` | High–Low | `/etc/environment`, `environment.d`, `.pam_environment` or a shell start file sets a variable that loads code (as `PROC-ENV-INJECT`) |
| `PERS-SYSACCT-SHELL` / `PERS-EMPTY-PASSWORD` / `PERS-SUDO-NOPASSWD` | High–Low | Account and sudo settings |

## Desktop session (`desktop_session`)

Everything tied to a graphical session. Each title starts with a label: `[xdg]` (shared
standards), `[kde]`, `[gnome]`, `[xfce]`, `[wm]` (sway, i3 and other window managers),
`[login]` (login screen), `[x11]`, `[input]`, `[remote]`, `[media]` (sound, camera, screen),
`[portal]`, `[flatpak]`, `[snap]` and `[appimage]`.

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
| `PERS-MIME-HANDLER` | High–Info | `mimeapps.list` sends links or files to a menu entry of one's own (Medium for web, mail, folders, text and PDF; Info for app sign-in links) or to one with a suspicious command |
| `PERS-LAUNCHER` | Critical–Medium | A menu entry in a home folder with a suspicious command, one that starts something from a hidden, cache or download folder, or one that replaces an installed program's entry |
| `DESK-AUTOLOGIN` | Medium | SDDM, GDM, LightDM or greetd logs a user in by itself |
| `DESK-LINGER` | Low | Services of a user run without a login (lingering) |
| `DESK-SESSION-REMOTE` / `-ROOT` | Medium/Info | A graphical session from another computer, or a desktop running as root |
| `DESK-XSERVER-OPEN` | High | Xorg or Xwayland runs without access control or accepts network connections |
| `DESK-XWAYLAND-KEYS` | Medium/Low | KDE lets X11 programs see all typing, or the mouse, under Wayland |
| `DESK-INPUT-INJECT` | High–Low | A program that can type and click for you (`ydotool`, `wtype`, `xdotool`, holders of `/dev/uinput`) |
| `DESK-INPUT-GROUP` / `-OPEN` | Medium / High | Users in the `input` group; keyboard devices open to everyone |
| `DESK-AUDIO-EXEC` / `-NETWORK` / `-SCRIPT` / `-VIRTUAL` | High–Info | PipeWire/WirePlumber settings from no package that start programs, send audio over the network, run own scripts or add virtual devices |
| `DESK-RECORDING` | High–Info | A program is recording sound or video right now (`pw-dump`); High from an odd place, Medium for recording tools |
| `DESK-DEVICE-OPEN` | High–Info | A program holds the camera or microphone device itself |
| `DESK-PORTAL-GRANT` | Low/Info | Apps with a remembered permission to control or record the screen (Low), or to use camera, microphone, location or the background |
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
| `AUTH-LOCAL-FAILED` | Medium/Low | Wrong password at the console, display manager (SDDM, GDM, LightDM), screen lock or password dialog; the evidence says where. The KDE password box closing after a fingerprint or smart card unlock logs a "failure" too; those are not counted |
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
| `BASE-PERSIST-WATCHED` | Info | Files of a kind the older scanner did not record, from no package and unchanged since before the baseline was made: listed once, then watched |
| `BASE-SSH-KEY-NEW` | **Critical** | A new key in an `authorized_keys` file |
| `BASE-BLUETOOTH-NEW` | High/Medium | A new paired Bluetooth device (High for a keyboard) |
| `BASE-ADDON-NEW` | Medium | A browser add-on that was not switched on before |
| `BASE-EDITOR-NEW` | Low | A new editor extension |
| `BASE-LOCAL-PACKAGE` | Medium | A package that no source offers and that was not installed in this version when the baseline was made, also one that looks like an old Debian package. Packages a release upgrade leaves behind were installed then and stay quiet |
| `BASE-PACKAGE-REPLACED` | High/Medium | A package's checksum list, install scripts, debconf script (`config`) or triggers (`/var/lib/dpkg/info`) changed while its version stayed the same. High when no source offers the package |
| `BASE-PACKAGE-CHANGED` | Medium | Packages installed in another version, newly installed or with new files for another architecture, that apt's history does not explain (see below); one finding with the list |
| `BASE-FIREWALL-OFF` | High | A firewall that was on is off |
| `BASE-FIREWALL-RULE` | Medium/Low | A new accept rule since the baseline (root; compared without counters, with the members of named sets). Medium for incoming chains, Low for forwarded and other traffic. In Docker's and libvirt's own chains (not `DOCKER-USER`) private addresses and `veth*`/`br-*` names are ignored, so a new container is not a new rule |
| `BASE-EFI-FILE-CHANGED` | Medium/Info | A boot file built on this computer (such as a local `grubx64.efi`) changed; Info when `dpkg.log` shows an update of GRUB (or fwupd) after the baseline, and the baseline then takes the new file in |
| `BASE-DEVICE-NEW` | Medium | A USB keyboard or Thunderbolt device that was not connected before |
| `BASE-APPARMOR-OFF` | High | AppArmor or SELinux stopped protecting |
| `BASE-DESKTOP-NEW` | High/Medium | A graphical desktop appeared on a machine that had none; a virtual or remote screen (Xvnc, x11vnc, Xvfb) started running |
| `BASE-SECUREBOOT-OFF` / `BASE-LOCKDOWN-OFF` | High | Secure Boot or the kernel lockdown was switched off |
| `BASE-BOOT-ENTRY-NEW` / `-CHANGED` / `BASE-BOOT-ORDER` | Medium/Low | UEFI boot entries or their order changed |

### After a scanner upgrade

A newer version records more kinds of files than an older baseline holds. Those that are
exactly what their package ships (also through a link the package ships) are not reported;
those from no package that have not changed since before the baseline become one
`BASE-PERSIST-WATCHED` line; only files changed after the baseline are listed one by one. All
of them are taken into the automatic baseline after a clean scan as root; it counts as updated
once such a scan has included both `persistence` and `desktop_session`.

### How an apt upgrade is verified

A changed (or new) SUID or persistence file is accepted as an upgrade only when **all** hold:
a package owns it (`/var/lib/dpkg/info/*.md5sums`, or a conffile in `/var/lib/dpkg/status`),
its content equals that package's checksum, and `/var/log/dpkg.log` shows an install/upgrade of
the package after the baseline (or its file list was rewritten since). This uses dpkg's own
MD5 records, like `debsums`; a root attacker who also rewrites those records and the log could
fool it, so run `debsums` or scan from trusted media when in doubt.

A changed or new **package** is accepted, and written into the automatic baseline with its new
version and fingerprint, only when **all** hold: apt or aptitude's history shows that exactly this
version was installed after the baseline, by a command that was not handed a `.deb` file; none of
dpkg's files for the package (`/var/lib/dpkg/info`) has been written since that run ended; and a
software source offers the package. Everything else is gathered in `BASE-PACKAGE-CHANGED`, so
packages stay protected as updates arrive. A root scan is needed to update the baseline.

## External tools (`external:*`)

| Rule | Usual level | Meaning |
|------|-------------|---------|
| `EXT-DEBSUMS-CHANGED` / `-MISSING` | Critical–Low | A package file differs from its `.deb` / is missing |
| `EXT-LYNIS-WARN` / `-SUGGEST` | Medium/Low | Lynis warnings and hardening suggestions. A failed `apt-get check` (PKGS-7390) is tried again and is Low when it passes |

`chkrootkit` and `rkhunter` are no longer run (since 0.14.0): they mostly raised false alarms
on Debian 13, and the scanner's own checks cover hidden modules and processes, known rootkit
module names, changed system files and login record gaps.

## What it cannot see

* A **kernel rootkit** can lie to every user-space program. `ss` ↔ `/proc/net` and
  `sched_debug` ↔ `/proc` catch simple ones; for certainty, scan the disk from trusted boot
  media with `--root /mnt/disk`.
* Without **root**, other users' processes, `/root`, `/var/spool/cron` and debugfs are
  unreadable. The report says what was skipped.
* Very large folders are only searched up to a limit; the notes then say `Incomplete` and which
  search stopped early. In home folders, ordinary folders are searched before hidden ones, the
  hidden folders with Python environments each on their own. Skipped are `node_modules` and
  `.git` everywhere, and caches, games and containers at their usual place only (`~/.cache`,
  `~/.local/share/Trash`, `Steam`, `containers`, `flatpak`, `~/.var`, `.cargo/registry`,
  `.rustup`, `.npm`, `.yarn`, `.gradle`, `.m2`, `.conda/pkgs`, `go/pkg/mod` …): a project folder
  with one of these names is searched.
* A scan is a short moment: the password wallet is only heard while the scanner listens, and a
  program that read a password file and closed it before the scan leaves nothing open. A program
  that ends right after asking the wallet may not be identified.
* A **baseline** only shows change. If the machine was already compromised when it was made,
  the intrusion looks normal – which is why it is not saved automatically when the first scan
  has critical or high findings.
