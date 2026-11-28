//! Secrets: who has the browser's saved passwords and cookies open, private keys and tokens
//! that others can read, settings in the environment that load code into programs, and tokens
//! carried by running programs. Secret values are never read into a report.

use super::common::{analyze_command, clip, risky_home_place, shq};
use super::{Collector, ScanCtx};
use crate::config::Config;
use crate::finding::{Finding, Severity};
use crate::procinfo::{is_program_path, ProcInfo};
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::MetadataExt;

// ---------------------------------------------------------------- open password stores

const PROFILE_MARKS: [&str; 8] = ["/.mozilla/", "/.config/mozilla/", "/google-chrome", "/chromium/", "/BraveSoftware/", "/microsoft-edge", "/vivaldi", "/.thunderbird/"];
const BROWSER_SECRETS: [&str; 7] = ["Cookies", "Login Data", "Web Data", "logins.json", "key4.db", "cookies.sqlite", "signons.sqlite"];

const BROWSERS: [&str; 12] = [
    "firefox", "firefox-esr", "chrome", "chromium", "brave", "msedge", "vivaldi-bin", "opera", "thunderbird", "firefox-bin",
    "thunderbird-bin", "chrome_crashpad_handler",
];
const KEYRINGS: [&str; 5] = ["gnome-keyring-daemon", "kwalletd5", "kwalletd6", "ksecretd", "kwalletmanager5"];
/// Backup, search and antivirus programs read every file.
const READS_EVERYTHING: [&str; 11] = ["baloo_file", "baloo_file_extractor", "tracker-extract-3", "localsearch-3", "rsync", "borg", "restic", "tar", "clamscan", "clamd", "duplicity"];

/// What kind of password store a path is, if it is one.
pub fn secret_store(path: &str) -> Option<&'static str> {
    let name = crate::procinfo::basename(path);
    if name.ends_with(".keyring") && path.contains("/keyrings/") || name.ends_with(".kwl") {
        return Some("password wallet");
    }
    // SQLite keeps changes in a "-journal" or "-wal" file beside the database
    let name = name.trim_end_matches("-journal").trim_end_matches("-wal");
    (BROWSER_SECRETS.contains(&name) && PROFILE_MARKS.iter().any(|m| path.contains(m))).then_some("browser passwords or cookies")
}

/// The programs whose job it is to read a store.
fn rightful(store: &str) -> &'static [&'static str] {
    if store == "password wallet" {
        &KEYRINGS
    } else {
        &BROWSERS
    }
}

/// Lines for the evidence of a program that lost an exception: the foreign code it runs.
pub(crate) fn foreign_note(ctx: &ScanCtx, p: &ProcInfo) -> String {
    format!("\nruns code from a place your programs can write to, so its name earns it nothing:\n{}", clip(&p.foreign_code(ctx.sys).join("\n"), 600))
}

/// How worrying it is that this program has the store open. `None` for its rightful users, who
/// are known by their program file only: any process can call itself "firefox". The caller also
/// checks that they run no foreign code ([`ProcInfo::is_clean_program`]).
pub fn judge_reader(cfg: &Config, store: &str, exe: &str) -> Option<Severity> {
    let system = ["/usr/", "/opt/", "/snap/", "/app/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
    if system && is_program_path(exe, rightful(store)) {
        return None;
    }
    if system && is_program_path(exe, &READS_EVERYTHING) {
        return Some(Severity::Low);
    }
    Some(if cfg.is_temp_path(exe) || risky_home_place(exe, cfg).is_some() { Severity::Critical } else { Severity::High })
}

fn check_open_stores(ctx: &ScanCtx, col: &mut Collector) {
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread()) {
        let mut open: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
        for fd in ctx.sys.dir_names(format!("/proc/{}/fd", p.pid)) {
            let Some(target) = ctx.sys.read_link(format!("/proc/{}/fd/{fd}", p.pid)) else { continue };
            if let Some(store) = secret_store(&target) {
                open.entry(store).or_default().insert(target);
            }
        }
        let exe = p.exe_path().unwrap_or("");
        for (store, files) in open {
            let judged = judge_reader(ctx.cfg, store, exe);
            // the rightful users and the programs that read everything get their exception only
            // while they run no foreign code; with such code in them they weigh the most
            let clean = match judged {
                None => p.is_clean_program(ctx, rightful(store)),
                Some(Severity::Low) => p.is_clean_program(ctx, &READS_EVERYTHING),
                Some(_) => true,
            };
            let severity = match judged {
                _ if !clean => Severity::Critical,
                Some(severity) => severity,
                None => continue,
            };
            let foreign = if clean { String::new() } else { foreign_note(ctx, p) };
            col.push(
                Finding::new(severity, super::proc_audit::MODULE, "PROC-SECRET-ACCESS", format!("{} has the {store} open", p.display_name()))
                    .evidence(format!("PID {} UID {} exe={}\ncmdline=\"{}\"\n{}{foreign}", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 300), clip(&files.into_iter().collect::<Vec<_>>().join("\n"), 600)))
                    .description("Only the browser (or the wallet program) should read these files. Password-stealing malware copies them, or slips its code into a program that may read them. If you do not know this program, or the code listed for it, disconnect from the network and change your passwords from another computer.")
                    .verify(format!("ls -l /proc/{}/fd", p.pid))
                    .verify(format!("ps -o pid,user,lstart,cmd -p {}", p.pid)),
            );
        }
    }
}

// ---------------------------------------------------------------- environment variables

/// Is a file named in an environment variable in a place where code to load does not belong?
fn odd_file(cfg: &Config, path: &str) -> bool {
    let temp = cfg.is_temp_path(path) && !path.starts_with("/tmp/.mount_");
    let home = ["~/", "$HOME/", "${HOME}/", "%h/"].iter().find_map(|p| path.strip_prefix(p)).map(|r| format!("/home/user/{r}"));
    temp || path.starts_with("./") || risky_home_place(home.as_deref().unwrap_or(path), cfg).is_some()
}

/// Variables that make programs load or run extra code: (severity, why).
pub fn judge_variable(cfg: &Config, name: &str, value: &str) -> Option<(Severity, String)> {
    if value.trim().is_empty() {
        return None;
    }
    let words: Vec<&str> = value.split_whitespace().collect();
    // the file given to an option, as "--require x" or "--require=x"
    let argument = |flags: &[&str]| {
        words.iter().enumerate().find_map(|(i, w)| {
            flags.iter().find_map(|f| match w.strip_prefix(f) {
                Some("") => words.get(i + 1).copied(),
                Some(rest) => rest.strip_prefix('=').or_else(|| f.len().eq(&2).then_some(rest)),
                None => None,
            })
        })
    };
    let paths = || value.split(':').filter(|p| !p.is_empty());
    let judged = |file: &str, normal: Severity, what: &str| {
        let odd = odd_file(cfg, file);
        Some((if odd { Severity::High } else { normal }, format!("{what} {file}{}", if odd { " (from an unusual place)" } else { "" })))
    };
    match name {
        "NODE_OPTIONS" => judged(argument(&["--require", "--import", "--loader", "--experimental-loader", "-r"])?, Severity::Low, "every Node.js program loads"),
        "PYTHONSTARTUP" => judged(value, Severity::Low, "every interactive Python runs"),
        "BASH_ENV" => judged(value, Severity::Medium, "every shell script runs"),
        "PERL5OPT" => judged(argument(&["-M", "-m", "-d"])?, Severity::Low, "every Perl program loads"),
        "RUBYOPT" => judged(argument(&["-r"])?, Severity::Low, "every Ruby program loads"),
        "JAVA_TOOL_OPTIONS" | "_JAVA_OPTIONS" => judged(words.iter().find_map(|w| w.strip_prefix("-javaagent:"))?, Severity::Medium, "every Java program loads"),
        "LD_AUDIT" => {
            let known = cfg.allowed_ld_preload.iter().any(|a| value.contains(a.as_str()));
            (!known).then(|| (Severity::High, format!("every program loads the audit library {value}")))
        }
        "GCONV_PATH" => judged(value, Severity::Medium, "programs load text conversion code from"),
        "PYTHONPATH" | "PERL5LIB" | "RUBYLIB" | "NODE_PATH" | "QT_PLUGIN_PATH" | "GTK_PATH" => {
            let odd = paths().find(|p| cfg.is_temp_path(p) && !p.starts_with("/tmp/.mount_"))?;
            Some((Severity::High, format!("libraries are loaded from the temporary folder {odd}")))
        }
        "PROMPT_COMMAND" | "GIT_SSH_COMMAND" => {
            let worst = analyze_command(value, cfg).into_iter().filter(|i| i.severity >= Severity::High && !i.reason.starts_with("points to a home")).max_by_key(|i| i.severity)?;
            Some((worst.severity, worst.reason))
        }
        _ => None,
    }
}

/// A variable's value as it may be shown: passwords in options ("-Dproxy.password=x") and in
/// addresses ("https://user:x@host") are hidden.
pub fn hide_secrets(value: &str) -> String {
    let words = value.split(' ').map(|word| {
        if let Some((left, _)) = word.split_once('=') {
            let lower = left.to_ascii_lowercase();
            if ["pass", "token", "secret", "apikey", "api_key", "api-key", "_auth"].iter().any(|k| lower.contains(k)) {
                return format!("{left}=<hidden>");
            }
        }
        match word.split_once("://") {
            Some((scheme, rest)) => {
                let (authority, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
                match authority.rsplit_once('@') {
                    Some((_, host)) => format!("{scheme}://<hidden>@{host}{path}"),
                    None => word.to_string(),
                }
            }
            None => word.to_string(),
        }
    });
    words.collect::<Vec<_>>().join(" ")
}

/// "http_proxy", "HTTPS_PROXY", "all_proxy" …
pub fn is_proxy_variable(name: &str) -> bool {
    ["http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "auto_proxy"].contains(&name.to_ascii_lowercase().as_str())
}

/// A proxy on this computer is usually a tool of one's own; one elsewhere sees the traffic.
pub fn judge_proxy(value: &str) -> Severity {
    let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
    let rest = value.split_once("://").map(|(_, r)| r).unwrap_or(value);
    // "user:password@host:port/path": the whole host name has to be this computer's
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let address = authority.rsplit('@').next().unwrap_or(authority);
    let host = match address.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        // an address without brackets and more than one colon is an IPv6 address
        None if address.matches(':').count() > 1 => address,
        None => address.split(':').next().unwrap_or(""),
    };
    let host = host.trim_end_matches('.');
    let local = rest.starts_with("unix:")
        || value.starts_with("unix:")
        || ["localhost", "ip6-localhost", "ip6-loopback"].iter().any(|n| host.eq_ignore_ascii_case(n))
        || host.parse::<std::net::IpAddr>().map(|ip| crate::modules::net_proc::ip_is_loopback(&ip)).unwrap_or(false);
    if local {
        Severity::Low
    } else {
        Severity::Medium
    }
}

/// Is an SSH agent socket somewhere agents normally put it?
pub fn usual_agent_socket(path: &str) -> bool {
    let name = crate::procinfo::basename(path);
    path.starts_with("/run/user/")
        || (path.starts_with("/tmp/ssh-") && (name.starts_with("agent.") || name == "agent"))
        // sshd's forwarded agents, and agents kept in the home folder
        || ["/.ssh/", "/.gnupg/", "/.1password/", "/.bitwarden", "/.cache/keyring-", "/.var/app/"].iter().any(|d| path.contains(d))
        || path.starts_with("/tmp/keyring-")
}

/// Does a variable name say that its value is a secret?
pub fn names_a_secret(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    // window activation tokens and the like are not secrets
    if ["XDG_ACTIVATION_TOKEN", "DESKTOP_STARTUP_ID"].contains(&upper.as_str()) {
        return false;
    }
    ["_API_KEY", "_APIKEY", "_TOKEN", "_SECRET", "_SECRET_KEY", "_ACCESS_KEY", "_PASSWORD", "_PRIVATE_KEY"].iter().any(|e| upper.ends_with(e)) || ["PGPASSWORD", "MYSQL_PWD"].contains(&upper.as_str())
}

/// The programs that have no business holding keys.
const SHOULD_NOT_HOLD: [&str; 10] = ["firefox", "firefox-esr", "chrome", "chromium", "brave", "thunderbird", "evince", "okular", "soffice.bin", "vlc"];

fn check_environments(ctx: &ScanCtx, col: &mut Collector) {
    // (variable, value) → (severity, why, processes)
    let mut injected: BTreeMap<(String, String), (Severity, String, Vec<String>)> = BTreeMap::new();
    let mut sockets: BTreeMap<String, Vec<String>> = BTreeMap::new();
    // secret name → processes (names only, never values)
    let mut secrets: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    // proxy setting (passwords hidden) → (severity, processes)
    let mut proxies: BTreeMap<String, (Severity, BTreeSet<String>)> = BTreeMap::new();
    let mut misplaced = false;
    // the scanner only inherited these from whoever started it
    let own = crate::procinfo::own_exe(ctx.sys);
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread() && (own.is_none() || p.exe_path() != own.as_deref())) {
        let Ok(env) = ctx.sys.read_bytes(format!("/proc/{}/environ", p.pid)) else { continue };
        let who = |p: &ProcInfo| format!("{} (PID {})", p.display_name(), p.pid);
        for entry in env.split(|b| *b == 0) {
            let entry = String::from_utf8_lossy(entry);
            let Some((name, value)) = entry.split_once('=') else { continue };
            if is_proxy_variable(name) && !value.is_empty() {
                let shown = format!("{}={}", name.to_ascii_lowercase(), clip(&hide_secrets(value), 200));
                proxies.entry(shown).or_insert((judge_proxy(value), BTreeSet::new())).1.insert(p.display_name());
            } else if let Some((severity, why)) = judge_variable(ctx.cfg, name, value) {
                injected.entry((name.to_string(), clip(&hide_secrets(value), 200))).or_insert((severity, hide_secrets(&why), Vec::new())).2.push(who(p));
            } else if name == "SSH_AUTH_SOCK" && !value.is_empty() && !usual_agent_socket(value) {
                sockets.entry(value.to_string()).or_default().push(who(p));
            } else if value.len() >= 8 && names_a_secret(name) {
                misplaced |= p.candidate_names().iter().any(|n| SHOULD_NOT_HOLD.contains(&n.as_str())) || p.exe_path().map(|e| ctx.cfg.is_temp_path(e) && !e.starts_with("/tmp/.mount_")).unwrap_or(false);
                secrets.entry(name.to_string()).or_default().insert(p.display_name());
            }
        }
    }
    let list = |users: &[String]| format!("{} process(es): {}", users.len(), clip(&users.iter().take(8).cloned().collect::<Vec<_>>().join(", "), 300));
    for ((name, value), (severity, why, users)) in injected {
        col.push(
            Finding::new(severity, super::proc_audit::MODULE, "PROC-ENV-INJECT", format!("{name} makes programs load extra code"))
                .evidence(format!("{name}={value}\n{why}\n{}", list(&users)))
                .description("A variable in the environment makes programs run extra code when they start. Development tools set some of these; malware uses them to stay and to get into other programs without changing them.")
                .verify(format!("grep -rn {name} /etc/environment /etc/environment.d ~/.config/environment.d ~/.profile ~/.bashrc 2>/dev/null")),
        );
    }
    for (socket, users) in sockets {
        col.push(
            Finding::new(Severity::Medium, super::proc_audit::MODULE, "PROC-SSH-SOCKET", "Programs use an SSH key agent in an unusual place")
                .evidence(format!("SSH_AUTH_SOCK={socket}\n{}", list(&users)))
                .description("Programs hand their SSH signing requests to whatever listens on this socket. A planted agent can record or misuse them. Password managers with their own agent also look like this.")
                .verify(format!("ls -l {}", shq(&socket))),
        );
    }
    if let Some(severity) = proxies.values().map(|p| p.0).max() {
        let lines: Vec<String> = proxies.iter().map(|(setting, (_, who))| format!("{setting}: {}", clip(&who.iter().cloned().collect::<Vec<_>>().join(", "), 200))).collect();
        col.push(
            Finding::new(severity, super::proc_audit::MODULE, "PROC-ENV-PROXY", "Running programs send traffic through a proxy")
                .evidence(clip(&lines.join("\n"), 900))
                .description("These programs started with a proxy setting, so their web traffic goes through that server. Company networks, VPN tools and debuggers do this; malware does it to read traffic.")
                .verify("env | grep -i _proxy; grep -ri _proxy /etc/environment /etc/environment.d ~/.config/environment.d 2>/dev/null"),
        );
    }
    if !secrets.is_empty() {
        let lines: Vec<String> = secrets.iter().map(|(name, who)| format!("{name}: {}", clip(&who.iter().cloned().collect::<Vec<_>>().join(", "), 200))).collect();
        col.push(
            Finding::new(if misplaced { Severity::Medium } else { Severity::Low }, super::proc_audit::MODULE, "PROC-ENV-SECRETS", "Programs carry keys or tokens in their environment")
                .evidence(format!("variable names and the programs that have them (values are not read into this report):\n{}", clip(&lines.join("\n"), 1500)))
                .description("Every program started from a shell inherits its variables, and other programs of the same user can read them. Keep keys in a file only you can read, or give them only to the program that needs them.")
                .verify("tr '\\0' '\\n' < /proc/<pid>/environ | cut -d= -f1"),
        );
    }
}

pub(crate) fn check_processes(ctx: &ScanCtx, col: &mut Collector) {
    check_open_stores(ctx, col);
    check_environments(ctx, col);
}

// ---------------------------------------------------------------- readable secret files

const CREDENTIALS: [&str; 11] = [
    ".aws/credentials", ".kube/config", ".config/gh/hosts.yml", ".docker/config.json", ".netrc", ".git-credentials",
    ".pypirc", ".npmrc", ".config/gcloud/credentials.db", ".azure/accessTokens.json", ".config/rclone/rclone.conf",
];

/// Can users other than the owner open the file? Every folder from the home folder down has to
/// let them pass.
fn others_can_read(ctx: &ScanCtx, home: &str, path: &str, meta: &std::fs::Metadata) -> bool {
    // a group of one's own is no other user
    let group = meta.gid() != meta.uid() && meta.mode() & 0o040 != 0;
    let world = meta.mode() & 0o004 != 0;
    if !group && !world {
        return false;
    }
    let mut folder = std::path::Path::new(path).parent();
    while let Some(f) = folder.filter(|f| f.starts_with(home)) {
        let Ok(m) = std::fs::metadata(ctx.sys.path(f)) else { return false };
        let passes = (world && m.mode() & 0o001 != 0) || (group && m.mode() & 0o010 != 0);
        if !passes {
            return false;
        }
        folder = f.parent();
    }
    true
}

fn private_keys(ctx: &ScanCtx, home: &str) -> Vec<String> {
    let ssh = format!("{home}/.ssh");
    let mut out: Vec<String> = ctx
        .sys
        .dir_names(&ssh)
        .into_iter()
        .filter(|n| !n.ends_with(".pub") && (n.starts_with("id_") || n.ends_with(".pem") || n.ends_with("_key") || n.ends_with(".key")))
        .map(|n| format!("{ssh}/{n}"))
        .collect();
    let gpg = format!("{home}/.gnupg/private-keys-v1.d");
    out.extend(ctx.sys.dir_names(&gpg).into_iter().map(|n| format!("{gpg}/{n}")));
    out.push(format!("{home}/.gnupg/secring.gpg"));
    out
}

pub(crate) fn check_files(ctx: &ScanCtx, col: &mut Collector, homes: &[String]) {
    let (mut keys, mut tokens, mut loose) = (Vec::new(), Vec::new(), Vec::new());
    for home in homes {
        let mut candidates: Vec<(String, u8)> = private_keys(ctx, home).into_iter().map(|p| (p, 0)).collect();
        candidates.extend(CREDENTIALS.iter().map(|c| (format!("{home}/{c}"), 1)));
        candidates.extend(super::homeindex::of(ctx, home).env_files.iter().map(|p| (p.clone(), 2)));
        for (path, kind) in candidates {
            let Ok(meta) = std::fs::symlink_metadata(ctx.sys.path(&path)) else { continue };
            // an .npmrc without a token only holds settings
            let open = meta.mode() & 0o004 != 0 || (meta.gid() != meta.uid() && meta.mode() & 0o040 != 0);
            if !meta.is_file() || !open || (path.ends_with("/.npmrc") && !ctx.sys.read_string(&path).map(|t| t.contains("_auth")).unwrap_or(false)) {
                continue;
            }
            let line = format!("{path} (mode {:04o}, owner {})", meta.mode() & 0o7777, meta.uid());
            if others_can_read(ctx, home, &path, &meta) {
                if kind == 0 { &mut keys } else { &mut tokens }.push(line);
            } else if kind < 2 {
                loose.push(line);
            }
        }
    }
    let mut report = |severity: Severity, title: &str, mut files: Vec<String>, text: &str| {
        if files.is_empty() {
            return;
        }
        files.sort();
        files.dedup();
        let first = files[0].split(" (mode").next().unwrap_or("").to_string();
        col.push(
            Finding::new(severity, super::fs_perms::MODULE, "FS-SECRET-PERMS", title)
                .evidence(clip(&files.join("\n"), 1500))
                .description(text.to_string())
                .verify(format!("ls -l {}", shq(&first)))
                .verify(format!("namei -l {}", shq(&first))),
        );
    };
    report(Severity::High, "Private keys that other users can read", keys, "Other accounts on this computer, and anything running as them, can copy these keys. Run chmod 600 on each and consider making new keys.");
    report(Severity::Medium, "Passwords or tokens that other users can read", tokens, "These files hold logins for cloud, code and package services, and other accounts can read them. Run chmod 600 on each.");
    report(Severity::Low, "Secret files with loose permissions behind a closed folder", loose, "The folder keeps others out today, but the files themselves are open; a copy or a changed folder would expose them. Run chmod 600 on each.");
}
