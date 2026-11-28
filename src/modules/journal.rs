//! Login messages from the systemd journal, only from the programs that write them.
//!
//! Anyone may log with any facility and any program name (`logger -p authpriv.notice -t sshd
//! "Accepted password for root …"`). The journal itself records who sent each message in fields
//! that start with `_`, which a sender cannot set. A line counts when root sent it, when it comes
//! from the polkit service, or when it comes from one of the few programs that log logins while
//! running as the person (`sudo`, `su`, `pkexec`, screen locks), under their own name. Each of
//! these groups is asked for separately, so a flood of other messages cannot push the real lines
//! out of what is read.
//!
//! A program of a user can still imitate the last group: it can run them in ways that let it add
//! code to them, or mount a file of its own at their path in a mount namespace it made, whose
//! path the journal then records (it records nothing about namespaces). Their lines never lead to
//! more than a Medium finding.

use serde_json::Value;

/// Facilities Debian logs logins with: auth and authpriv.
const FACILITIES: [&str; 2] = ["SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"];

/// Programs that log what a person does while running with that person's id, by full path.
const HELPERS: [&str; 5] = [
    "/usr/bin/sudo",
    "/usr/bin/su",
    "/usr/bin/pkexec",
    "/usr/bin/gpasswd",
    "/usr/lib/polkit-1/polkit-agent-helper-1",
];

/// Screen locks. `*` stands for the folder of the computer's architecture.
const LOCKERS: [&str; 12] = [
    "/usr/lib/*/libexec/kscreenlocker_greet",
    "/usr/libexec/kscreenlocker_greet",
    "/usr/bin/swaylock",
    "/usr/bin/gtklock",
    "/usr/bin/hyprlock",
    "/usr/bin/waylock",
    "/usr/bin/i3lock",
    "/usr/bin/light-locker",
    "/usr/libexec/xscreensaver/xscreensaver-auth",
    "/usr/libexec/cinnamon-screensaver-pam-helper",
    "/usr/libexec/mate-screensaver-dialog",
    "/usr/lib/mate-screensaver/mate-screensaver-dialog",
];

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Entry {
    /// Microseconds since 1970.
    pub time: i64,
    pub cursor: String,
    pub host: String,
    /// The name the sender gave itself (`SYSLOG_IDENTIFIER`).
    pub tag: String,
    pub pid: String,
    pub message: String,
    /// The user id the journal saw (`_UID`).
    pub uid: Option<u32>,
    /// The program the journal saw (`_EXE`); empty when it had already exited.
    pub exe: String,
    /// The systemd unit the sender ran in (`_SYSTEMD_UNIT`).
    pub unit: String,
}

/// A field of `journalctl -o json`: text, or a list of bytes when it is not printable.
fn field(entry: &Value, name: &str) -> String {
    match entry.get(name) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(bytes)) => {
            let bytes: Vec<u8> = bytes.iter().filter_map(|b| b.as_u64().and_then(|n| u8::try_from(n).ok())).collect();
            String::from_utf8_lossy(&bytes).into_owned()
        }
        _ => String::new(),
    }
}

pub fn parse_entry(line: &str) -> Option<Entry> {
    let json: Value = serde_json::from_str(line).ok()?;
    let get = |name: &str| field(&json, name);
    Some(Entry {
        time: get("__REALTIME_TIMESTAMP").parse().ok()?,
        cursor: get("__CURSOR"),
        host: get("_HOSTNAME"),
        tag: get("SYSLOG_IDENTIFIER"),
        pid: get("_PID"),
        message: get("MESSAGE"),
        uid: get("_UID").parse().ok(),
        exe: get("_EXE"),
        unit: get("_SYSTEMD_UNIT"),
    })
}

fn locker(exe: &str) -> bool {
    LOCKERS.iter().any(|pattern| match pattern.split_once('*') {
        Some((start, end)) => exe.strip_prefix(start).and_then(|rest| rest.strip_suffix(end)).is_some_and(|folder| !folder.contains('/')),
        None => exe == *pattern,
    })
}

/// Was this line written by a program that may write it?
pub fn from_real_source(entry: &Entry) -> bool {
    if entry.uid == Some(0) {
        return true;
    }
    if entry.tag == "polkitd" {
        return entry.unit == "polkit.service";
    }
    // the others only under their own name, so none of them can pose as sshd or useradd
    let own_name = entry.exe.rsplit('/').next() == Some(entry.tag.as_str());
    own_name && (HELPERS.contains(&entry.exe.as_str()) || locker(&entry.exe))
}

/// The line as `journalctl -o short-iso` writes it, which the parser reads.
pub fn to_line(entry: &Entry) -> String {
    let time = chrono::DateTime::from_timestamp_micros(entry.time)
        .map(|t| t.with_timezone(&chrono::Local).format("%Y-%m-%dT%H:%M:%S%:z").to_string())
        .unwrap_or_else(|| "?".into());
    // one message is one line, and the name stays one word
    let tag: String = entry.tag.chars().filter(|c| !c.is_whitespace() && *c != '[' && *c != ':').collect();
    let host = if entry.host.is_empty() { "?" } else { entry.host.as_str() };
    let pid = if entry.pid.is_empty() { String::new() } else { format!("[{}]", entry.pid) };
    format!("{time} {host} {tag}{pid}: {}", entry.message.replace(['\n', '\r'], " "))
}

/// What to ask `journalctl` for: one query per group of senders, each as (name, matches).
pub fn queries() -> Vec<(&'static str, Vec<String>)> {
    let with = |extra: Vec<String>| FACILITIES.iter().map(|f| f.to_string()).chain(extra).collect::<Vec<_>>();
    let triplet = format!("{}-linux-gnu", std::env::consts::ARCH);
    let exes = |list: &[&str]| list.iter().map(|p| format!("_EXE={}", p.replace('*', &triplet))).collect::<Vec<_>>();
    vec![
        ("root programs", with(vec!["_UID=0".into()])),
        ("the polkit service", with(vec!["_SYSTEMD_UNIT=polkit.service".into()])),
        ("sudo, su and pkexec", with(exes(&HELPERS))),
        ("screen locks", with(exes(&LOCKERS))),
    ]
}

/// The query for every login message, whoever sent it: only to see whether the journal can be
/// read and which lines are not counted.
pub fn any_sender() -> Vec<String> {
    FACILITIES.iter().map(|f| f.to_string()).collect()
}
