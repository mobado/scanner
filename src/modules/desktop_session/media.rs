//! Sound, camera and screen: PipeWire and WirePlumber settings that run programs, send audio
//! over the network or add virtual devices; programs recording right now; programs holding the
//! camera or microphone device; and the standing permissions of the desktop portals.

use super::MODULE;
use crate::finding::{Finding, Severity};
use crate::modules::common::{analyze_user_command, capped, clip, max_severity, reasons, risky_home_place, shq};
use crate::modules::persistence::record;
use crate::modules::{wallet, Collector, ScanCtx};
use crate::pkgverify::owned_paths;
use crate::procinfo::read_proc;
use serde_json::Value;
use std::collections::BTreeSet;
use walkdir::WalkDir;

type Homes = [(String, u32, String)];

fn finding(col: &mut Collector, severity: Severity, rule: &str, title: String, evidence: String, description: &str, verify: String) {
    col.push(Finding::new(severity, MODULE, rule, title).evidence(clip(&evidence, 1200)).description(description.to_string()).verify(verify));
}

// ---------------------------------------------------------------- settings

/// What a PipeWire or WirePlumber settings file does beyond ordinary tuning.
#[derive(Debug, Default, PartialEq)]
pub struct AudioSettings {
    /// Commands the sound server starts ("context.exec").
    pub commands: Vec<String>,
    /// Lines that send or receive audio over the network.
    pub network: Vec<String>,
    /// Lines that add virtual or loopback devices.
    pub virtual_devices: Vec<String>,
}

/// The value after `key =` or `key:` on a line, quoted or not.
fn spa_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let at = line.find(key)?;
    // "path" must be the whole word
    if line[..at].chars().next_back().map(|c| c.is_alphanumeric() || c == '.' || c == '_').unwrap_or(false) {
        return None;
    }
    let rest = line[at + key.len()..].trim_start_matches('"').trim_start();
    let rest = rest.strip_prefix(['=', ':'])?.trim_start();
    match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next(),
        None => rest.split([' ', '}', ',', ']']).next(),
    }
}

pub fn audio_settings(text: &str) -> AudioSettings {
    const NETWORK: [&str; 9] = [
        "module-native-protocol-tcp", "module-rtp-send", "module-rtp-recv", "module-pulse-tunnel", "module-tunnel-sink",
        "module-tunnel-source", "libpipewire-module-rtp-", "libpipewire-module-roc", "\"tcp:",
    ];
    const VIRTUAL: [&str; 4] = ["libpipewire-module-loopback", "module-null-sink", "module-loopback", "support.null-audio-sink"];
    let mut out = AudioSettings::default();
    // inside "context.exec = [ … ]" or "pulse.cmd = [ … ]"
    let mut exec_depth: Option<i32> = None;
    for line in text.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
        let line = line.split(" #").next().unwrap_or(line);
        if line.starts_with("context.exec") || line.starts_with("\"context.exec\"") {
            exec_depth = Some(0);
        }
        if let Some(depth) = exec_depth.as_mut() {
            if let Some(path) = spa_value(line, "path") {
                let args = spa_value(line, "args").unwrap_or("");
                out.commands.push(format!("{path} {args}").trim().to_string());
            } else if let Some(args) = spa_value(line, "args") {
                if let Some(last) = out.commands.last_mut() {
                    *last = format!("{last} {args}");
                }
            }
            *depth += line.matches('[').count() as i32 - line.matches(']').count() as i32;
            if *depth <= 0 && line.contains(']') {
                exec_depth = None;
            }
        }
        if NETWORK.iter().any(|n| line.contains(n)) {
            out.network.push(line.to_string());
        }
        if VIRTUAL.iter().any(|n| line.contains(n)) {
            out.virtual_devices.push(line.to_string());
        }
    }
    out
}

fn settings_files(ctx: &ScanCtx, homes: &Homes) -> Vec<String> {
    let mut dirs: Vec<String> = ["/etc/pipewire", "/etc/wireplumber", "/usr/local/share/pipewire", "/usr/local/share/wireplumber"].map(String::from).to_vec();
    for (_, _, home) in homes {
        dirs.extend([".config/pipewire", ".config/wireplumber", ".local/share/wireplumber"].iter().map(|d| format!("{home}/{d}")));
    }
    let mut files = Vec::new();
    for dir in dirs {
        let walk = WalkDir::new(ctx.sys.path(&dir)).max_depth(4).follow_links(false).into_iter().filter_map(|e| e.ok()).filter(|e| !e.file_type().is_dir());
        files.extend(capped(walk, 300, dir.as_str()).map(|e| ctx.sys.display(e.path())));
    }
    files.sort();
    files
}

fn check_settings(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    let files = settings_files(ctx, homes);
    let owned = owned_paths(ctx.sys, &files);
    for path in files {
        record(ctx, col, &path);
        if owned.contains(&path) {
            continue;
        }
        let Ok(text) = ctx.sys.read_string(&path) else { continue };
        let verify = format!("cat {}", shq(&path));
        if path.ends_with(".lua") {
            finding(col, Severity::Low, "DESK-AUDIO-SCRIPT", format!("Own sound server script: {path}"), path.clone(),
                "WirePlumber runs this script whenever the desktop's sound starts. Check that you added it.", verify.clone());
        }
        let found = audio_settings(&text);
        if !found.commands.is_empty() {
            let issues: Vec<_> = found.commands.iter().flat_map(|c| analyze_user_command(c, ctx.cfg)).collect();
            let odd = found.commands.iter().filter_map(|c| c.split_whitespace().next()).any(|p| ctx.cfg.is_temp_path(p) || risky_home_place(p, ctx.cfg).is_some());
            let severity = if odd { Severity::High } else { max_severity(&issues).filter(|s| *s >= Severity::High).unwrap_or(Severity::Medium) };
            let why = if issues.is_empty() { String::new() } else { format!("\n{}", reasons(&issues)) };
            finding(col, severity, "DESK-AUDIO-EXEC", format!("The sound server starts a program: {path}"), format!("{path}\n{}{why}", found.commands.join("\n")),
                "PipeWire runs these commands every time it starts, which is at every login. A file no package installed that does this is a quiet way to stay.", verify.clone());
        }
        if !found.network.is_empty() {
            finding(col, Severity::Medium, "DESK-AUDIO-NETWORK", format!("Sound is sent or received over the network: {path}"), format!("{path}\n{}", found.network.join("\n")),
                "Audio, possibly from the microphone, can travel to or from another computer. Multi-room audio does this on purpose; check that you set it up.", verify.clone());
        }
        if !found.virtual_devices.is_empty() {
            finding(col, Severity::Info, "DESK-AUDIO-VIRTUAL", format!("Virtual sound devices are set up: {path}"), format!("{path}\n{}", found.virtual_devices.join("\n")),
                "Loopback and virtual devices route sound between programs, for streaming and effects. They can also feed recordings.", verify);
        }
    }
}

// ---------------------------------------------------------------- recording right now

#[derive(Debug, Clone, PartialEq)]
pub struct Recording {
    /// "audio" or "video".
    pub kind: &'static str,
    pub app: String,
    pub pid: Option<u32>,
    /// Records what the computer plays instead of a microphone.
    pub of_speakers: bool,
}

/// Programs that are taking sound or pictures, from the output of `pw-dump`.
pub fn recordings(json: &str) -> Vec<Recording> {
    let Ok(Value::Array(objects)) = serde_json::from_str::<Value>(json) else { return Vec::new() };
    let text = |v: &Value| v.as_str().map(String::from).or_else(|| v.as_u64().map(|n| n.to_string()));
    let mut out = Vec::new();
    for object in &objects {
        let Some(props) = object.pointer("/info/props") else { continue };
        let get = |key: &str| props.get(key).and_then(text);
        let kind = match get("media.class").as_deref() {
            Some("Stream/Input/Audio") => "audio",
            Some("Stream/Input/Video") => "video",
            _ => continue,
        };
        // the stream may leave the process to the client that made it
        let client = get("client.id").and_then(|id| objects.iter().find(|o| o.get("id").and_then(text) == Some(id.clone())));
        let from_client = |key: &str| client.and_then(|c| c.pointer("/info/props")).and_then(|p| p.get(key)).and_then(text);
        let pid = get("application.process.id").or_else(|| from_client("application.process.id")).or_else(|| from_client("pipewire.sec.pid")).and_then(|p| p.parse().ok());
        let app = get("application.name").or_else(|| from_client("application.name")).or_else(|| get("node.name")).unwrap_or_else(|| "?".into());
        out.push(Recording { kind, app, pid, of_speakers: get("stream.capture.sink").as_deref() == Some("true") });
    }
    out
}

/// Tools whose whole purpose is to record.
const RECORDERS: [&str; 10] = ["pw-record", "pw-cat", "parecord", "parec", "arecord", "ffmpeg", "gst-launch-1.0", "sox", "rec", "wf-recorder"];

fn check_recording(ctx: &ScanCtx, col: &mut Collector) {
    if !ctx.sys.is_live() {
        return;
    }
    let (Some(dump), Some(env)) = (crate::external_tools::find_binary("pw-dump"), crate::external_tools::find_binary("env")) else { return };
    let mut normal = BTreeSet::new();
    for (uid, gid, _) in wallet::sessions(ctx) {
        let args = vec![format!("XDG_RUNTIME_DIR=/run/user/{uid}"), dump.display().to_string()];
        let Some((program, args)) = wallet::as_user(ctx, uid, gid, env.clone(), args) else { continue };
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = match crate::external_tools::run_checked(&program, &args, 15) {
            Ok(out) => out,
            Err(why) => {
                col.note(format!("Recording: NOT CHECKED – the sound server of user {uid} could not be asked ({why})"));
                continue;
            }
        };
        for r in recordings(&out) {
            let process = r.pid.and_then(|pid| read_proc(ctx.sys, pid));
            let exe = process.as_ref().and_then(|p| p.exe_path()).unwrap_or("").to_string();
            let name = process.as_ref().map(|p| p.display_name()).unwrap_or_else(|| r.app.clone());
            let odd = !exe.is_empty() && (ctx.cfg.is_temp_path(&exe) || risky_home_place(&exe, ctx.cfg).is_some());
            // a name only adds suspicion here, so every one the process goes by counts
            let tool = RECORDERS.contains(&name.as_str()) || process.as_ref().is_some_and(|p| p.candidate_names().iter().any(|n| RECORDERS.contains(&n.as_str())));
            if !odd && !tool {
                normal.insert(format!("{} ({}{})", r.app, r.kind, if r.of_speakers { ", of the speakers" } else { "" }));
                continue;
            }
            let who = process.as_ref().map(|p| format!("PID {} UID {} exe={exe}\ncmdline=\"{}\"", p.pid, p.uid, clip(&p.cmdline_str(), 300))).unwrap_or_else(|| format!("application {}", r.app));
            finding(col, if odd { Severity::High } else { Severity::Medium }, "DESK-RECORDING", format!("{name} is recording {} right now", r.kind),
                who, "A program is taking sound or pictures at this moment. If you did not start it, someone may be listening or watching.", "pw-top -b -n 1; pw-dump | grep -B5 -A20 'Stream/Input'".to_string());
        }
    }
    if !normal.is_empty() {
        finding(col, Severity::Info, "DESK-RECORDING", "Programs recording right now".into(), normal.into_iter().collect::<Vec<_>>().join("\n"),
            "Calls, voice chat and screen sharing look like this.", "pw-top -b -n 1".to_string());
    }
}

/// Programs that open the camera or the microphone device themselves, past the sound server.
fn check_devices(ctx: &ScanCtx, col: &mut Collector) {
    let mut normal = BTreeSet::new();
    for p in ctx.processes.iter().filter(|p| !p.is_kernel_thread()) {
        let name = p.display_name();
        // the sound server and the desktop itself, when it is their installed program file
        let desktop = p.exe_path().is_some_and(|e| e.starts_with("/usr/") && !e.starts_with("/usr/local/"))
            && p.is_program(&["pipewire", "wireplumber", "pulseaudio", "pipewire-pulse", "systemd", "systemd-logind", "kwin_wayland", "gnome-shell"]);
        if desktop {
            continue;
        }
        let devices: BTreeSet<String> = ctx
            .sys
            .dir_names(format!("/proc/{}/fd", p.pid))
            .iter()
            .filter_map(|fd| ctx.sys.read_link(format!("/proc/{}/fd/{fd}", p.pid)))
            // "pcmC0D0c": c = capture
            .filter(|t| t.starts_with("/dev/video") || t.starts_with("/dev/snd/pcm") && t.ends_with('c'))
            .collect();
        if devices.is_empty() {
            continue;
        }
        let exe = p.exe_path().unwrap_or("");
        let odd = ctx.cfg.is_temp_path(exe) || risky_home_place(exe, ctx.cfg).is_some();
        let system = ["/usr/", "/opt/", "/snap/", "/app/"].iter().any(|d| exe.starts_with(d)) && !exe.starts_with("/usr/local/");
        let list = devices.into_iter().collect::<Vec<_>>().join(", ");
        if system && !odd {
            normal.insert(format!("{name}: {list}"));
            continue;
        }
        finding(col, if odd { Severity::High } else { Severity::Medium }, "DESK-DEVICE-OPEN", format!("{name} holds the camera or microphone"),
            format!("PID {} UID {} exe={}\ncmdline=\"{}\"\n{list}", p.pid, p.uid, p.exe.as_deref().unwrap_or("?"), clip(&p.cmdline_str(), 300)),
            "A program from outside the system folders has the camera or microphone open.", format!("ls -l /proc/{}/fd | grep -E 'video|snd'", p.pid));
    }
    if !normal.is_empty() {
        finding(col, Severity::Info, "DESK-DEVICE-OPEN", "Programs holding the camera or microphone".into(), normal.into_iter().collect::<Vec<_>>().join("\n"),
            "Installed programs that use the devices directly, such as video calls.", "fuser -v /dev/video* /dev/snd/*".to_string());
    }
}

// ---------------------------------------------------------------- portal permissions

/// Apps with a standing "yes" (or a stored permission) in the output of the permission store's
/// `Lookup` call, as `busctl --json=short` prints it.
pub fn permitted_apps(json: &str) -> Vec<(String, String)> {
    let Ok(value) = serde_json::from_str::<Value>(json) else { return Vec::new() };
    let Some(apps) = value.pointer("/data/0").and_then(Value::as_object) else { return Vec::new() };
    apps.iter()
        .filter_map(|(app, perms)| {
            let perms: Vec<&str> = perms.as_array()?.iter().filter_map(Value::as_str).collect();
            let refused = perms.first().map(|p| *p == "no").unwrap_or(false);
            (!refused).then(|| (if app.is_empty() { "(programs outside a sandbox)".to_string() } else { app.clone() }, perms.join(",")))
        })
        .collect()
}

/// What each table of the permission store grants.
const TABLES: [(&str, Severity, &str); 7] = [
    ("remote-desktop", Severity::Low, "control the screen and keyboard"),
    ("screencast", Severity::Low, "record the screen"),
    ("screenshot", Severity::Low, "take pictures of the screen"),
    ("kde-authorized", Severity::Low, "control or record without asking (KDE)"),
    ("devices", Severity::Info, "use camera, microphone or speakers"),
    ("location", Severity::Info, "know where you are"),
    ("background", Severity::Info, "keep running in the background"),
];

fn check_permissions(ctx: &ScanCtx, col: &mut Collector) {
    if !ctx.sys.is_live() {
        return;
    }
    let Some(busctl) = crate::external_tools::find_binary("busctl") else { return };
    for (uid, gid, address) in wallet::sessions(ctx) {
        if let Err(why) = wallet::reach_bus(ctx, uid, gid, &address) {
            col.note(format!("Portal permissions: NOT CHECKED – the session bus of user {uid} could not be asked ({why})"));
            continue;
        }
        let call = |method: &str, signature: &str, args: &[&str]| -> Option<String> {
            let mut all: Vec<String> = [
                &format!("--address={address}"), "--auto-start=no", "--json=short", "call", "org.freedesktop.impl.portal.PermissionStore",
                "/org/freedesktop/impl/portal/PermissionStore", "org.freedesktop.impl.portal.PermissionStore", method, signature,
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            all.extend(args.iter().map(|s| s.to_string()));
            let (program, all) = wallet::as_user(ctx, uid, gid, busctl.clone(), all)?;
            let all: Vec<&str> = all.iter().map(String::as_str).collect();
            crate::external_tools::run_capture(&program, &all, 10).ok().filter(|o| o.status == Some(0)).map(|o| o.stdout)
        };
        for (table, severity, what) in TABLES {
            let Some(list) = call("List", "s", &[table]) else { continue };
            let Ok(list) = serde_json::from_str::<Value>(&list) else { continue };
            let mut lines = Vec::new();
            for id in list.pointer("/data/0").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).take(40) {
                if let Some(answer) = call("Lookup", "ss", &[table, id]) {
                    lines.extend(permitted_apps(&answer).into_iter().map(|(app, perms)| format!("{app}: {id} ({perms})")));
                }
            }
            if !lines.is_empty() {
                lines.sort();
                finding(col, severity, "DESK-PORTAL-GRANT", format!("Apps with standing permission to {what} (user {uid})"), lines.join("\n"),
                    "The desktop remembers this answer and does not ask again. Take back what you do not want in the system settings, or with 'flatpak permissions'.", format!("flatpak permissions {table}"));
            }
        }
    }
}

pub(super) fn check_media(ctx: &ScanCtx, col: &mut Collector, homes: &Homes) {
    check_settings(ctx, col, homes);
    check_devices(ctx, col);
    check_recording(ctx, col);
    check_permissions(ctx, col);
}
