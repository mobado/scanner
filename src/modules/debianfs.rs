//! Debian's own integrity (part of `fs_perms`): the merged /usr layout, and diversions that
//! quietly put another file where a program was.

use super::common::{clip, shq};
use super::fs_perms::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use crate::modules::persistence::record;

/// On Debian 13 these are links into /usr.
const MERGED: [(&str, &str); 4] = [("/bin", "usr/bin"), ("/sbin", "usr/sbin"), ("/lib", "usr/lib"), ("/lib64", "usr/lib64")];

fn check_usr_merge(ctx: &ScanCtx, col: &mut Collector) {
    // only systems that say they are merged
    if !ctx.sys.exists("/var/lib/dpkg/info/usr-is-merged.list") {
        return;
    }
    let mut wrong = Vec::new();
    for (path, target) in MERGED {
        if std::fs::symlink_metadata(ctx.sys.path(path)).is_err() {
            continue;
        }
        match ctx.sys.read_link(path) {
            Some(link) if link.trim_start_matches('/').trim_end_matches('/') == target => {}
            Some(link) => wrong.push(format!("{path} points to {link} instead of {target}")),
            None => wrong.push(format!("{path} is a folder of its own instead of a link to {target}")),
        }
    }
    if !wrong.is_empty() {
        col.push(
            Finding::new(Severity::High, MODULE, "FS-USRMERGE", "System folders are not linked the way Debian 13 sets them up")
                .evidence(wrong.join("\n"))
                .description("Programs and libraries are looked for in these places. A changed link or a second folder can make the system run other files than the ones apt checks.")
                .verify("ls -ld /bin /sbin /lib /lib64"),
        );
    }
}

/// (original path, new name, package) from `/var/lib/dpkg/diversions`; the package ":" means
/// someone ran `dpkg-divert` by hand.
pub fn diversions(text: &str) -> Vec<(String, String, String)> {
    let lines: Vec<&str> = text.lines().collect();
    lines.chunks_exact(3).map(|c| (c[0].to_string(), c[1].to_string(), c[2].to_string())).collect()
}

fn check_diversions(ctx: &ScanCtx, col: &mut Collector) {
    let path = "/var/lib/dpkg/diversions";
    let Ok(text) = ctx.sys.read_string(path) else { return };
    record(ctx, col, path);
    let local: Vec<String> = diversions(&text)
        .into_iter()
        .filter(|(from, _, package)| package == ":" && ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/lib/", "/usr/libexec/"].iter().any(|d| from.starts_with(d)))
        .map(|(from, to, _)| format!("{from} → {to}"))
        .collect();
    if !local.is_empty() {
        let first = local[0].split(" → ").next().unwrap_or("").to_string();
        col.push(
            Finding::new(Severity::Medium, MODULE, "FS-DIVERSION", "Programs were diverted by hand")
                .evidence(clip(&local.join("\n"), 900))
                .description("A diversion makes apt install the real file under another name, so another file can sit in its place and stay there through upgrades. Administrators do this on purpose; check that you did.")
                .verify("dpkg-divert --list")
                .verify(format!("ls -l {}", shq(&first))),
        );
    }
}

pub(crate) fn check(ctx: &ScanCtx, col: &mut Collector) {
    check_usr_merge(ctx, col);
    check_diversions(ctx, col);
}
