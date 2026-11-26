//! Plugged-in hardware (part of `kernel`): USB devices that are both a keyboard and a drive
//! (BadUSB) now or in the kernel log, and Thunderbolt devices, which can read memory.

use super::common::clip;
use super::kernel::MODULE;
use super::{Collector, ScanCtx};
use crate::finding::{Finding, Severity};
use std::collections::{BTreeMap, BTreeSet};

const USB: &str = "/sys/bus/usb/devices";
const THUNDERBOLT: &str = "/sys/bus/thunderbolt/devices";

fn value(ctx: &ScanCtx, path: String) -> String {
    ctx.sys.read_string(path).map(|v| v.trim().to_string()).unwrap_or_default()
}

/// (is a keyboard, is a drive) for every USB device, from its interfaces.
fn usb_roles(ctx: &ScanCtx) -> BTreeMap<String, (bool, bool)> {
    let mut roles: BTreeMap<String, (bool, bool)> = BTreeMap::new();
    for interface in ctx.sys.dir_names(USB) {
        let Some((device, _)) = interface.split_once(':') else { continue };
        let class = value(ctx, format!("{USB}/{interface}/bInterfaceClass"));
        let protocol = value(ctx, format!("{USB}/{interface}/bInterfaceProtocol"));
        let entry = roles.entry(device.to_string()).or_default();
        // class 03 = input device, protocol 01 = keyboard; class 08 = mass storage
        entry.0 |= class == "03" && protocol == "01";
        entry.1 |= class == "08";
    }
    roles
}

/// USB ports that the kernel log shows registering both a keyboard and a drive.
pub fn log_keyboard_drives(lines: &[&str]) -> Vec<String> {
    let mut keyboards: BTreeMap<String, &str> = BTreeMap::new();
    let mut drives: BTreeSet<String> = BTreeSet::new();
    // "…/usb1/1-2/1-2:1.0/…" or "usb-storage 1-2:1.1: USB Mass Storage device detected"
    let port = |text: &str| {
        text.split(['/', ' ']).find_map(|part| {
            let (device, interface) = part.split_once(':')?;
            let is_port = device.contains('-') && device.chars().all(|c| c.is_ascii_digit() || c == '-' || c == '.');
            (is_port && interface.starts_with(|c: char| c.is_ascii_digit())).then(|| device.to_string())
        })
    };
    for line in lines {
        if line.contains("USB Mass Storage device detected") {
            drives.extend(port(line));
        } else if line.contains("input:") && line.contains("Keyboard") && line.contains("/usb") {
            if let Some(p) = port(line.split(" as ").nth(1).unwrap_or("")) {
                keyboards.entry(p).or_insert(line);
            }
        }
    }
    keyboards.into_iter().filter(|(p, _)| drives.contains(p)).map(|(p, line)| format!("port {p}: {}", clip(line, 200))).collect()
}

fn check_usb(ctx: &ScanCtx, col: &mut Collector, peripherals: &mut Vec<String>) {
    let mut combined = Vec::new();
    for (device, (keyboard, drive)) in usb_roles(ctx) {
        if !keyboard {
            continue;
        }
        let id = format!("{}:{} {}", value(ctx, format!("{USB}/{device}/idVendor")), value(ctx, format!("{USB}/{device}/idProduct")), value(ctx, format!("{USB}/{device}/product")));
        peripherals.push(format!("USB keyboard {}", id.trim()));
        if drive {
            combined.push(format!("{device}: {}", id.trim()));
        }
    }
    if !combined.is_empty() {
        col.push(
            Finding::new(Severity::High, MODULE, "KERN-USB-BADUSB", "A USB device is both a keyboard and a drive")
                .evidence(combined.join("\n"))
                .description("A memory stick that also acts as a keyboard can type commands by itself (Rubber Ducky, BadUSB). A few combined gadgets are honest; unplug it if you do not know it, and look at what was typed.")
                .verify("lsusb -t")
                .verify("journalctl -k | grep -iE 'usb|input:'"),
        );
    }
    if !ctx.sys.is_live() {
        return;
    }
    let Some(journalctl) = crate::external_tools::find_binary("journalctl") else { return };
    let since = format!("--since=-{}days", ctx.cfg.log_days.max(1));
    let args = ["--no-pager", "-q", "-o", "short-iso", "--dmesg", "--boot=all", "-n", "200000", since.as_str()];
    let Ok(out) = crate::external_tools::run_capture(&journalctl, &args, 60) else { return };
    // `--dmesg` with `--boot=all` covers earlier boots; each line keeps its time
    let lines: Vec<&str> = out.stdout.lines().filter(|l| l.contains("usb") || l.contains("USB")).collect();
    let seen = log_keyboard_drives(&lines);
    if !seen.is_empty() && combined.is_empty() {
        col.push(
            Finding::new(Severity::Medium, MODULE, "KERN-USB-HISTORY", "A keyboard that was also a drive has been plugged in")
                .evidence(clip(&seen.join("\n"), 900))
                .description("The kernel log shows one USB port registering a keyboard and a drive. That is how BadUSB sticks look; some honest gadgets too. Think about what was plugged in at that time.")
                .verify("journalctl -k --boot=all | grep -iE 'mass storage|keyboard'"),
        );
    }
}

fn check_thunderbolt(ctx: &ScanCtx, col: &mut Collector, peripherals: &mut Vec<String>) {
    let mut open = Vec::new();
    let mut devices = Vec::new();
    for name in ctx.sys.dir_names(THUNDERBOLT) {
        let base = format!("{THUNDERBOLT}/{name}");
        if name.starts_with("domain") {
            let level = value(ctx, format!("{base}/security"));
            if level == "none" {
                // with an IOMMU a device cannot reach memory it was not given
                let protected = value(ctx, format!("{base}/iommu_dma_protection")) == "1";
                if !protected {
                    open.push(format!("{name}: security=none and no IOMMU protection"));
                }
            }
            continue;
        }
        // "0-0" is the computer's own controller
        if name.ends_with("-0") || name.contains(':') {
            continue;
        }
        let device_name = value(ctx, format!("{base}/device_name"));
        if device_name.is_empty() {
            continue;
        }
        let entry = format!("{} {device_name} ({})", value(ctx, format!("{base}/vendor_name")), value(ctx, format!("{base}/unique_id")));
        peripherals.push(format!("Thunderbolt {}", entry.trim()));
        if value(ctx, format!("{base}/authorized")) != "0" {
            devices.push(entry.trim().to_string());
        }
    }
    if !open.is_empty() {
        col.push(
            Finding::new(Severity::Medium, MODULE, "KERN-THUNDERBOLT-OPEN", "Thunderbolt devices get memory access without being approved")
                .evidence(open.join("\n"))
                .description("Anyone who can plug something in can read or change the computer's memory. Set the Thunderbolt security level in the firmware to 'user' or higher, or enable the IOMMU.")
                .verify("cat /sys/bus/thunderbolt/devices/domain*/security")
                .verify("boltctl list   # package bolt"),
        );
    }
    if !devices.is_empty() {
        col.push(
            Finding::new(Severity::Low, MODULE, "KERN-THUNDERBOLT", "Approved Thunderbolt devices are connected")
                .evidence(devices.join("\n"))
                .description("Docks and displays are normal. Such a device can reach memory, so know each one.")
                .verify("boltctl list   # package bolt"),
        );
    }
}

pub(crate) fn run(ctx: &ScanCtx, col: &mut Collector) {
    if !ctx.sys.exists(USB) && !ctx.sys.exists(THUNDERBOLT) {
        return;
    }
    let mut peripherals = Vec::new();
    check_usb(ctx, col, &mut peripherals);
    check_thunderbolt(ctx, col, &mut peripherals);
    peripherals.sort();
    peripherals.dedup();
    col.inventory.peripherals = Some(peripherals);
}
