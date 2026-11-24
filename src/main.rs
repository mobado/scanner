//! scanner – command line (clap) and, with the `gui` feature, a window.
//!
//! Without flags the window opens when a screen is available, otherwise a
//! terminal scan runs. Flags such as --json, --output and --baseline-* always give
//! terminal mode.

mod elevate;
#[cfg(feature = "gui")]
mod gui;

use anyhow::{bail, Context, Result};
use clap::Parser;
use scanner::baseline::Baseline;
use scanner::external_tools::{self, Tool};
use scanner::{Config, ModuleId, ScanOptions, Severity, SysRoot};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "scanner",
    version,
    about = "Read-only intrusion and backdoor scanner for Debian 13 (Trixie)",
    long_about = "Read-only intrusion and backdoor scanner for Debian 13 (Trixie).\n\
The scanner only reads – it never changes anything on the system. Run as root for full coverage.\n\n\
Exit codes: 0 = no high/critical findings, 1 = at least one high, 2 = at least one critical, 3 = error."
)]
struct Cli {
    /// Write the report as JSON instead of readable text
    #[arg(long)]
    json: bool,

    /// Write the report to a file instead of the terminal
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    /// Save a baseline (SUID/SGID, listening ports, persistence files) as JSON
    #[arg(long, value_name = "FILE")]
    baseline_save: Option<PathBuf>,

    /// Compare against a previously saved baseline
    #[arg(long, value_name = "FILE")]
    baseline_compare: Option<PathBuf>,

    /// Whitelist/configuration in TOML or JSON
    #[arg(long, short = 'c', value_name = "FILE")]
    config: Option<PathBuf>,

    /// Modules to run, comma separated (net_proc,proc_audit,fs_perms,persistence). Default: all
    #[arg(long, value_delimiter = ',', value_name = "MODULES")]
    modules: Option<Vec<String>>,

    /// External tools to run, comma separated (debsums,chkrootkit,rkhunter,lynis) or "all"
    #[arg(long, value_delimiter = ',', value_name = "TOOLS")]
    tools: Option<Vec<String>>,

    /// Walk the whole PID range to find hidden processes (slower)
    #[arg(long)]
    deep_pid_scan: bool,

    /// Run everything: all modules, all installed external tools and the deep PID scan
    #[arg(long)]
    full: bool,

    /// Print only one summary line (OK/NOTICE/ATTENTION/ALARM) – handy for monitoring and cron
    #[arg(long)]
    summary: bool,

    /// Do not save or use the automatic baseline (/var/lib/scanner/baseline.json)
    #[arg(long)]
    no_auto_baseline: bool,

    /// Scan another root file system (e.g. a mounted disk or a test directory)
    #[arg(long, value_name = "DIR", default_value = "/")]
    root: PathBuf,

    /// Only show findings from this level and up (low, medium, high, critical)
    #[arg(long, value_name = "LEVEL", default_value = "low")]
    min_severity: String,

    /// No colours in terminal output
    #[arg(long)]
    no_color: bool,

    /// Print the default whitelist as TOML and exit
    #[arg(long)]
    print_config: bool,

    /// Run the safe self-test in a temporary sandbox and exit
    #[arg(long)]
    self_test: bool,

    /// Show which external tools are installed and exit
    #[arg(long)]
    list_tools: bool,

    /// Force terminal mode
    #[arg(long, conflicts_with = "gui")]
    cli: bool,

    /// Force window mode
    #[arg(long)]
    gui: bool,

    /// Do not ask for the sudo password – run with the privileges the program was started with
    #[arg(long)]
    no_sudo: bool,

    /// Open the window, draw about 120 frames, save a screenshot as PNG and exit
    #[arg(long, value_name = "FILE.png")]
    screenshot: Option<PathBuf>,
}

fn main() -> ExitCode {
    // sudo runs the program as its password prompt (SUDO_ASKPASS) with the prompt as the only argument.
    if std::env::var_os(elevate::ASKPASS_ENV).is_some() && !scanner::sys::is_root() {
        #[cfg(feature = "gui")]
        {
            let prompt = std::env::args().nth(1).unwrap_or_default();
            return ExitCode::from(gui::run_askpass(prompt));
        }
        #[cfg(not(feature = "gui"))]
        return ExitCode::from(1);
    }
    let cli = Cli::parse();
    match real_main(cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("scanner: error: {e:#}");
            ExitCode::from(3)
        }
    }
}

fn wants_cli(cli: &Cli) -> bool {
    cli.cli
        || cli.json
        || cli.output.is_some()
        || cli.baseline_save.is_some()
        || cli.baseline_compare.is_some()
        || cli.modules.is_some()
        || cli.tools.is_some()
        || cli.deep_pid_scan
        || cli.full
        || cli.summary
        || cli.root.as_os_str() != "/"
}

fn has_display() -> bool {
    std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some()
}

/// Load the whitelist: --config, else /etc/scanner/whitelist.toml, else
/// ~/.config/scanner/whitelist.toml. Returns the path that was read, if any.
fn load_config(path: &Option<PathBuf>) -> Result<(Config, Option<PathBuf>)> {
    let chosen = path.clone().or_else(scanner::config::default_whitelist_path);
    match chosen {
        Some(p) => {
            let cfg = Config::load(&p).with_context(|| format!("could not read the whitelist {}", p.display()))?;
            Ok((cfg, Some(p)))
        }
        None => Ok((Config::default(), None)),
    }
}

fn real_main(cli: Cli) -> Result<u8> {
    if cli.print_config {
        print!("{}", Config::default().to_toml()?);
        return Ok(0);
    }
    if cli.list_tools {
        for (t, p) in external_tools::availability() {
            match p {
                Some(p) => println!("{:<11} found: {}", t.binary(), p.display()),
                None => println!("{:<11} missing (apt install {})", t.binary(), t.binary()),
            }
        }
        return Ok(0);
    }
    if cli.self_test {
        return self_test(&cli);
    }

    let use_gui = cli.gui || cli.screenshot.is_some() || (!wants_cli(&cli) && has_display());

    // Ask for the sudo password and restart as root. Skipped for screenshot checks,
    // roots other than "/" and when --no-sudo or SCANNER_NO_SUDO=1 is given.
    let mut sudo_note: Option<String> = None;
    let wants_root = !scanner::sys::is_root()
        && !cli.no_sudo
        && cli.screenshot.is_none()
        && cli.root.as_os_str() == "/"
        && std::env::var_os("SCANNER_NO_SUDO").is_none();
    if wants_root {
        let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
        match elevate::relaunch_with_sudo(&args, use_gui) {
            // The root version has finished (the window was closed / the report written).
            elevate::Outcome::Ran(code) => return Ok(code),
            elevate::Outcome::Declined(msg) => {
                eprintln!("scanner: {msg}");
                sudo_note = Some(msg);
            }
        }
    }
    #[cfg(not(feature = "gui"))]
    let _ = &sudo_note;

    if use_gui {
        #[cfg(feature = "gui")]
        {
            let (cfg, cfg_path) = load_config(&cli.config)?;
            gui::run(cfg, cfg_path, cli.screenshot.clone(), sudo_note)?;
            return Ok(0);
        }
        #[cfg(not(feature = "gui"))]
        if cli.gui || cli.screenshot.is_some() {
            bail!("this binary is built without a window (--no-default-features); run without --gui");
        }
    }
    cli_scan(&cli)
}

fn parse_opts(cli: &Cli) -> Result<ScanOptions> {
    let modules = match &cli.modules {
        Some(list) => list.iter().map(|m| m.parse::<ModuleId>()).collect::<Result<Vec<_>, _>>().map_err(anyhow::Error::msg)?,
        None => ModuleId::ALL.to_vec(),
    };
    let tools = match &cli.tools {
        Some(list) if list.iter().any(|t| t.eq_ignore_ascii_case("all")) => Tool::ALL.to_vec(),
        Some(list) => list.iter().map(|t| t.parse::<Tool>()).collect::<Result<Vec<_>, _>>().map_err(anyhow::Error::msg)?,
        None => Vec::new(),
    };
    let min_severity: Severity = cli.min_severity.parse().map_err(anyhow::Error::msg)?;
    if let Some(b) = &cli.baseline_compare {
        if !b.exists() {
            bail!("the baseline file {} does not exist", b.display());
        }
    }
    if cli.full {
        return Ok(ScanOptions {
            modules: ModuleId::ALL.to_vec(),
            tools: Tool::ALL.to_vec(),
            deep_pid_scan: true,
            baseline_compare: cli.baseline_compare.clone(),
            min_severity,
        });
    }
    Ok(ScanOptions { modules, tools, deep_pid_scan: cli.deep_pid_scan, baseline_compare: cli.baseline_compare.clone(), min_severity })
}

fn cli_scan(cli: &Cli) -> Result<u8> {
    let (cfg, _) = load_config(&cli.config)?;
    let opts = parse_opts(cli)?;
    if !cli.root.is_dir() {
        bail!("the root {} is not a directory", cli.root.display());
    }
    let sys = SysRoot::new(&cli.root);
    let interactive = std::io::stderr().is_terminal();
    let report = scanner::scan::run_scan_auto(&sys, &cfg, &opts, !cli.no_auto_baseline, &|msg| {
        if interactive {
            eprintln!("» {msg}");
        }
    });

    if let Some(path) = &cli.baseline_save {
        Baseline::from_report(&report).save(path).with_context(|| format!("could not save the baseline {}", path.display()))?;
        eprintln!("Baseline saved: {} ({} SUID/SGID files, {} persistence files)", path.display(), report.inventory.suid.len(), report.inventory.persistence_files.len());
    }

    let color = !cli.no_color && cli.output.is_none() && std::io::stdout().is_terminal();
    let text = if cli.summary { report.summary_line() } else if cli.json { report.to_json()? } else { report.to_text(color) };
    match &cli.output {
        Some(path) => {
            std::fs::write(path, &text).with_context(|| format!("could not write {}", path.display()))?;
            eprintln!(
                "Report saved: {} – {} critical, {} high, {} medium, {} low",
                path.display(),
                report.summary.critical,
                report.summary.high,
                report.summary.medium,
                report.summary.low
            );
        }
        None => println!("{text}"),
    }
    Ok(report.exit_code())
}

fn self_test(cli: &Cli) -> Result<u8> {
    let res = scanner::sandbox::run_self_test(&|m| eprintln!("» {m}"))?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        println!("Self-test in a sandbox (nothing on the real system is read or changed):\n");
        for c in &res.checks {
            println!("  [{}] {:<22} {}", if c.passed { "OK  " } else { "FAIL" }, c.rule, c.what);
        }
        println!("\n{} of {} rules fired as expected.", res.passed, res.checks.len());
    }
    Ok(if res.failed == 0 { 0 } else { 1 })
}
