//! The window (eframe/egui): choose modules and tools, run scans in the
//! background, read the findings with evidence and verification commands, manage
//! baselines, export reports and run the self-test.

use eframe::egui::{self, Color32, CornerRadius, Margin, RichText, Stroke};
use scanner::baseline::Baseline;
use scanner::external_tools::{self, Tool};
use scanner::report::Report;
use scanner::sandbox::SelfTestResult;
use scanner::{run_scan, Config, Finding, ModuleId, ScanOptions, Severity, SysRoot};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex};

const BG: Color32 = Color32::from_rgb(0x12, 0x16, 0x1c);
const PANEL: Color32 = Color32::from_rgb(0x19, 0x1f, 0x27);
const CARD: Color32 = Color32::from_rgb(0x20, 0x27, 0x31);
const CARD_HI: Color32 = Color32::from_rgb(0x27, 0x30, 0x3c);
const BORDER: Color32 = Color32::from_rgb(0x2f, 0x39, 0x46);
const TEXT: Color32 = Color32::from_rgb(0xdc, 0xe3, 0xea);
const MUTED: Color32 = Color32::from_rgb(0x8b, 0x98, 0xa8);
const ACCENT: Color32 = Color32::from_rgb(0x3d, 0xa5, 0x8a);
const OK: Color32 = Color32::from_rgb(0x4c, 0xb8, 0x6b);
const WARN: Color32 = Color32::from_rgb(0xe0, 0x9b, 0x2d);

fn sev_color(s: Severity) -> Color32 {
    match s {
        Severity::Critical => Color32::from_rgb(0xe0, 0x3e, 0x52),
        Severity::High => Color32::from_rgb(0xf0, 0x7a, 0x3a),
        Severity::Medium => Color32::from_rgb(0xe4, 0xc0, 0x3c),
        Severity::Low => Color32::from_rgb(0x4a, 0x9a, 0xd4),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Findings,
    Network,
    Suid,
    Persistence,
    Notes,
    SelfTest,
}

enum Msg {
    Scan(Box<Report>),
    SelfTest(Result<Box<SelfTestResult>, String>),
}

struct Shot {
    path: PathBuf,
    frames: u32,
    requested: bool,
    done: Arc<AtomicBool>,
}

pub struct ScannerApp {
    cfg: Config,
    cfg_path: String,
    modules: Vec<(ModuleId, bool)>,
    tools: Vec<(Tool, Option<PathBuf>, bool)>,
    deep_pid: bool,
    root_path: String,
    baseline_compare: String,
    baseline_save: String,
    export_path: String,
    /// Save the report automatically when the scan is done ("Full scan + save report").
    auto_export: bool,
    rx: Option<Receiver<Msg>>,
    progress: Arc<Mutex<String>>,
    report: Option<Report>,
    self_test: Option<SelfTestResult>,
    show_sev: [bool; 4],
    module_filter: String,
    search: String,
    tab: Tab,
    status: String,
    is_root: bool,
    shot: Option<Shot>,
    /// Result of "Restart with sudo" (runs in its own thread so the window does not freeze).
    sudo_result: Option<Receiver<Result<(), &'static str>>>,
}

impl ScannerApp {
    fn new(cc: &eframe::CreationContext<'_>, cfg: Config, cfg_path: Option<PathBuf>, shot: Option<PathBuf>, sudo_note: Option<String>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = PANEL;
        visuals.window_fill = PANEL;
        visuals.extreme_bg_color = BG;
        visuals.override_text_color = Some(TEXT);
        visuals.selection.bg_fill = ACCENT.linear_multiply(0.6);
        visuals.widgets.inactive.bg_fill = CARD_HI;
        visuals.widgets.inactive.weak_bg_fill = CARD_HI;
        visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(0x30, 0x3b, 0x49);
        cc.egui_ctx.set_theme(egui::Theme::Dark);
        cc.egui_ctx.set_visuals_of(egui::Theme::Dark, visuals);
        cc.egui_ctx.all_styles_mut(|s| {
            s.spacing.item_spacing = egui::vec2(8.0, 6.0);
            s.spacing.button_padding = egui::vec2(10.0, 5.0);
        });

        let mut app = ScannerApp {
            cfg,
            cfg_path: cfg_path.map(|p| p.display().to_string()).unwrap_or_default(),
            modules: ModuleId::ALL.iter().map(|m| (*m, *m != ModuleId::FsPerms)).collect(),
            tools: external_tools::availability().into_iter().map(|(t, p)| (t, p, false)).collect(),
            deep_pid: false,
            root_path: "/".into(),
            baseline_compare: String::new(),
            baseline_save: "/var/lib/scanner/baseline.json".into(),
            export_path: default_report_path().display().to_string(),
            auto_export: false,
            rx: None,
            progress: Arc::new(Mutex::new(String::new())),
            report: None,
            self_test: None,
            show_sev: [true; 4],
            module_filter: "all".into(),
            search: String::new(),
            tab: Tab::Findings,
            status: "Quick scan started (add the file system walk in the list on the left).".into(),
            is_root: scanner::sys::is_root(),
            shot: shot.map(|path| Shot { path, frames: 0, requested: false, done: Arc::new(AtomicBool::new(false)) }),
            sudo_result: None,
        };
        if let Some(note) = sudo_note {
            app.status = note;
        }
        app.start_scan(&cc.egui_ctx);
        app
    }

    fn busy(&self) -> bool {
        self.rx.is_some()
    }

    fn set_progress(&self, s: &str) {
        if let Ok(mut p) = self.progress.lock() {
            *p = s.to_string();
        }
    }

    fn start_scan(&mut self, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        let opts = ScanOptions {
            modules: self.modules.iter().filter(|(_, on)| *on).map(|(m, _)| *m).collect(),
            tools: self.tools.iter().filter(|(_, p, on)| *on && p.is_some()).map(|(t, _, _)| *t).collect(),
            deep_pid_scan: self.deep_pid,
            baseline_compare: (!self.baseline_compare.trim().is_empty()).then(|| PathBuf::from(self.baseline_compare.trim())),
            min_severity: Severity::Low,
        };
        if opts.modules.is_empty() && opts.tools.is_empty() {
            self.status = "Choose at least one module or tool.".into();
            return;
        }
        let root = if self.root_path.trim().is_empty() { "/".to_string() } else { self.root_path.trim().to_string() };
        let cfg = self.cfg.clone();
        let (tx, rx) = channel();
        let progress = self.progress.clone();
        let ctx2 = ctx.clone();
        self.set_progress("Starting …");
        std::thread::spawn(move || {
            let sys = SysRoot::new(root);
            let report = run_scan(&sys, &cfg, &opts, &|m| {
                if let Ok(mut p) = progress.lock() {
                    *p = m.to_string();
                }
                ctx2.request_repaint();
            });
            let _ = tx.send(Msg::Scan(Box::new(report)));
            ctx2.request_repaint();
        });
        self.rx = Some(rx);
    }

    fn start_self_test(&mut self, ctx: &egui::Context) {
        if self.busy() {
            return;
        }
        let (tx, rx) = channel();
        let progress = self.progress.clone();
        let ctx2 = ctx.clone();
        self.set_progress("Building the sandbox …");
        std::thread::spawn(move || {
            let res = scanner::sandbox::run_self_test(&|m| {
                if let Ok(mut p) = progress.lock() {
                    *p = m.to_string();
                }
                ctx2.request_repaint();
            });
            let _ = tx.send(Msg::SelfTest(res.map(Box::new).map_err(|e| format!("{e:#}"))));
            ctx2.request_repaint();
        });
        self.rx = Some(rx);
    }

    fn poll(&mut self) {
        let Some(rx) = &self.rx else { return };
        if let Ok(msg) = rx.try_recv() {
            match msg {
                Msg::Scan(r) => {
                    self.status = format!(
                        "Scan done in {:.1} s: {} findings ({} critical, {} high).",
                        r.duration_ms as f64 / 1000.0,
                        r.summary.total,
                        r.summary.critical,
                        r.summary.high
                    );
                    self.report = Some(*r);
                    if std::mem::take(&mut self.auto_export) {
                        self.export(false);
                        let txt_status = self.status.clone();
                        self.export(true);
                        self.status = format!("{} · {}", self.status, txt_status);
                    }
                    if self.tab == Tab::SelfTest {
                        self.tab = Tab::Findings;
                    }
                }
                Msg::SelfTest(Ok(res)) => {
                    self.status = format!("Self-test done: {} of {} rules fired as expected.", res.passed, res.checks.len());
                    self.self_test = Some(*res);
                    self.tab = Tab::SelfTest;
                }
                Msg::SelfTest(Err(e)) => self.status = format!("The self-test failed: {e}"),
            }
            self.rx = None;
        }
    }

    fn poll_sudo(&mut self, ctx: &egui::Context) {
        let Some(rx) = &self.sudo_result else { return };
        if let Ok(res) = rx.try_recv() {
            self.sudo_result = None;
            match res {
                // The root version has started in a new window – close this one.
                Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                Err(msg) => self.status = msg.to_string(),
            }
        }
    }

    fn handle_screenshot(&mut self, ctx: &egui::Context) {
        let busy = self.busy();
        let Some(shot) = &mut self.shot else { return };
        shot.frames += 1;
        ctx.request_repaint();
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaintWhileHidden);
        if shot.done.load(Ordering::SeqCst) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }
        let ready = (shot.frames >= 120 && !busy) || shot.frames >= 1200;
        if ready && !shot.requested {
            shot.requested = true;
            let path = shot.path.clone();
            let done = shot.done.clone();
            let ctx2 = ctx.clone();
            ctx.request_screenshot(move |img| {
                if let Err(e) = save_png(&path, &img) {
                    eprintln!("scanner: could not save the screenshot: {e}");
                }
                done.store(true, Ordering::SeqCst);
                ctx2.request_repaint();
            });
        }
    }

    // ------------------------------------------------------------- vyer

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            shield(ui);
            ui.vertical(|ui| {
                ui.label(RichText::new("Scanner").size(22.0).strong().color(Color32::WHITE));
                ui.label(RichText::new("Read-only intrusion and backdoor scanner for Debian 13 (Trixie)").color(MUTED));
            });
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let (txt, col) = if self.is_root { ("● Running as root – full coverage", OK) } else { ("● Not root – limited view", WARN) };
                if !self.is_root {
                    let waiting = self.sudo_result.is_some();
                    let label = if waiting { "Waiting for password …" } else { "🔑  Restart with sudo" };
                    let b = egui::Button::new(RichText::new(label).strong().color(Color32::WHITE)).fill(ACCENT);
                    if ui
                        .add_enabled(!waiting, b)
                        .on_hover_text("Asks for your sudo password and restarts the scanner with root privileges.")
                        .clicked()
                    {
                        let (tx, rx) = channel();
                        let ctx = ui.ctx().clone();
                        std::thread::spawn(move || {
                            let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).filter(|a| a != "--no-sudo").collect();
                            let _ = tx.send(crate::elevate::spawn_with_sudo(&args));
                            ctx.request_repaint();
                        });
                        self.sudo_result = Some(rx);
                    }
                }
                pill(ui, txt, col);
                if let Some(r) = &self.report {
                    ui.label(RichText::new(format!("{}  ·  {}  ·  kernel {}", r.hostname, r.os, r.kernel)).color(MUTED));
                }
            });
        });
        ui.add_space(6.0);
    }

    fn side_panel(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(6.0);
            let full = egui::Button::new(RichText::new("⚡  Full scan + save report").size(15.0).strong().color(Color32::WHITE))
                .fill(ACCENT)
                .min_size(egui::vec2(ui.available_width(), 34.0));
            if ui
                .add_enabled(!self.busy(), full)
                .on_hover_text("Runs all four modules and every installed external tool (can take a few minutes) and saves the report as JSON and text.")
                .clicked()
            {
                for (_, on) in &mut self.modules {
                    *on = true;
                }
                for (_, path, on) in &mut self.tools {
                    *on = path.is_some();
                }
                self.auto_export = true;
                self.start_scan(&ctx);
            }
            ui.label(RichText::new(format!("Saved to {}", self.export_path)).small().color(MUTED));
            ui.add_space(8.0);
            section(ui, "Modules");
            for (m, on) in &mut self.modules {
                ui.checkbox(on, RichText::new(m.label()).strong());
                ui.indent(m.id(), |ui| {
                    ui.label(RichText::new(m.describe()).small().color(MUTED));
                });
            }
            ui.checkbox(&mut self.deep_pid, "Deep PID scan (slow)");

            ui.add_space(8.0);
            section(ui, "External Debian tools");
            for (t, path, on) in &mut self.tools {
                let found = path.is_some();
                ui.add_enabled_ui(found, |ui| {
                    ui.checkbox(on, RichText::new(t.binary()).strong());
                });
                ui.indent(t.binary(), |ui| {
                    if found {
                        ui.label(RichText::new(t.describe()).small().color(MUTED));
                    } else {
                        ui.label(RichText::new(format!("missing – apt install {}", t.binary())).small().color(WARN));
                    }
                });
            }

            ui.add_space(8.0);
            section(ui, "Baseline");
            ui.label(RichText::new("Compare with file (empty = no comparison)").small().color(MUTED));
            ui.add(egui::TextEdit::singleline(&mut self.baseline_compare).hint_text("/var/lib/scanner/baseline.json").desired_width(f32::INFINITY));
            ui.label(RichText::new("Save the latest scan as a baseline").small().color(MUTED));
            ui.add(egui::TextEdit::singleline(&mut self.baseline_save).desired_width(f32::INFINITY));
            let can_save = self.report.is_some() && !self.baseline_save.trim().is_empty();
            if ui.add_enabled(can_save, egui::Button::new("Save baseline")).clicked() {
                if let Some(r) = &self.report {
                    let path = PathBuf::from(self.baseline_save.trim());
                    self.status = match Baseline::from_report(r).save(&path) {
                        Ok(()) => {
                            let missing: Vec<&str> = ModuleId::ALL.iter().filter(|m| !r.modules.iter().any(|x| x == m.id())).map(|m| m.id()).collect();
                            format!(
                                "Baseline saved to {} ({} SUID/SGID files, {} persistence files){}",
                                path.display(),
                                r.inventory.suid.len(),
                                r.inventory.persistence_files.len(),
                                if missing.is_empty() { String::new() } else { format!(" – note: {} was not included", missing.join(", ")) }
                            )
                        }
                        Err(e) => format!("Could not save the baseline: {e}"),
                    };
                }
            }

            ui.add_space(8.0);
            section(ui, "Whitelist");
            ui.add(egui::TextEdit::singleline(&mut self.cfg_path).hint_text("/etc/scanner/whitelist.toml").desired_width(f32::INFINITY));
            ui.horizontal(|ui| {
                if ui.button("Load").clicked() {
                    let p = PathBuf::from(self.cfg_path.trim());
                    self.status = match Config::load(&p) {
                        Ok(c) => {
                            self.cfg = c;
                            format!("Whitelist {} loaded.", p.display())
                        }
                        Err(e) => format!("{e}"),
                    };
                }
                if ui.button("Defaults").clicked() {
                    self.cfg = Config::default();
                    self.status = "The Debian 13 default whitelist is used.".into();
                }
            });
            ui.label(RichText::new(format!("{} known SUID files · {} allowed ports", self.cfg.allowed_suid.len(), self.cfg.allowed_listen_ports.len())).small().color(MUTED));

            ui.add_space(8.0);
            section(ui, "Root to scan");
            ui.add(egui::TextEdit::singleline(&mut self.root_path).desired_width(f32::INFINITY));
            ui.label(RichText::new("\"/\" = this system. Another directory is for mounted disks or tests.").small().color(MUTED));

            ui.add_space(14.0);
            let busy = self.busy();
            let big = egui::Button::new(RichText::new("▶  Start scan").size(16.0).strong().color(Color32::WHITE)).fill(ACCENT).min_size(egui::vec2(ui.available_width(), 36.0));
            if ui.add_enabled(!busy, big).clicked() {
                self.start_scan(&ctx);
            }
            let st = egui::Button::new("🧪  Run self-test in a sandbox").min_size(egui::vec2(ui.available_width(), 30.0));
            if ui.add_enabled(!busy, st).on_hover_text("Builds a made-up system with harmless test artefacts in a temporary directory and checks that the rules fire. Nothing on the computer is changed.").clicked() {
                self.start_self_test(&ctx);
            }
            ui.add_space(6.0);
            ui.label(RichText::new("The scanner only reads. It never changes, stops or removes anything.").small().color(MUTED));
        });
    }

    fn summary_cards(&self, ui: &mut egui::Ui) {
        let Some(r) = &self.report else { return };
        ui.columns(5, |cols| {
            for (i, sev) in Severity::ALL_DESC.iter().enumerate() {
                let n = r.summary.count(*sev);
                egui::Frame::new()
                    .fill(CARD)
                    .stroke(Stroke::new(1.0, if n > 0 { sev_color(*sev) } else { BORDER }))
                    .corner_radius(CornerRadius::same(8))
                    .inner_margin(Margin::symmetric(12, 8))
                    .show(&mut cols[i], |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(n.to_string()).size(26.0).strong().color(if n > 0 { sev_color(*sev) } else { MUTED }));
                            ui.label(RichText::new(sev.label()).color(MUTED));
                        });
                    });
            }
            egui::Frame::new().fill(CARD).stroke(Stroke::new(1.0, BORDER)).corner_radius(CornerRadius::same(8)).inner_margin(Margin::symmetric(12, 8)).show(&mut cols[4], |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(r.summary.total.to_string()).size(26.0).strong());
                    ui.vertical(|ui| {
                        ui.label(RichText::new(format!("findings in {:.1} s", r.duration_ms as f64 / 1000.0)).small().color(MUTED));
                        ui.label(RichText::new(format!("{} processes", r.inventory.process_count)).small().color(MUTED));
                    });
                });
            });
        });
    }

    fn tabs(&mut self, ui: &mut egui::Ui) {
        let (nf, nn, ns, np, nnotes) = match &self.report {
            Some(r) => (r.findings.len(), r.inventory.connections.len(), r.inventory.suid.len(), r.inventory.units.len(), r.notes.len()),
            None => (0, 0, 0, 0, 0),
        };
        ui.horizontal(|ui| {
            for (tab, label) in [
                (Tab::Findings, format!("Findings ({nf})")),
                (Tab::Network, format!("Network ({nn})")),
                (Tab::Suid, format!("SUID/SGID ({ns})")),
                (Tab::Persistence, format!("Persistence ({np})")),
                (Tab::Notes, format!("Notes ({nnotes})")),
                (Tab::SelfTest, "Self-test".to_string()),
            ] {
                let selected = self.tab == tab;
                let text = RichText::new(label).strong().color(if selected { Color32::WHITE } else { MUTED });
                let b = egui::Button::new(text).fill(if selected { CARD_HI } else { Color32::TRANSPARENT }).stroke(if selected { Stroke::new(1.0, ACCENT) } else { Stroke::NONE });
                if ui.add(b).clicked() {
                    self.tab = tab;
                }
            }
        });
    }

    fn findings_view(&mut self, ui: &mut egui::Ui) {
        let Some(r) = &self.report else {
            ui.label("No scan yet.");
            return;
        };
        let mut modules: Vec<String> = r.findings.iter().map(|f| f.module.clone()).collect();
        modules.sort();
        modules.dedup();
        ui.horizontal(|ui| {
            for (i, sev) in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low].iter().enumerate() {
                let on = self.show_sev[i];
                let b = egui::Button::new(RichText::new(sev.label()).color(if on { Color32::BLACK } else { MUTED }).strong())
                    .fill(if on { sev_color(*sev) } else { CARD })
                    .corner_radius(CornerRadius::same(10));
                if ui.add(b).clicked() {
                    self.show_sev[i] = !on;
                }
            }
            ui.add_space(10.0);
            egui::ComboBox::from_id_salt("modfilter").selected_text(format!("Module: {}", self.module_filter)).show_ui(ui, |ui| {
                ui.selectable_value(&mut self.module_filter, "all".to_string(), "all");
                for m in &modules {
                    ui.selectable_value(&mut self.module_filter, m.clone(), m);
                }
            });
            ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Search title, evidence, rule …").desired_width(260.0));
        });
        ui.add_space(4.0);
        let q = self.search.to_lowercase();
        let show_sev = self.show_sev;
        let module_filter = self.module_filter.clone();
        let visible: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| {
                let idx = match f.severity {
                    Severity::Critical => 0,
                    Severity::High => 1,
                    Severity::Medium => 2,
                    Severity::Low => 3,
                };
                show_sev[idx]
                    && (module_filter == "all" || f.module == module_filter)
                    && (q.is_empty() || f.title.to_lowercase().contains(&q) || f.evidence.to_lowercase().contains(&q) || f.rule.to_lowercase().contains(&q))
            })
            .collect();
        if visible.is_empty() {
            ui.add_space(20.0);
            ui.label(RichText::new(if r.findings.is_empty() { "No findings. Compare against a baseline regularly to detect changes." } else { "No findings match the filter." }).color(MUTED));
            return;
        }
        let ctx = ui.ctx().clone();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            for (i, f) in visible.iter().enumerate() {
                finding_card(ui, &ctx, i, f);
            }
        });
    }

    fn network_view(&self, ui: &mut egui::Ui) {
        let Some(r) = &self.report else { return };
        if r.inventory.connections.is_empty() {
            ui.label(RichText::new("No connections (run the Network and hidden processes module).").color(MUTED));
            return;
        }
        let mut conns = r.inventory.connections.clone();
        conns.sort_by(|a, b| b.listening.cmp(&a.listening).then(a.local_port.cmp(&b.local_port)));
        egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new("net").striped(true).num_columns(8).spacing([14.0, 4.0]).show(ui, |ui| {
                for h in ["Proto", "Local address", "Remote address", "State", "PID", "UID", "Process", "Command line"] {
                    ui.label(RichText::new(h).strong().color(MUTED));
                }
                ui.end_row();
                for c in conns.iter().take(2000) {
                    ui.label(&c.proto);
                    ui.monospace(format!("{}:{}", c.local_addr, c.local_port));
                    ui.monospace(if c.listening { "—".to_string() } else { format!("{}:{}", c.remote_addr, c.remote_port) });
                    ui.label(RichText::new(&c.state).color(if c.listening { ACCENT } else { TEXT }));
                    ui.label(c.pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into()));
                    ui.label(c.uid.to_string());
                    ui.label(c.process.clone().unwrap_or_else(|| "unknown".into()));
                    ui.label(RichText::new(scanner::modules::common::clip(c.cmdline.as_deref().unwrap_or(""), 70)).small().color(MUTED));
                    ui.end_row();
                }
            });
        });
    }

    fn suid_view(&self, ui: &mut egui::Ui) {
        let Some(r) = &self.report else { return };
        if r.inventory.suid.is_empty() {
            ui.label(RichText::new("No SUID/SGID list yet – tick \"File permissions and SUID/SGID\" and scan again.").color(MUTED));
            return;
        }
        egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new("suid").striped(true).num_columns(6).spacing([14.0, 4.0]).show(ui, |ui| {
                for h in ["Path", "Type", "Mode", "Owner", "Known", "SHA-256"] {
                    ui.label(RichText::new(h).strong().color(MUTED));
                }
                ui.end_row();
                for e in &r.inventory.suid {
                    let known = self.cfg.is_suid_allowed(&e.path);
                    ui.monospace(&e.path);
                    ui.label(match (e.suid, e.sgid) {
                        (true, true) => "SUID+SGID",
                        (true, false) => "SUID",
                        _ => "SGID",
                    });
                    ui.monospace(&e.mode);
                    ui.label(format!("{}:{}", e.uid, e.gid));
                    ui.label(RichText::new(if known { "yes" } else { "no" }).color(if known { OK } else { WARN }));
                    ui.monospace(RichText::new(e.sha256.as_deref().map(|h| &h[..16.min(h.len())]).unwrap_or("?")).color(MUTED));
                    ui.end_row();
                }
            });
        });
    }

    fn persistence_view(&self, ui: &mut egui::Ui) {
        let Some(r) = &self.report else { return };
        ui.label(RichText::new(format!("{} files that control automatic execution were hashed for the baseline.", r.inventory.persistence_files.len())).color(MUTED));
        ui.add_space(4.0);
        if r.inventory.units.is_empty() {
            ui.label(RichText::new("No locally created systemd units were found.").color(MUTED));
            return;
        }
        egui::ScrollArea::both().auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new("units").striped(true).num_columns(5).spacing([14.0, 4.0]).show(ui, |ui| {
                for h in ["Unit", "Type", "Enabled", "Active", "Command"] {
                    ui.label(RichText::new(h).strong().color(MUTED));
                }
                ui.end_row();
                for u in &r.inventory.units {
                    ui.monospace(&u.name);
                    ui.label(&u.scope);
                    ui.label(if u.enabled { "yes" } else { "no" });
                    ui.label(match u.active {
                        Some(true) => "yes",
                        Some(false) => "no",
                        None => "?",
                    });
                    ui.label(RichText::new(scanner::modules::common::clip(&u.exec.join(" | "), 90)).small().color(MUTED));
                    ui.end_row();
                }
            });
        });
    }

    fn notes_view(&self, ui: &mut egui::Ui) {
        let Some(r) = &self.report else { return };
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if r.notes.is_empty() {
                ui.label("No notes – everything could be read.");
            }
            for n in &r.notes {
                ui.label(format!("•  {n}"));
            }
            ui.add_space(10.0);
            ui.label(RichText::new(format!("Modules: {}", r.modules.join(", "))).color(MUTED));
            if !r.tools_run.is_empty() {
                ui.label(RichText::new(format!("External tools: {}", r.tools_run.join(", "))).color(MUTED));
            }
            if let Some(b) = &r.baseline_compared {
                ui.label(RichText::new(format!("Baseline: {b}")).color(MUTED));
            }
        });
    }

    fn self_test_view(&mut self, ui: &mut egui::Ui) {
        let Some(st) = &self.self_test else {
            ui.add_space(8.0);
            ui.label("The self-test builds a made-up Debian system in a temporary directory with harmless test artefacts:");
            for l in [
                "• a bash process whose standard input/output is connected to a TCP connection (reverse shell)",
                "• a deleted binary in /tmp listening on port 31337, a fileless memfd process and a fake [kworker]",
                "• a systemd service with base64, a cron job with curl | sh and an rc.local that starts from /dev/shm",
                "• authorized_keys with command=, PermitRootLogin yes, pam_permit and an extra UID 0 account",
                "• a SUID file in /tmp and a new SUID file compared against a baseline",
            ] {
                ui.label(RichText::new(l).color(MUTED));
            }
            ui.add_space(8.0);
            ui.label("Then it checks that every rule fires. Nothing on the real system is read or changed.");
            ui.add_space(8.0);
            let ctx = ui.ctx().clone();
            if ui.add_enabled(!self.busy(), egui::Button::new("Run self-test now")).clicked() {
                self.start_self_test(&ctx);
            }
            return;
        };
        let all_ok = st.failed == 0;
        ui.label(RichText::new(format!("{} of {} rules fired as expected", st.passed, st.checks.len())).size(18.0).strong().color(if all_ok { OK } else { WARN }));
        ui.add_space(6.0);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            egui::Grid::new("selftest").striped(true).num_columns(3).spacing([14.0, 4.0]).show(ui, |ui| {
                for c in &st.checks {
                    ui.label(RichText::new(if c.passed { "✔ OK" } else { "✘ FEL" }).strong().color(if c.passed { OK } else { sev_color(Severity::Critical) }));
                    ui.monospace(&c.rule);
                    ui.label(&c.what);
                    ui.end_row();
                }
            });
            ui.add_space(8.0);
            ui.label(RichText::new(format!("Sandbox report: {} findings ({} critical, {} high).", st.report.summary.total, st.report.summary.critical, st.report.summary.high)).color(MUTED));
        });
    }

    fn bottom_bar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            if self.busy() {
                ui.add(egui::Spinner::new());
                let p = self.progress.lock().map(|p| p.clone()).unwrap_or_default();
                ui.label(RichText::new(p).color(ACCENT));
            } else {
                ui.label(RichText::new(&self.status).color(MUTED));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let has = self.report.is_some();
                if ui.add_enabled(has, egui::Button::new("Export text")).clicked() {
                    self.export(false);
                }
                if ui.add_enabled(has, egui::Button::new("Export JSON")).clicked() {
                    self.export(true);
                }
                ui.add(egui::TextEdit::singleline(&mut self.export_path).desired_width(240.0));
                ui.label(RichText::new("Report file:").color(MUTED));
            });
        });
        ui.add_space(4.0);
    }

    fn export(&mut self, json: bool) {
        let Some(r) = &self.report else { return };
        let mut path = PathBuf::from(self.export_path.trim());
        if !json && path.extension().map(|e| e == "json").unwrap_or(false) {
            path.set_extension("txt");
        }
        let text = if json { r.to_json().map_err(|e| e.to_string()) } else { Ok(r.to_text(false)) };
        let result = text.and_then(|t| {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
                give_to_sudo_user(parent);
            }
            std::fs::write(&path, t).map_err(|e| e.to_string())?;
            give_to_sudo_user(&path);
            Ok(())
        });
        self.status = match result {
            Ok(()) => format!("The report was saved to {}", path.display()),
            Err(e) => format!("Could not save the report: {e}"),
        };
    }
}

impl eframe::App for ScannerApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.poll();
        self.poll_sudo(&ctx);
        self.handle_screenshot(&ctx);
        if self.busy() {
            ctx.request_repaint_after(std::time::Duration::from_millis(120));
        }

        egui::Panel::top("top").frame(egui::Frame::new().fill(BG).inner_margin(Margin::symmetric(14, 4))).show(ui, |ui| self.top_bar(ui));
        egui::Panel::bottom("bottom").frame(egui::Frame::new().fill(BG).inner_margin(Margin::symmetric(14, 2))).show(ui, |ui| self.bottom_bar(ui));
        egui::Panel::left("left")
            .default_size(300.0)
            .resizable(true)
            .frame(egui::Frame::new().fill(PANEL).inner_margin(Margin::symmetric(12, 6)).stroke(Stroke::new(1.0, BORDER)))
            .show(ui, |ui| self.side_panel(ui));
        egui::CentralPanel::default().frame(egui::Frame::new().fill(BG).inner_margin(Margin::symmetric(16, 10))).show(ui, |ui| {
            if self.report.is_none() && self.busy() {
                ui.add_space(60.0);
                ui.vertical_centered(|ui| {
                    ui.add(egui::Spinner::new().size(36.0));
                    ui.label(RichText::new(self.progress.lock().map(|p| p.clone()).unwrap_or_default()).size(16.0));
                });
                return;
            }
            self.summary_cards(ui);
            ui.add_space(8.0);
            self.tabs(ui);
            ui.separator();
            match self.tab {
                Tab::Findings => self.findings_view(ui),
                Tab::Network => self.network_view(ui),
                Tab::Suid => self.suid_view(ui),
                Tab::Persistence => self.persistence_view(ui),
                Tab::Notes => self.notes_view(ui),
                Tab::SelfTest => self.self_test_view(ui),
            }
        });
    }
}

fn finding_card(ui: &mut egui::Ui, ctx: &egui::Context, i: usize, f: &Finding) {
    let c = sev_color(f.severity);
    egui::Frame::new()
        .fill(CARD)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(6))
        .inner_margin(Margin { left: 0, right: 10, top: 6, bottom: 6 })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                // coloured edge
                let (rect, _) = ui.allocate_exact_size(egui::vec2(5.0, 22.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, CornerRadius::same(2), c);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        egui::Frame::new().fill(c).corner_radius(CornerRadius::same(4)).inner_margin(Margin::symmetric(6, 1)).show(ui, |ui| {
                            ui.label(RichText::new(f.severity.label().to_uppercase()).small().strong().color(Color32::BLACK));
                        });
                        ui.label(RichText::new(format!("{} · {}", f.module, f.rule)).small().color(MUTED));
                    });
                    egui::CollapsingHeader::new(RichText::new(&f.title).strong().color(Color32::WHITE)).id_salt(("finding", i, &f.rule)).show(ui, |ui| {
                        if !f.description.is_empty() {
                            ui.label(&f.description);
                        }
                        if !f.evidence.is_empty() {
                            ui.add_space(4.0);
                            ui.label(RichText::new("Evidence").strong().color(MUTED));
                            egui::Frame::new().fill(BG).corner_radius(CornerRadius::same(4)).inner_margin(Margin::same(8)).show(ui, |ui| {
                                ui.set_width(ui.available_width());
                                ui.label(RichText::new(&f.evidence).monospace().size(12.0));
                            });
                        }
                        if !f.verify.is_empty() {
                            ui.add_space(4.0);
                            ui.label(RichText::new("Verify manually").strong().color(MUTED));
                            for v in &f.verify {
                                ui.horizontal(|ui| {
                                    if ui.small_button("Copy").clicked() {
                                        ctx.copy_text(v.clone());
                                    }
                                    ui.label(RichText::new(format!("$ {v}")).monospace().size(12.0).color(ACCENT));
                                });
                            }
                        }
                    });
                });
            });
        });
    ui.add_space(4.0);
}

/// Where the report is saved by default: in the project's reports/ directory when the program runs
/// from its build directory (…/app/target/…), otherwise in the home directory of whoever started it
/// (also when it runs through sudo).
fn default_report_path() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let s = exe.display().to_string();
        if let Some(idx) = s.find("/target/") {
            return PathBuf::from(&s[..idx]).join("reports").join("scanner-report.json");
        }
    }
    let home = std::env::var("SUDO_USER")
        .ok()
        .and_then(|u| scanner::procinfo::read_accounts(&SysRoot::live()).into_iter().find(|a| a.name == u).map(|a| a.home))
        .or_else(|| std::env::var("HOME").ok())
        .unwrap_or_else(|| "/tmp".into());
    PathBuf::from(home).join("scanner-report.json")
}

/// When the program runs through sudo: let the file be owned by whoever started it, so it
/// can be read and removed without root.
fn give_to_sudo_user(path: &std::path::Path) {
    let uid = std::env::var("SUDO_UID").ok().and_then(|v| v.parse::<u32>().ok());
    let gid = std::env::var("SUDO_GID").ok().and_then(|v| v.parse::<u32>().ok());
    if uid.is_some() && scanner::sys::is_root() {
        let _ = std::os::unix::fs::chown(path, uid, gid);
    }
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.label(RichText::new(title.to_uppercase()).small().strong().color(ACCENT));
    ui.add_space(2.0);
}

fn pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    egui::Frame::new().fill(color.linear_multiply(0.18)).stroke(Stroke::new(1.0, color)).corner_radius(CornerRadius::same(12)).inner_margin(Margin::symmetric(10, 3)).show(ui, |ui| {
        ui.label(RichText::new(text).color(color).strong());
    });
}

/// A simple shield drawn with shapes (no image file).
fn shield(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(40.0, 44.0), egui::Sense::hover());
    let p = ui.painter();
    let c = rect.center();
    let pts = vec![
        egui::pos2(c.x, rect.top() + 2.0),
        egui::pos2(rect.right() - 3.0, rect.top() + 9.0),
        egui::pos2(rect.right() - 5.0, c.y + 6.0),
        egui::pos2(c.x, rect.bottom() - 2.0),
        egui::pos2(rect.left() + 5.0, c.y + 6.0),
        egui::pos2(rect.left() + 3.0, rect.top() + 9.0),
    ];
    p.add(egui::Shape::convex_polygon(pts, ACCENT.linear_multiply(0.35), Stroke::new(2.0, ACCENT)));
    p.circle_stroke(egui::pos2(c.x - 2.0, c.y - 2.0), 7.0, Stroke::new(2.5, Color32::WHITE));
    p.line_segment([egui::pos2(c.x + 3.0, c.y + 3.0), egui::pos2(c.x + 9.0, c.y + 9.0)], Stroke::new(3.0, Color32::WHITE));
}

fn save_png(path: &std::path::Path, img: &egui::ColorImage) -> Result<(), String> {
    let [w, h] = img.size;
    let mut bytes = Vec::with_capacity(w * h * 4);
    for px in &img.pixels {
        bytes.extend_from_slice(&px.to_srgba_unmultiplied());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
    }
    image::save_buffer(path, &bytes, w as u32, h as u32, image::ExtendedColorType::Rgba8).map_err(|e| e.to_string())
}

pub fn run(cfg: Config, cfg_path: Option<PathBuf>, screenshot: Option<PathBuf>, sudo_note: Option<String>) -> anyhow::Result<()> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Scanner – intrusion and backdoor scanner for Debian 13")
        .with_inner_size([1360.0, 860.0])
        .with_min_inner_size([960.0, 620.0]);
    if screenshot.is_some() {
        // Do not take focus from what the person is doing while the picture is taken.
        viewport = viewport.with_active(false);
    }
    let options = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "scanner",
        options,
        Box::new(move |cc| Ok(Box::new(ScannerApp::new(cc, cfg, cfg_path, screenshot, sudo_note)))),
    )
    .map_err(|e| anyhow::anyhow!("the window could not start: {e}"))
}

// ------------------------------------------------------------------ password window

/// Small window that sudo uses as SUDO_ASKPASS: prints the password on stdout.
struct AskPass {
    prompt: String,
    password: String,
    answer: Arc<Mutex<Option<String>>>,
    focus_set: bool,
    shot: Option<Shot>,
}

impl eframe::App for AskPass {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if let Some(shot) = &mut self.shot {
            shot.frames += 1;
            ctx.request_repaint();
            if shot.done.load(Ordering::SeqCst) {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            } else if shot.frames >= 60 && !shot.requested {
                shot.requested = true;
                let (path, done) = (shot.path.clone(), shot.done.clone());
                ctx.request_screenshot(move |img| {
                    let _ = save_png(&path, &img);
                    done.store(true, Ordering::SeqCst);
                });
            }
        }
        let mut submit = false;
        let mut cancel = false;
        egui::CentralPanel::default().frame(egui::Frame::new().fill(PANEL).inner_margin(Margin::same(18))).show(ui, |ui| {
            ui.horizontal(|ui| {
                shield(ui);
                ui.vertical(|ui| {
                    ui.label(RichText::new("Scanner needs root privileges").size(18.0).strong().color(Color32::WHITE));
                    ui.label(RichText::new("To see every process, key and scheduled job the scanner starts with sudo. It still changes nothing.").color(MUTED));
                });
            });
            ui.add_space(12.0);
            ui.label(RichText::new(&self.prompt).strong());
            let resp = ui.add(egui::TextEdit::singleline(&mut self.password).password(true).desired_width(f32::INFINITY).hint_text("sudo password"));
            if !self.focus_set {
                resp.request_focus();
                self.focus_set = true;
            }
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                submit = true;
            }
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if ui.add(egui::Button::new(RichText::new("Start with sudo").strong().color(Color32::WHITE)).fill(ACCENT)).clicked() {
                    submit = true;
                }
                if ui.button("Cancel (run without root)").clicked() {
                    cancel = true;
                }
            });
        });
        if ui.input(|i| i.key_pressed(egui::Key::Escape)) {
            cancel = true;
        }
        if submit {
            if let Ok(mut a) = self.answer.lock() {
                *a = Some(std::mem::take(&mut self.password));
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        } else if cancel {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

/// Show the password window. Exit code 0 = password printed on stdout, 1 = cancelled.
pub fn run_askpass(prompt: String) -> u8 {
    use std::io::Write;
    let answer: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let shot = std::env::var_os("SCANNER_ASKPASS_SHOT")
        .map(|p| Shot { path: PathBuf::from(p), frames: 0, requested: false, done: Arc::new(AtomicBool::new(false)) });
    let viewport = egui::ViewportBuilder::default()
        .with_title("Scanner – sudo password")
        .with_inner_size([480.0, 240.0])
        .with_resizable(false)
        .with_active(shot.is_none());
    let options = eframe::NativeOptions { viewport, centered: true, ..Default::default() };
    let a2 = answer.clone();
    let prompt = if prompt.trim().is_empty() { "Password:".to_string() } else { prompt };
    let res = eframe::run_native(
        "scanner-askpass",
        options,
        Box::new(move |cc| {
            cc.egui_ctx.set_theme(egui::Theme::Dark);
            Ok(Box::new(AskPass { prompt, password: String::new(), answer: a2, focus_set: false, shot }))
        }),
    );
    if res.is_err() {
        return 1;
    }
    let pw = answer.lock().ok().and_then(|mut a| a.take());
    match pw {
        Some(pw) => {
            let mut out = std::io::stdout();
            if writeln!(out, "{pw}").and_then(|_| out.flush()).is_ok() {
                0
            } else {
                1
            }
        }
        None => 1,
    }
}
