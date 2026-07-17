use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Terminal;
use sysinfo::System;

use crate::collect;
use crate::config::Settings;
use crate::ui::chrome;
use crate::ui::format::{set_unit_mode, UnitMode};
use crate::ui::palette as p;

const SAMPLE_INTERVAL_STEP: Duration = Duration::from_millis(100);
pub const MIN_SAMPLE_INTERVAL: Duration = Duration::from_millis(100);
pub const MAX_SAMPLE_INTERVAL: Duration = Duration::from_secs(10);
const CPU_HISTORY_LEN: usize = 16;
const USAGE_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const METADATA_REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const BACKGROUND_COLLECTOR_POLL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveState {
    Live,
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailTab {
    Disk,
    Vfs,
}

pub struct App {
    pub live: LiveState,
    pub devices: Vec<collect::DeviceTick>,
    pub filesystems: Vec<collect::FsTick>,
    pub volumes: collect::VolumeTick,
    pub io: collect::IoCollector,
    pub io_show_unmounted: bool,
    pub settings: Settings,
    pub show_settings: bool,
    pub smart: collect::SmartCollector,
    pub selected_io: usize,
    pub detail_tab: DetailTab,
    pub sample_interval: Duration,
    pub cpu_usage: f64,
    pub cpu_history: VecDeque<f64>,
    cpu_system: System,
    /// Latest slow collector state published by the background TUI thread.
    background_snapshot: Option<Arc<Mutex<CollectorSnapshot>>>,
    /// Remaining sampled intervals before clean exit; must be at least one when set.
    remaining_intervals: Option<u64>,
    pub should_quit: bool,
}

#[derive(Clone)]
struct CollectorSnapshot {
    devices: Vec<collect::DeviceTick>,
    filesystems: Vec<collect::FsTick>,
    volumes: collect::VolumeTick,
    smart_by_device: std::collections::HashMap<String, collect::smart::SmartTick>,
}

impl CollectorSnapshot {
    fn from_state(
        devices: Vec<collect::DeviceTick>,
        filesystems: Vec<collect::FsTick>,
        volumes: collect::VolumeTick,
        smart: &collect::SmartCollector,
    ) -> Self {
        Self {
            devices,
            filesystems,
            volumes,
            smart_by_device: smart.by_device.clone(),
        }
    }
}

impl App {
    fn new(sample_interval: Duration, remaining_intervals: Option<u64>) -> Self {
        let settings = Settings::load();
        set_unit_mode(settings.unit_mode);
        let devices = collect::devices::collect();
        let filesystems = collect::filesystems::collect();
        let volumes = collect::volumes::collect();
        let mut io = collect::IoCollector::new();
        io.prime();
        let mut cpu_system = System::new();
        cpu_system.refresh_cpu_usage();
        let mut smart = collect::SmartCollector::new();
        smart.refresh_if_due(&devices);
        let background_snapshot = Some(spawn_background_collector(CollectorSnapshot::from_state(
            devices.clone(),
            filesystems.clone(),
            volumes.clone(),
            &smart,
        )));
        Self {
            live: LiveState::Live,
            sample_interval,
            cpu_usage: 0.0,
            cpu_history: VecDeque::with_capacity(CPU_HISTORY_LEN),
            cpu_system,
            selected_io: 0,
            detail_tab: DetailTab::Disk,
            devices,
            filesystems,
            volumes,
            io,
            io_show_unmounted: settings.io_show_unmounted,
            settings,
            show_settings: false,
            smart,
            background_snapshot,
            remaining_intervals,
            should_quit: false,
        }
    }

    fn persist_settings(&mut self) {
        self.settings.io_show_unmounted = self.io_show_unmounted;
        set_unit_mode(self.settings.unit_mode);
        self.settings.save();
    }

    fn toggle_unit_mode(&mut self) {
        self.settings.unit_mode = self.settings.unit_mode.toggle();
        self.persist_settings();
    }

    fn toggle_io_unmounted(&mut self) {
        self.io_show_unmounted = !self.io_show_unmounted;
        self.selected_io = 0;
        self.persist_settings();
    }

    fn toggle_detail_tab(&mut self) {
        self.detail_tab = match self.detail_tab {
            DetailTab::Disk => DetailTab::Vfs,
            DetailTab::Vfs => DetailTab::Disk,
        };
    }

    fn decrease_sample_interval(&mut self) {
        self.sample_interval = self
            .sample_interval
            .saturating_sub(SAMPLE_INTERVAL_STEP)
            .max(MIN_SAMPLE_INTERVAL);
    }

    fn increase_sample_interval(&mut self) {
        self.sample_interval =
            (self.sample_interval + SAMPLE_INTERVAL_STEP).min(MAX_SAMPLE_INTERVAL);
    }

    fn note_interval_completed(&mut self) {
        let Some(remaining) = self.remaining_intervals else {
            return;
        };
        self.remaining_intervals = Some(remaining.saturating_sub(1));
        if self.remaining_intervals == Some(0) {
            self.should_quit = true;
        }
    }

    fn tick(&mut self) {
        self.apply_background_snapshot();
        // The collector forms calm display buckets at the selected cadence.
        // The eBPF backend still accounts for every request between polls.
        if self.io.sample(self.sample_interval) {
            self.cpu_system.refresh_cpu_usage();
            let usage = self.cpu_system.global_cpu_usage() as f64;
            if usage.is_finite() {
                self.cpu_usage = usage.clamp(0.0, 100.0);
                self.cpu_history.push_back(self.cpu_usage);
                if self.cpu_history.len() > CPU_HISTORY_LEN {
                    self.cpu_history.pop_front();
                }
            }
            self.note_interval_completed();
        }
        let visible_io = crate::screen::visible_device_count(self);
        self.selected_io = self.selected_io.min(visible_io.saturating_sub(1));
    }

    fn apply_background_snapshot(&mut self) {
        let Some(snapshot) = &self.background_snapshot else {
            return;
        };
        let Ok(snapshot) = snapshot.lock() else {
            return;
        };
        self.devices.clone_from(&snapshot.devices);
        self.filesystems.clone_from(&snapshot.filesystems);
        self.volumes = snapshot.volumes.clone();
        self.smart.by_device.clone_from(&snapshot.smart_by_device);
    }
}

fn spawn_background_collector(initial: CollectorSnapshot) -> Arc<Mutex<CollectorSnapshot>> {
    let shared = Arc::new(Mutex::new(initial.clone()));
    let thread_shared = Arc::clone(&shared);
    thread::spawn(move || {
        let mut devices = initial.devices;
        let mut filesystems = initial.filesystems;
        let mut volumes = initial.volumes;
        let mut smart = collect::SmartCollector::new();
        smart.by_device = initial.smart_by_device;
        let mut last_usage_refresh = Instant::now();
        let mut last_metadata_refresh = Instant::now();
        loop {
            if last_usage_refresh.elapsed() >= USAGE_REFRESH_INTERVAL {
                collect::devices::refresh_usage(&mut devices);
                filesystems = collect::filesystems::collect();
                last_usage_refresh = Instant::now();
            }
            if last_metadata_refresh.elapsed() >= METADATA_REFRESH_INTERVAL {
                devices = collect::devices::collect();
                volumes = collect::volumes::collect();
                last_metadata_refresh = Instant::now();
            }
            smart.refresh_if_due(&devices);
            if let Ok(mut snapshot) = thread_shared.lock() {
                *snapshot = CollectorSnapshot::from_state(
                    devices.clone(),
                    filesystems.clone(),
                    volumes.clone(),
                    &smart,
                );
            }
            thread::sleep(BACKGROUND_COLLECTOR_POLL);
        }
    });
    shared
}

/// Run TUI mode, optionally exiting after at least one sampled interval.
pub fn run(sample_interval: Duration, intervals: Option<u64>) -> Result<()> {
    let mut app = App::new(sample_interval, intervals);

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = main_loop(&mut terminal, &mut app);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

fn main_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    // Input wakes the poll immediately; this only caps idle redraws at 10 FPS.
    let frame_budget = Duration::from_millis(100);
    let mut redraw = true;
    loop {
        if matches!(app.live, LiveState::Live) || redraw {
            terminal.draw(|f| draw(f, app))?;
            redraw = false;
        }
        if event::poll(frame_budget)? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Release {
                    handle_key(app, k.code);
                    if app.should_quit {
                        // Skip the final collector/metadata tick. Returning
                        // still restores the terminal; process teardown can
                        // reclaim collector and eBPF resources.
                        return Ok(());
                    }
                    redraw = true;
                }
            }
        }
        app.tick();
        if app.should_quit {
            terminal.draw(|f| draw(f, app))?;
            return Ok(());
        }
    }
}

fn handle_key(app: &mut App, key: KeyCode) {
    if app.show_settings {
        match key {
            KeyCode::Esc | KeyCode::Char(',') => app.show_settings = false,
            KeyCode::Char('b') => app.toggle_unit_mode(),
            KeyCode::Char('u') => app.toggle_io_unmounted(),
            KeyCode::Char('-') => app.decrease_sample_interval(),
            KeyCode::Char('+') | KeyCode::Char('=') => app.increase_sample_interval(),
            KeyCode::Char('q') => app.should_quit = true,
            _ => {}
        }
        return;
    }

    match key {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char(',') => app.show_settings = true,
        KeyCode::Char('p') => {
            app.live = match app.live {
                LiveState::Live => LiveState::Paused,
                LiveState::Paused => LiveState::Live,
            };
        }
        KeyCode::Char('u') => app.toggle_io_unmounted(),
        KeyCode::Tab => app.toggle_detail_tab(),
        KeyCode::Char('-') => app.decrease_sample_interval(),
        KeyCode::Char('+') | KeyCode::Char('=') => app.increase_sample_interval(),
        KeyCode::Up | KeyCode::Char('k') if app.selected_io > 0 => app.selected_io -= 1,
        KeyCode::Down | KeyCode::Char('j')
            if app.selected_io + 1 < crate::screen::visible_device_count(app) =>
        {
            app.selected_io += 1
        }
        _ => {}
    }
}

fn draw(f: &mut ratatui::Frame, app: &App) {
    // Paint the whole canvas with the terminal-bg before chrome draws, so
    // unfilled regions don't show through with the host terminal's default.
    let full = f.area();
    f.render_widget(Paragraph::new("").style(Style::default().bg(p::BG)), full);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(1),    // content
            Constraint::Length(1), // footer
        ])
        .split(full);

    let content = Rect {
        x: layout[0].x,
        y: layout[0].y,
        width: layout[0].width,
        height: layout[0].height,
    };
    crate::screen::draw(f, content, app);
    if app.show_settings {
        draw_settings_overlay(f, full, app);
    }
    let collection_source = match app.io.latency_source() {
        collect::ebpf::LatencySource::AggregateAwait => "AGGREGATE AWAIT",
        collect::ebpf::LatencySource::EbpfPerRequest => "PER-REQUEST eBPF",
    };
    chrome::draw_footer(f, layout[1], app.io_show_unmounted, collection_source);
}

fn draw_settings_overlay(f: &mut ratatui::Frame, area: Rect, app: &App) {
    let w = area.width.min(64);
    let h = 10.min(area.height);
    let popup = Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    f.render_widget(Clear, popup);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(p::CYAN).bg(p::BG))
        .title(Span::styled(
            " Settings ",
            Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(p::BG));
    let inner = block.inner(popup);
    f.render_widget(block, popup);

    let io_mode = if app.io_show_unmounted {
        "all devices"
    } else {
        "mounted only"
    };
    let unit_hint = match app.settings.unit_mode {
        UnitMode::Binary => "b toggles to decimal KB/MB",
        UnitMode::Decimal => "b toggles to binary KiB/MiB",
    };
    let lines = vec![
        Line::from(vec![
            Span::styled(
                " b ",
                Style::default().fg(p::YELLOW).add_modifier(Modifier::BOLD),
            ),
            Span::styled("units        ", Style::default().fg(p::DIM)),
            Span::styled(app.settings.unit_mode.label(), Style::default().fg(p::FG)),
        ]),
        Line::from(Span::styled(
            format!("   {unit_hint}"),
            Style::default().fg(p::DIM),
        )),
        Line::from(""),
        Line::from(vec![
            Span::styled(
                " u ",
                Style::default().fg(p::YELLOW).add_modifier(Modifier::BOLD),
            ),
            Span::styled("device view  ", Style::default().fg(p::DIM)),
            Span::styled(io_mode, Style::default().fg(p::FG)),
        ]),
        Line::from(Span::styled(
            "   persists to ~/.config/iodyne/config.json",
            Style::default().fg(p::DIM),
        )),
        Line::from(""),
        Line::from(Span::styled(
            " Esc or , closes settings",
            Style::default().fg(p::DIM),
        )),
    ];
    f.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Left)
            .style(Style::default().bg(p::BG)),
        inner,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collect::devices::{DeviceKind, DeviceTick};
    use crate::collect::io::{
        AwaitSample, DeviceHistory, IoCollector, IoTick, LatencyPct, MergeRates,
        TracedLatencySample, WorkloadSample,
    };
    use crate::collect::smart::{SmartCollector, SmartTick};
    use crate::collect::{FsTick, VolumeTick};
    use ratatui::backend::TestBackend;
    use std::collections::VecDeque;

    #[test]
    fn devices_collector_returns_something() {
        // Smoke test on whichever platform `cargo test` runs on. We don't
        // assert specific counts — CI VMs vary — only that it doesn't
        // panic and (on a real workstation) it sees at least one disk.
        let devs = crate::collect::devices::collect();
        if !devs.is_empty() {
            let d = &devs[0];
            assert!(!d.name.is_empty(), "device name should not be empty");
            // On macOS we expect model + protocol to be filled in.
            #[cfg(target_os = "macos")]
            {
                assert!(d.size_bytes > 0, "macOS device should report size");
                assert!(
                    !d.model.is_empty() && d.model != "Unknown",
                    "macOS device should have a model"
                );
            }
        }
    }

    fn fixture_app(populated: bool) -> App {
        let mut io = IoCollector::new_for_test();
        if populated {
            let workload = WorkloadSample {
                read_iops: 120.0,
                write_iops: 45.0,
                read_bps: 24.0 * 1024.0 * 1024.0,
                write_bps: 8.0 * 1024.0 * 1024.0,
                read_request_bytes: Some(128.0 * 1024.0),
                write_request_bytes: Some(64.0 * 1024.0),
                merge_rates: MergeRates::Available {
                    read_per_sec: 3.0,
                    write_per_sec: 2.0,
                },
            };
            let await_sample = AwaitSample {
                read_us: Some(850.0),
                write_us: Some(4_200.0),
            };
            io.latest.push(IoTick {
                device: "sda".into(),
                bps: workload.read_bps + workload.write_bps,
                split: Some((workload.read_bps, workload.write_bps)),
                iops: workload.read_iops + workload.write_iops,
                iops_split: Some((workload.read_iops, workload.write_iops)),
                avg_request_bytes: Some(96.0 * 1024.0),
                queue_depth: Some(1.5),
                await_sample,
                latency_avg: Some((850.0, 4_200.0)),
                latency_pct: Some(LatencyPct {
                    p50_r: 700.0,
                    p99_r: 1_800.0,
                    p999_r: 2_100.0,
                    p50_w: 3_500.0,
                    p99_w: 9_000.0,
                    p999_w: 12_000.0,
                }),
            });
            io.history.insert(
                "sda".into(),
                DeviceHistory {
                    combined: VecDeque::from(vec![workload.read_bps + workload.write_bps; 24]),
                    workload_samples: VecDeque::from(vec![workload; 24]),
                    await_samples: VecDeque::from(vec![await_sample; 24]),
                    read_us: VecDeque::from(vec![850.0; 24]),
                    write_us: VecDeque::from(vec![4_200.0; 24]),
                },
            );
            let mut traced = TracedLatencySample::default();
            traced.read[8] = 120;
            traced.write[14] = 45;
            io.traced_history
                .insert("sda".into(), VecDeque::from(vec![traced; 24]));
        }

        let devices = vec![DeviceTick {
            name: "sda".into(),
            kind: DeviceKind::Ssd,
            model: "Fixture SSD".into(),
            bus: "SATA".into(),
            size_bytes: 1_000_000_000_000,
            used_bytes: 400_000_000_000,
            is_removable: false,
            firmware: Some("1.0".into()),
            serial: Some("fixture".into()),
            smart_ok: Some(true),
            idle: false,
        }];
        let filesystems = vec![FsTick {
            mount: "/mnt/data".into(),
            device: "/dev/sda1".into(),
            fs_type: "ext4".into(),
            size_bytes: 1_000_000_000_000,
            used_bytes: 400_000_000_000,
            avail_bytes: 600_000_000_000,
            inode_pct: Some(12),
            is_removable: false,
            is_system: false,
        }];
        let mut smart = SmartCollector::new();
        smart.by_device.insert(
            "sda".into(),
            SmartTick {
                device: "sda".into(),
                temperature_c: Some(34),
                power_on_hours: Some(1_200),
                percentage_used: Some(7),
                available_spare: Some(100),
                ..Default::default()
            },
        );

        App {
            live: LiveState::Live,
            sample_interval: collect::io::DEFAULT_SAMPLE_INTERVAL,
            cpu_usage: 37.0,
            cpu_history: VecDeque::from([8.0, 14.0, 31.0, 22.0, 37.0]),
            cpu_system: System::new(),
            devices,
            filesystems,
            volumes: VolumeTick::default(),
            io,
            io_show_unmounted: false,
            settings: Settings::default(),
            show_settings: false,
            smart,
            selected_io: 0,
            detail_tab: DetailTab::Disk,
            background_snapshot: None,
            remaining_intervals: None,
            should_quit: false,
        }
    }

    fn render_screen(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut term = Terminal::new(backend).expect("terminal");
        term.draw(|f| super::draw(f, app)).expect("draw");
        let buffer = term.backend().buffer();
        (0..height)
            .map(|y| {
                (0..width)
                    .map(|x| buffer.cell((x, y)).unwrap().symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn assert_populated_screen(width: u16, height: u16) {
        let text = render_screen(&fixture_app(true), width, height);
        for expected in [
            "Device", "Free", "B/s", "IOPS", "1 device", "2000ms", "CPU 37%", "READ", "WRITE",
            "Await", "DISK",
        ] {
            assert!(
                text.contains(expected),
                "missing {expected:?} at {width}x{height}"
            );
        }
        for removed in [
            "j/k selects detail",
            "latency distribution",
            "requested rates",
            "VFS activity",
            "all | 1 device",
        ] {
            assert!(
                !text.contains(removed),
                "stale {removed:?} at {width}x{height}"
            );
        }
        assert!(text.lines().any(|line| line.starts_with('┌')));
        assert!(text.lines().any(|line| line.starts_with('│')));
    }

    #[test]
    fn populated_screen_renders_overview_and_detail_at_responsive_sizes() {
        assert_populated_screen(130, 36);
        assert_populated_screen(110, 30);
        let _ = render_screen(&fixture_app(true), 60, 20);
        let _ = render_screen(&fixture_app(true), 24, 10);
    }

    #[test]
    fn clipped_device_overview_and_global_footer_show_navigation_context() {
        let mut app = fixture_app(true);
        let template = app.io.latest[0].clone();
        for suffix in ['b', 'c', 'd', 'e', 'f', 'g', 'h'] {
            let mut tick = template.clone();
            tick.device = format!("sd{suffix}");
            app.io.latest.push(tick);
        }
        app.io_show_unmounted = true;
        app.selected_io = 8;

        let screen = render_screen(&app, 130, 28);
        assert!(screen.contains("DEVICES 3–8 of 8"));
        assert!(screen.contains('↑'));
        assert!(screen.contains('↓'));
        let source_line = screen
            .lines()
            .find(|line| line.contains("AGGREGATE AWAIT") || line.contains("PER-REQUEST eBPF"))
            .expect("collection source title");
        assert!(
            source_line
                .find("AGGREGATE AWAIT")
                .or_else(|| source_line.find("PER-REQUEST eBPF"))
                .is_some_and(|x| x > 100),
            "source was not lower-right aligned: {source_line:?}"
        );
    }

    #[test]
    fn detail_tabs_switch_and_remain_contiguous_with_footer() {
        let mut app = fixture_app(true);
        assert_eq!(app.detail_tab, DetailTab::Disk);
        handle_key(&mut app, KeyCode::Tab);
        assert_eq!(app.detail_tab, DetailTab::Vfs);

        let screen = render_screen(&app, 130, 36);
        let lines: Vec<_> = screen.lines().collect();
        let vfs_y = lines
            .iter()
            .position(|line| line.contains(" VFS | 10s"))
            .expect("VFS pane title");

        assert!(lines[vfs_y].starts_with('┌'));
        assert!(lines[vfs_y - 1].contains("DISK"));
        assert!(lines[vfs_y - 1].contains("VFS"));
        assert!(lines[lines.len() - 2].starts_with('└'));
        assert!(lines.last().unwrap().contains("p:Pause"));

        handle_key(&mut app, KeyCode::Tab);
        assert_eq!(app.detail_tab, DetailTab::Disk);
    }

    #[test]
    fn empty_and_undersized_screens_render_without_panicking() {
        let app = fixture_app(false);
        let empty = render_screen(&app, 130, 40);
        assert!(empty.contains("No IO data yet"));
        assert!(empty.contains("2000ms"));
        assert!(empty.contains("CPU 37%"));
        let _ = render_screen(&app, 60, 20);
    }

    #[test]
    fn paused_header_replaces_sampling_control() {
        let mut app = fixture_app(false);
        handle_key(&mut app, KeyCode::Char('p'));
        let screen = render_screen(&app, 130, 20);

        assert!(screen.contains("PAUSED"));
        assert!(!screen.contains("2000ms"));
        assert!(screen.contains("CPU 37%"));
    }

    #[test]
    fn numeric_keys_have_no_navigation_behavior() {
        let mut app = fixture_app(false);
        let before = (
            app.selected_io,
            app.io_show_unmounted,
            app.live,
            app.show_settings,
            app.should_quit,
        );

        for key in '0'..='9' {
            handle_key(&mut app, KeyCode::Char(key));
        }

        assert_eq!(
            before,
            (
                app.selected_io,
                app.io_show_unmounted,
                app.live,
                app.show_settings,
                app.should_quit,
            )
        );
    }

    #[test]
    fn sampling_hotkeys_adjust_and_clamp_the_interval() {
        let mut app = fixture_app(false);
        assert_eq!(app.sample_interval, Duration::from_secs(2));

        handle_key(&mut app, KeyCode::Char('-'));
        assert_eq!(app.sample_interval, Duration::from_millis(1_900));
        handle_key(&mut app, KeyCode::Char('+'));
        assert_eq!(app.sample_interval, Duration::from_secs(2));

        app.sample_interval = MIN_SAMPLE_INTERVAL;
        handle_key(&mut app, KeyCode::Char('-'));
        assert_eq!(app.sample_interval, MIN_SAMPLE_INTERVAL);
        app.sample_interval = MAX_SAMPLE_INTERVAL;
        handle_key(&mut app, KeyCode::Char('+'));
        assert_eq!(app.sample_interval, MAX_SAMPLE_INTERVAL);
    }

    #[test]
    fn interval_quota_sets_quit_only_when_configured() {
        let mut app = fixture_app(false);
        app.remaining_intervals = Some(1);

        app.note_interval_completed();

        assert_eq!(app.remaining_intervals, Some(0));
        assert!(app.should_quit);

        let mut app = fixture_app(false);
        app.note_interval_completed();

        assert_eq!(app.remaining_intervals, None);
        assert!(!app.should_quit);
    }

    #[test]
    fn selection_moves_from_all_to_the_last_physical_device() {
        let mut app = fixture_app(true);
        assert_eq!(crate::screen::visible_device_count(&app), 2);
        assert_eq!(app.selected_io, 0);

        handle_key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.selected_io, 1);
        handle_key(&mut app, KeyCode::Char('j'));
        assert_eq!(app.selected_io, 1);
        handle_key(&mut app, KeyCode::Char('k'));
        assert_eq!(app.selected_io, 0);
    }
}
