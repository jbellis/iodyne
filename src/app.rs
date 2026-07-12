use std::io;
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

use crate::collect;
use crate::config::Settings;
use crate::ui::chrome;
use crate::ui::format::{set_unit_mode, UnitMode};
use crate::ui::palette as p;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveState {
    Live,
    Paused,
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
    /// Last full enumeration (slow path — system_profiler + diskutil).
    last_metadata_refresh: Instant,
    /// Last usage refresh (fast path — sysinfo only).
    last_usage_refresh: Instant,
    pub should_quit: bool,
}

impl App {
    fn new() -> Self {
        let settings = Settings::load();
        set_unit_mode(settings.unit_mode);
        let devices = collect::devices::collect();
        let filesystems = collect::filesystems::collect();
        let volumes = collect::volumes::collect();
        let io = collect::IoCollector::new();
        let mut smart = collect::SmartCollector::new();
        smart.refresh_if_due(&devices);
        Self {
            live: LiveState::Live,
            selected_io: 0,
            devices,
            filesystems,
            volumes,
            io,
            io_show_unmounted: settings.io_show_unmounted,
            settings,
            show_settings: false,
            smart,
            last_metadata_refresh: Instant::now(),
            last_usage_refresh: Instant::now(),
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

    fn tick(&mut self) {
        if matches!(self.live, LiveState::Paused) {
            return;
        }
        // The collector forms calm one-second display buckets and rate-limits
        // internally. The eBPF backend still accounts for every request in
        // kernel between these polls.
        self.io.sample();
        let visible_io = crate::screen::visible_device_count(self);
        self.selected_io = self.selected_io.min(visible_io.saturating_sub(1));

        // Slower path: sysinfo-only — used bytes + mounts list at 1Hz.
        let usage_elapsed = self.last_usage_refresh.elapsed();
        if usage_elapsed >= Duration::from_millis(1000) {
            collect::devices::refresh_usage(&mut self.devices);
            self.filesystems = collect::filesystems::collect();
            self.last_usage_refresh = Instant::now();
        }
        // Slow path: system_profiler + diskutil. Picks up new drives.
        if self.last_metadata_refresh.elapsed() >= Duration::from_secs(30) {
            self.devices = collect::devices::collect();
            self.volumes = collect::volumes::collect();
            self.last_metadata_refresh = Instant::now();
        }
        // SMART has its own 5-minute cadence handled inside the collector;
        // we just nudge it on each tick.
        self.smart.refresh_if_due(&self.devices);
    }
}

pub fn run() -> Result<()> {
    let mut app = App::new();

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
    loop {
        terminal.draw(|f| draw(f, app))?;
        if event::poll(frame_budget)? {
            if let Event::Key(k) = event::read()? {
                if k.kind != KeyEventKind::Release {
                    handle_key(app, k.code);
                }
            }
        }
        app.tick();
        if app.should_quit {
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
                LiveState::Paused => {
                    app.io.resume();
                    LiveState::Live
                }
            };
        }
        KeyCode::Char('u') => app.toggle_io_unmounted(),
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
            Constraint::Length(2), // footer (divider + text)
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
    chrome::draw_footer(f, layout[1]);
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
            devices,
            filesystems,
            volumes: VolumeTick::default(),
            io,
            io_show_unmounted: false,
            settings: Settings::default(),
            show_settings: false,
            smart,
            selected_io: 0,
            last_metadata_refresh: Instant::now(),
            last_usage_refresh: Instant::now(),
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
            "Device",
            "Free",
            "B/s",
            "IOPS",
            "1 device",
            "LIVE",
            "READ",
            "WRITE",
            "Await",
            "VFS | 10s",
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
    fn empty_and_undersized_screens_render_without_panicking() {
        let app = fixture_app(false);
        let empty = render_screen(&app, 130, 40);
        assert!(empty.contains("No IO data yet"));
        assert!(empty.contains("LIVE"));
        let _ = render_screen(&app, 60, 20);
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
