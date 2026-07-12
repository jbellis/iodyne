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
use sysinfo::System;

use crate::collect;
use crate::config::Settings;
use crate::tabs::{self, TabId, ALL_TABS};
use crate::ui::chrome;
use crate::ui::format::{set_unit_mode, UnitMode};
use crate::ui::palette as p;

pub struct Options {
    pub start_tab: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveState {
    Live,
    Paused,
}

#[derive(Debug, Clone)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub uptime_secs: u64,
    pub device_count: usize,
}

pub struct App {
    pub active_tab: TabId,
    pub live: LiveState,
    pub host: HostInfo,
    pub devices: Vec<collect::DeviceTick>,
    pub filesystems: Vec<collect::FsTick>,
    pub volumes: collect::VolumeTick,
    pub io: collect::IoCollector,
    pub io_show_unmounted: bool,
    pub settings: Settings,
    pub show_settings: bool,
    pub smart: collect::SmartCollector,
    pub insights: Vec<crate::insights::Insight>,
    pub selected_device: usize,
    pub selected_fs: usize,
    pub selected_io: usize,
    /// Last full enumeration (slow path — system_profiler + diskutil).
    last_metadata_refresh: Instant,
    /// Last usage refresh (fast path — sysinfo only).
    last_usage_refresh: Instant,
    pub should_quit: bool,
}

impl App {
    fn new(start: TabId) -> Self {
        let settings = Settings::load();
        set_unit_mode(settings.unit_mode);
        let devices = collect::devices::collect();
        let filesystems = collect::filesystems::collect();
        let volumes = collect::volumes::collect();
        let io = collect::IoCollector::new();
        let mut smart = collect::SmartCollector::new();
        smart.refresh_if_due(&devices);
        Self {
            active_tab: start,
            live: LiveState::Live,
            host: read_host(devices.len()),
            selected_device: 0,
            selected_fs: 0,
            selected_io: 0,
            devices,
            filesystems,
            volumes,
            io,
            io_show_unmounted: settings.io_show_unmounted,
            settings,
            show_settings: false,
            smart,
            insights: Vec::new(),
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
        let visible_io = crate::tabs::io::visible_device_count(self);
        self.selected_io = self.selected_io.min(visible_io.saturating_sub(1));

        // Slower path: sysinfo-only — used bytes + mounts list at 1Hz.
        let usage_elapsed = self.last_usage_refresh.elapsed();
        if usage_elapsed >= Duration::from_millis(1000) {
            collect::devices::refresh_usage(&mut self.devices);
            self.filesystems = collect::filesystems::collect();
            if self.selected_fs >= self.filesystems.len() && !self.filesystems.is_empty() {
                self.selected_fs = self.filesystems.len() - 1;
            }
            self.host.uptime_secs = System::uptime();
            self.last_usage_refresh = Instant::now();
        }
        // Slow path: system_profiler + diskutil. Picks up new drives.
        if self.last_metadata_refresh.elapsed() >= Duration::from_secs(30) {
            self.devices = collect::devices::collect();
            self.volumes = collect::volumes::collect();
            self.host.device_count = self.devices.len();
            if self.selected_device >= self.devices.len() && !self.devices.is_empty() {
                self.selected_device = self.devices.len() - 1;
            }
            self.last_metadata_refresh = Instant::now();
        }
        // SMART has its own 5-minute cadence handled inside the collector;
        // we just nudge it on each tick.
        self.smart.refresh_if_due(&self.devices);

        // Recompute insights each tick — pure functions over current
        // state, so this is cheap.
        self.insights = crate::insights::evaluate(
            &self.devices,
            &self.filesystems,
            &self.io.latest,
            &self.smart,
        );
    }
}

pub fn run(opts: Options) -> Result<()> {
    let start = opts
        .start_tab
        .as_deref()
        .and_then(TabId::from_str)
        .unwrap_or(TabId::Overview);
    let mut app = App::new(start);

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
        KeyCode::Char('u') if app.active_tab == TabId::Io => {
            app.toggle_io_unmounted();
        }
        KeyCode::Char(c) if c.is_ascii_digit() && c != '0' => {
            let idx = (c as u8 - b'1') as usize;
            if let Some(t) = ALL_TABS.get(idx) {
                app.active_tab = *t;
            }
        }
        KeyCode::Up | KeyCode::Char('k') => match app.active_tab {
            TabId::Devices if app.selected_device > 0 => app.selected_device -= 1,
            TabId::Fs if app.selected_fs > 0 => app.selected_fs -= 1,
            TabId::Io if app.selected_io > 0 => app.selected_io -= 1,
            _ => {}
        },
        KeyCode::Down | KeyCode::Char('j') => match app.active_tab {
            TabId::Devices if app.selected_device + 1 < app.devices.len() => {
                app.selected_device += 1
            }
            TabId::Fs if app.selected_fs + 1 < app.filesystems.len() => app.selected_fs += 1,
            TabId::Io if app.selected_io + 1 < crate::tabs::io::visible_device_count(app) => {
                app.selected_io += 1
            }
            _ => {}
        },
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
            Constraint::Length(1), // header
            Constraint::Length(2), // tab bar (labels + underline)
            Constraint::Min(1),    // content
            Constraint::Length(2), // footer (divider + text)
        ])
        .split(full);

    chrome::draw_header(f, layout[0], &app.host, app.live);
    chrome::draw_tab_bar(f, layout[1], app.active_tab, app.insights.len());
    let content = Rect {
        x: layout[2].x,
        y: layout[2].y,
        width: layout[2].width,
        height: layout[2].height,
    };
    tabs::draw(f, content, app);
    if app.show_settings {
        draw_settings_overlay(f, full, app);
    }
    chrome::draw_footer(f, layout[3], &[]);
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
            Span::styled("IO panels    ", Style::default().fg(p::DIM)),
            Span::styled(io_mode, Style::default().fg(p::FG)),
        ]),
        Line::from(Span::styled(
            "   persists to ~/.config/diskwatch/config.json",
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

fn read_host(device_count: usize) -> HostInfo {
    let hostname = System::host_name().unwrap_or_else(|| "localhost".to_string());
    let name = System::name().unwrap_or_else(|| "unknown".to_string());
    let version = System::os_version().unwrap_or_default();
    let arch = std::env::consts::ARCH;
    let os = if version.is_empty() {
        format!("{} {}", name, arch)
    } else {
        format!("{} {} {}", name, version, arch)
    };
    HostInfo {
        hostname,
        os,
        uptime_secs: System::uptime(),
        device_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

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

    fn render_all_tabs(width: u16, height: u16) {
        let backend = TestBackend::new(width, height);
        let mut term = Terminal::new(backend).expect("terminal");
        let mut app = App::new(TabId::Overview);
        for tab in ALL_TABS {
            app.active_tab = *tab;
            term.draw(|f| super::draw(f, &app)).expect("draw");
        }
    }

    #[test]
    fn renders_at_design_size() {
        render_all_tabs(130, 36);
    }

    #[test]
    fn renders_at_minimum_supported_size() {
        // README declares responsive ≥ 110×30.
        render_all_tabs(110, 30);
    }

    #[test]
    fn renders_at_undersized_terminal_without_panic() {
        // We don't promise pretty output below the supported floor, only
        // that we don't panic.
        render_all_tabs(60, 20);
    }
}
