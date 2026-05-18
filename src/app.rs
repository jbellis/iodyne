use std::io;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::widgets::Paragraph;
use ratatui::Terminal;
use sysinfo::System;

use crate::collect;
use crate::tabs::{self, TabId, ALL_TABS};
use crate::ui::chrome;
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
    pub smart: collect::SmartCollector,
    pub hot_files: collect::hot_files::HotFileWatcher,
    pub insights: Vec<crate::insights::Insight>,
    pub selected_device: usize,
    pub selected_fs: usize,
    /// Last full enumeration (slow path — system_profiler + diskutil).
    last_metadata_refresh: Instant,
    /// Last usage refresh (fast path — sysinfo only).
    last_usage_refresh: Instant,
    pub should_quit: bool,
}

impl App {
    fn new(start: TabId) -> Self {
        let devices = collect::devices::collect();
        let filesystems = collect::filesystems::collect();
        let volumes = collect::volumes::collect();
        let io = collect::IoCollector::new();
        let mut smart = collect::SmartCollector::new();
        smart.refresh_if_due(&devices);
        let roots = collect::hot_files::default_roots();
        let root_refs: Vec<&std::path::Path> = roots.iter().map(|p| p.as_path()).collect();
        let hot_files = collect::hot_files::HotFileWatcher::start(&root_refs);
        Self {
            active_tab: start,
            live: LiveState::Live,
            host: read_host(devices.len()),
            selected_device: 0,
            selected_fs: 0,
            devices,
            filesystems,
            volumes,
            io,
            smart,
            hot_files,
            insights: Vec::new(),
            last_metadata_refresh: Instant::now(),
            last_usage_refresh: Instant::now(),
            should_quit: false,
        }
    }

    fn tick(&mut self) {
        if matches!(self.live, LiveState::Paused) {
            return;
        }
        // IO is hot enough to warrant 5Hz sampling for its own latency
        // percentile window. The collector rate-limits internally, so
        // calling every frame is fine.
        self.io.sample();

        // Slower path: sysinfo-only — used bytes + mounts list at 1Hz.
        let usage_elapsed = self.last_usage_refresh.elapsed();
        if usage_elapsed >= Duration::from_millis(1000) {
            collect::devices::refresh_usage(&mut self.devices);
            self.filesystems = collect::filesystems::collect();
            if self.selected_fs >= self.filesystems.len() && !self.filesystems.is_empty() {
                self.selected_fs = self.filesystems.len() - 1;
            }
            // Decay per-file EWMA rates and prune idle / overflowed
            // entries. The watcher thread keeps writing into the same
            // map between calls; we just shape it back down.
            self.hot_files.decay(usage_elapsed);
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
            &self.hot_files,
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
    let frame_budget = Duration::from_millis(50);
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
    match key {
        KeyCode::Char('q') | KeyCode::Esc => app.should_quit = true,
        KeyCode::Char('p') => {
            app.live = match app.live {
                LiveState::Live => LiveState::Paused,
                LiveState::Paused => LiveState::Live,
            };
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
            _ => {}
        },
        KeyCode::Down | KeyCode::Char('j') => match app.active_tab {
            TabId::Devices if app.selected_device + 1 < app.devices.len() => {
                app.selected_device += 1
            }
            TabId::Fs if app.selected_fs + 1 < app.filesystems.len() => app.selected_fs += 1,
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
    chrome::draw_footer(f, layout[3], &[]);
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
