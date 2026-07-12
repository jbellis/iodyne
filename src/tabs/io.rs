//! IO tab — port of `dwRenderIo`.
//!
//! 2-column grid of per-device panels. Each shows read/write rates,
//! sparkline history, and inline summary stats. Latency / queue depth
//! are deferred; the panel shows "—" for those slots.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::collect::{DeviceHistory, FsTick, IoTick};
use crate::ui::format::fmt_rate;
use crate::ui::palette as p;
use crate::ui::sparkline::BaselineSparkline;

const MIN_PANEL_HEIGHT: u16 = 5;

pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    if app.io.latest.is_empty() {
        draw_empty(f, area);
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(MIN_PANEL_HEIGHT),
            Constraint::Length(1),
        ])
        .split(area);

    draw_summary_line(f, rows[0], app);
    draw_panel_grid(f, rows[1], app);
    draw_latency_note(f, rows[2]);
}

fn draw_empty(f: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(p::FAINT).bg(p::BG))
        .title(Span::styled(
            " IO ",
            Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(p::BG));
    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(
        Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  No IO data yet — sampling begins on the first tick.",
                Style::default().fg(p::DIM),
            )),
        ])
        .style(Style::default().bg(p::BG)),
        inner,
    );
}

fn draw_summary_line(f: &mut Frame, area: Rect, app: &App) {
    let (agg, write) = crate::collect::io::aggregate(&app.io.latest);
    let any_split = app.io.latest.iter().any(|t| t.split.is_some());
    let visible = visible_io_ticks(app);
    let panel_scale = io_panel_scale(app, &visible);
    let read = agg - write;
    let mut spans = vec![
        Span::raw(" "),
        Span::styled("aggregate", Style::default().fg(p::DIM)),
        Span::raw("  "),
        Span::styled(
            fmt_rate(agg),
            Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
        ),
    ];
    if any_split {
        spans.push(Span::raw("   "));
        spans.push(Span::styled("read ", Style::default().fg(p::DIM)));
        spans.push(Span::styled(
            fmt_rate(read),
            Style::default().fg(p::GREEN).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::raw("   "));
        spans.push(Span::styled("write ", Style::default().fg(p::DIM)));
        spans.push(Span::styled(
            fmt_rate(write),
            Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
        ));
    } else {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            "(read+write combined; split pending IOKit Statistics)",
            Style::default().fg(p::DIM),
        ));
    }
    spans.push(Span::raw("   "));
    spans.push(Span::styled(
        format!(
            "{} device{}",
            app.io.latest.len(),
            if app.io.latest.len() == 1 { "" } else { "s" }
        ),
        Style::default().fg(p::DIM),
    ));
    spans.push(Span::raw("   "));
    spans.push(Span::styled("view ", Style::default().fg(p::DIM)));
    spans.push(Span::styled(
        if app.io_show_unmounted {
            "all"
        } else {
            "mounted"
        },
        Style::default()
            .fg(p::BR_WHITE)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(" (u toggles)", Style::default().fg(p::DIM)));
    spans.push(Span::raw("   "));
    spans.push(Span::styled("scale ", Style::default().fg(p::DIM)));
    spans.push(Span::styled(
        fmt_rate(panel_scale),
        Style::default().fg(p::FG),
    ));
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(p::BG)),
        Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: 1,
        },
    );
}

fn draw_panel_grid(f: &mut Frame, area: Rect, app: &App) {
    let visible = visible_io_ticks(app);
    if visible.is_empty() {
        draw_no_mounted_io(f, area);
        return;
    }

    let panel_scale = io_panel_scale(app, &visible);
    let panels = panel_areas(area, visible.len());
    for (panel_area, tick) in panels.into_iter().zip(visible.into_iter()) {
        let history = app.io.history.get(&tick.device);
        draw_panel(
            f,
            panel_area,
            tick,
            history,
            &app.filesystems,
            app.io_show_unmounted,
            panel_scale,
        );
    }
}

fn visible_io_ticks<'a>(app: &'a App) -> Vec<&'a IoTick> {
    app.io
        .latest
        .iter()
        .filter(|tick| {
            app.io_show_unmounted || io_device_is_mounted(&tick.device, &app.filesystems)
        })
        .collect()
}

fn io_panel_scale(app: &App, visible: &[&IoTick]) -> f64 {
    let max = visible.iter().fold(0.0_f64, |max, tick| {
        let latest = max.max(tick.bps);
        let history_max = app
            .io
            .history
            .get(&tick.device)
            .map(|h| h.combined.iter().copied().fold(0.0_f64, f64::max))
            .unwrap_or(0.0);
        latest.max(history_max)
    });

    power_of_two_rate_ceiling(max)
}

fn power_of_two_rate_ceiling(rate: f64) -> f64 {
    if !rate.is_finite() || rate <= 1.0 {
        return 1.0;
    }
    2_f64.powi(rate.log2().ceil() as i32)
}

fn draw_no_mounted_io(f: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(p::FAINT).bg(p::BG))
        .title(Span::styled(
            " IO ",
            Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(p::BG));
    let inner = block.inner(area);
    f.render_widget(block, area);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "  No mounted IO devices in the current sample. Press u to show unmounted devices.",
            Style::default().fg(p::DIM),
        )))
        .style(Style::default().bg(p::BG)),
        Rect {
            x: inner.x,
            y: inner.y,
            width: inner.width,
            height: 1,
        },
    );
}

fn panel_areas(area: Rect, n: usize) -> Vec<Rect> {
    if n == 0 {
        return Vec::new();
    }

    // A 2xN grid scales down proportionally as device count grows. Keep
    // rows at least tall enough for border + rate + latency + sparkline.
    let cols = if n == 1 { 1_usize } else { 2 };
    let max_rows = (area.height / MIN_PANEL_HEIGHT).max(1) as usize;
    let n = n.min(max_rows.saturating_mul(cols));
    let rows = n.div_ceil(cols);

    let row_constraints: Vec<Constraint> = (0..rows)
        .map(|_| Constraint::Ratio(1, rows as u32))
        .collect();
    let row_areas = Layout::default()
        .direction(Direction::Vertical)
        .constraints(row_constraints)
        .split(area);

    let mut out = Vec::with_capacity(n);
    for (r, row_area) in row_areas.iter().enumerate() {
        let in_row = if r == rows - 1 && n % cols != 0 {
            n % cols
        } else {
            cols
        };
        let col_constraints: Vec<Constraint> = (0..in_row)
            .map(|_| Constraint::Ratio(1, in_row as u32))
            .collect();
        let col_areas = Layout::default()
            .direction(Direction::Horizontal)
            .constraints(col_constraints)
            .split(*row_area);
        for c in col_areas.iter() {
            out.push(*c);
            if out.len() == n {
                return out;
            }
        }
    }
    out
}

fn draw_latency_note(f: &mut Frame, area: Rect) {
    if area.height == 0 {
        return;
    }
    let note = Line::from(vec![
        Span::raw(" "),
        Span::styled(
            "latency",
            Style::default().fg(p::DIM).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            " p50/p99 are per-tick averages; micro-spikes need eBPF/IOReport",
            Style::default().fg(p::DIM),
        ),
    ]);
    f.render_widget(
        Paragraph::new(note).style(Style::default().bg(p::BG)),
        Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: 1,
        },
    );
}

fn latency_line(tick: &IoTick) -> Line<'static> {
    let Some(pct) = tick.latency_pct else {
        return Line::from(Span::styled(
            "lat   no samples yet",
            Style::default().fg(p::DIM),
        ));
    };
    let color = |us: f64| {
        if us >= 10_000.0 {
            p::RED
        } else if us >= 2_000.0 {
            p::YELLOW
        } else if us > 0.0 {
            p::FG
        } else {
            p::DIM
        }
    };
    let lbl = |us: f64| {
        if us <= 0.0 {
            "—".to_string()
        } else if us >= 1_000.0 {
            format!("{:.1}ms", us / 1_000.0)
        } else {
            format!("{:.0}µs", us)
        }
    };
    Line::from(vec![
        Span::styled("lat ", Style::default().fg(p::DIM)),
        Span::styled("r ", Style::default().fg(p::DIM)),
        Span::styled("p50 ", Style::default().fg(p::DIM)),
        Span::styled(lbl(pct.p50_r), Style::default().fg(color(pct.p50_r))),
        Span::raw(" "),
        Span::styled("p99 ", Style::default().fg(p::DIM)),
        Span::styled(
            lbl(pct.p99_r),
            Style::default()
                .fg(color(pct.p99_r))
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("   "),
        Span::styled("w ", Style::default().fg(p::DIM)),
        Span::styled("p50 ", Style::default().fg(p::DIM)),
        Span::styled(lbl(pct.p50_w), Style::default().fg(color(pct.p50_w))),
        Span::raw(" "),
        Span::styled("p99 ", Style::default().fg(p::DIM)),
        Span::styled(
            lbl(pct.p99_w),
            Style::default()
                .fg(color(pct.p99_w))
                .add_modifier(Modifier::BOLD),
        ),
    ])
}

fn draw_panel(
    f: &mut Frame,
    area: Rect,
    tick: &IoTick,
    history: Option<&DeviceHistory>,
    filesystems: &[FsTick],
    show_unmounted: bool,
    panel_scale: f64,
) {
    let title = match mounts_for_device(&tick.device, filesystems) {
        Some(mounts) => format!(" {}  {} ", tick.device, mounts),
        None if show_unmounted => format!(" {}  [unmounted] ", tick.device),
        None => format!(" {} ", tick.device),
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(p::FAINT).bg(p::BG))
        .title(Span::styled(
            title,
            Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
        ))
        .style(Style::default().bg(p::BG));
    let inner = block.inner(area);
    f.render_widget(block, area);

    if inner.height < 5 || inner.width < 20 {
        return;
    }

    // Top line: per-direction rates.
    let mut rate_spans: Vec<Span> = Vec::new();
    if let Some((r, w)) = tick.split {
        rate_spans.push(Span::styled("read ", Style::default().fg(p::DIM)));
        rate_spans.push(Span::styled(
            fmt_rate(r),
            Style::default().fg(p::GREEN).add_modifier(Modifier::BOLD),
        ));
        rate_spans.push(Span::raw("   "));
        rate_spans.push(Span::styled("write ", Style::default().fg(p::DIM)));
        rate_spans.push(Span::styled(
            fmt_rate(w),
            Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
        ));
    } else {
        rate_spans.push(Span::styled("rate ", Style::default().fg(p::DIM)));
        rate_spans.push(Span::styled(
            fmt_rate(tick.bps),
            Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
        ));
    }
    let summary = Line::from(rate_spans);
    f.render_widget(
        Paragraph::new(summary).style(Style::default().bg(p::BG)),
        Rect {
            x: inner.x + 1,
            y: inner.y,
            width: inner.width.saturating_sub(2),
            height: 1,
        },
    );

    // Second line: latency percentiles.
    let lat_line = latency_line(tick);
    f.render_widget(
        Paragraph::new(lat_line).style(Style::default().bg(p::BG)),
        Rect {
            x: inner.x + 1,
            y: inner.y + 1,
            width: inner.width.saturating_sub(2),
            height: 1,
        },
    );

    // Single sparkline of combined throughput. Baseline-aware so the
    // panel is visually filled from the first sample.
    if let Some(h) = history {
        let panel_inner_h = inner.height.saturating_sub(2);
        let data: Vec<f64> = h.combined.iter().copied().collect();
        f.render_widget(
            BaselineSparkline::new(&data)
                .max(panel_scale)
                .style(Style::default().fg(p::CYAN).bg(p::BG)),
            Rect {
                x: inner.x + 1,
                y: inner.y + 2,
                width: inner.width.saturating_sub(2),
                height: panel_inner_h,
            },
        );
    }
}

fn mounts_for_device(device: &str, filesystems: &[FsTick]) -> Option<String> {
    let mut mounts: Vec<String> = filesystems
        .iter()
        .filter_map(|fs| mount_label_for_device(fs, device))
        .collect();
    mounts.sort_unstable();
    mounts.dedup();

    if mounts.is_empty() {
        return None;
    }

    const MAX_MOUNTS: usize = 2;
    let extra = mounts.len().saturating_sub(MAX_MOUNTS);
    let mut label = mounts
        .iter()
        .take(MAX_MOUNTS)
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if extra > 0 {
        label.push_str(&format!(" +{extra}"));
    }
    Some(label)
}

fn io_device_is_mounted(device: &str, filesystems: &[FsTick]) -> bool {
    filesystems
        .iter()
        .any(|fs| mount_label_for_device(fs, device).is_some())
}

fn mount_label_for_device(fs: &FsTick, io_device: &str) -> Option<String> {
    if let Some(label) = direct_mount_label_for_device(fs, io_device) {
        return Some(label);
    }

    let fs_device = disk_name(&fs.device);
    let stacked = stacked_members(fs_device)?;
    mount_label_for_device_with_members(fs, io_device, &stacked)
}

fn direct_mount_label_for_device(fs: &FsTick, io_device: &str) -> Option<String> {
    let fs_device = disk_name(&fs.device);
    let io = disk_name(io_device);
    if fs_device == io || whole_disk_name(fs_device) == io {
        return Some(fs.mount.clone());
    }
    None
}

fn mount_label_for_device_with_members(
    fs: &FsTick,
    io_device: &str,
    members: &[String],
) -> Option<String> {
    if direct_mount_label_for_device(fs, io_device).is_some() {
        return Some(fs.mount.clone());
    }

    let fs_device = disk_name(&fs.device);
    let io = disk_name(io_device);
    if members.iter().any(|member| member == io) {
        return Some(format!("{} via {}", fs.mount, fs_device));
    }
    None
}

fn stacked_members(device: &str) -> Option<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        sysfs_stacked_members(device)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = device;
        None
    }
}

#[cfg(target_os = "linux")]
fn sysfs_stacked_members(device: &str) -> Option<Vec<String>> {
    fn expand(name: &str, depth: u8, out: &mut Vec<String>) {
        let slaves_dir = format!("/sys/block/{}/slaves", name);
        let entries: Vec<String> = std::fs::read_dir(&slaves_dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        if entries.is_empty() || depth == 0 {
            out.push(whole_disk_name(name).to_string());
            return;
        }
        for slave in entries {
            expand(whole_disk_name(&slave), depth - 1, out);
        }
    }

    let kernel_name = device.trim_start_matches("/dev/");
    let slaves_dir = format!("/sys/block/{}/slaves", kernel_name);
    if !std::path::Path::new(&slaves_dir).is_dir() {
        return None;
    }

    let mut out = Vec::new();
    expand(kernel_name, 4, &mut out);
    out.sort();
    out.dedup();
    Some(out)
}

fn disk_name(device: &str) -> &str {
    device.strip_prefix("/dev/").unwrap_or(device)
}

fn whole_disk_name(device: &str) -> &str {
    if let Some((base, part)) = device.rsplit_once('p') {
        if base.starts_with("nvme") || base.starts_with("mmcblk") {
            if part.chars().all(|c| c.is_ascii_digit()) {
                return base;
            }
        }
    }

    if let Some(stripped) = device.strip_prefix("disk") {
        if let Some(idx) = stripped.find('s') {
            let base_len = "disk".len() + idx;
            let (_, suffix) = stripped.split_at(idx + 1);
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return &device[..base_len];
            }
        }
    }

    let split = device
        .char_indices()
        .rev()
        .find(|(_, c)| !c.is_ascii_digit())
        .map(|(idx, c)| idx + c.len_utf8())
        .unwrap_or(0);
    if split > 0 && split < device.len() {
        &device[..split]
    } else {
        device
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fs(device: &str, mount: &str) -> FsTick {
        FsTick {
            mount: mount.to_string(),
            device: device.to_string(),
            fs_type: "ext4".to_string(),
            size_bytes: 0,
            used_bytes: 0,
            avail_bytes: 0,
            inode_pct: None,
            is_removable: false,
            is_system: false,
        }
    }

    #[test]
    fn maps_linux_partition_mounts_to_whole_disk() {
        let filesystems = vec![fs("/dev/sda1", "/"), fs("/dev/sda2", "/home")];

        assert_eq!(
            mounts_for_device("sda", &filesystems),
            Some("/, /home".to_string())
        );
        assert!(io_device_is_mounted("sda", &filesystems));
        assert!(!io_device_is_mounted("sdb", &filesystems));
    }

    #[test]
    fn labels_stacked_mounts_via_container_device() {
        let filesystems = vec![fs("/dev/md0", "/mnt/optane")];
        let members = vec!["sdd".to_string(), "sde".to_string()];

        assert_eq!(
            mount_label_for_device_with_members(&filesystems[0], "sdd", &members),
            Some("/mnt/optane via md0".to_string())
        );
    }

    #[test]
    fn maps_nvme_partition_mounts_to_whole_disk() {
        let filesystems = vec![fs("/dev/nvme0n1p2", "/")];

        assert_eq!(
            mounts_for_device("nvme0n1", &filesystems),
            Some("/".to_string())
        );
    }

    #[test]
    fn maps_macos_slice_mounts_to_whole_disk() {
        let filesystems = vec![fs("/dev/disk3s1", "/System/Volumes/Data")];

        assert_eq!(
            mounts_for_device("disk3", &filesystems),
            Some("/System/Volumes/Data".to_string())
        );
    }

    #[test]
    fn abbreviates_long_mount_lists() {
        let filesystems = vec![
            fs("/dev/sdb1", "/a"),
            fs("/dev/sdb2", "/b"),
            fs("/dev/sdb3", "/c"),
        ];

        assert_eq!(
            mounts_for_device("sdb", &filesystems),
            Some("/a, /b +1".to_string())
        );
    }

    #[test]
    fn panel_grid_uses_two_columns_for_more_than_one_device() {
        let area = Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 15,
        };

        let panels = panel_areas(area, 6);

        assert_eq!(panels.len(), 6);
        assert_eq!(panels[0].height, 5);
        assert_eq!(panels[0].width, 50);
    }

    #[test]
    fn panel_grid_limits_to_complete_rows_that_fit() {
        let area = Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 11,
        };

        let panels = panel_areas(area, 10);

        assert_eq!(panels.len(), 4);
        assert!(panels.iter().all(|panel| panel.height >= MIN_PANEL_HEIGHT));
    }

    #[test]
    fn scale_rounds_up_to_power_of_two_rates() {
        assert_eq!(power_of_two_rate_ceiling(0.0), 1.0);
        assert_eq!(power_of_two_rate_ceiling(1.0), 1.0);
        assert_eq!(power_of_two_rate_ceiling(2.0), 2.0);
        assert_eq!(power_of_two_rate_ceiling(3.0), 4.0);
        assert_eq!(power_of_two_rate_ceiling(1025.0), 2048.0);
    }
}
