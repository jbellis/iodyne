//! Per-device IO overview.
//!
//! Every device uses the same fixed logarithmic latency scale, split into
//! read and write lanes. The selected device drives a compact histogram and
//! aligned workload graphs.

use std::collections::{HashMap, HashSet, VecDeque};
use std::ops::Range;
use std::path::Path;

#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;
use crate::collect::ebpf::{EbpfStatus, LatencySource, LATENCY_BUCKETS};
use crate::collect::io::{VfsActivitySource, VfsFileActivity};
use crate::collect::smart::{AtaAttr, SmartTick};
use crate::collect::volumes::{ApfsContainer, MdRaidArray, MdRaidMember, VolumeTick};
use crate::collect::{
    AwaitSample, DeviceTick, FsTick, IoTick, MergeRates, TracedLatencySample, WorkloadSample,
};
use crate::ui::format::{fmt_rate, fmt_size, unit_mode, UnitMode};
use crate::ui::palette as p;
use crate::ui::sparkline::BaselineSparkline;

const LATENCY_MIN_US: f64 = 50.0;
const LATENCY_MAX_US: f64 = 1_000_000.0;
const HEAT_BOUNDS_US: [f64; 6] = [250.0, 1_000.0, 4_000.0, 16_000.0, 64_000.0, 256_000.0];
const HEAT_LABELS: [&str; 7] = [
    "<250us",
    "250us-1ms",
    "1-4ms",
    "4-16ms",
    "16-64ms",
    "64-256ms",
    ">=256ms",
];
const WIDE_DETAIL_HEIGHT: u16 = 28;
const WIDE_DETAIL_BODY_HEIGHT: u16 = WIDE_DETAIL_HEIGHT - 2;
const COMPACT_DETAIL_HEIGHT: u16 = 23;
const DIRECTION_DETAIL_HEIGHT: u16 = 14;
const MAX_DETAIL_CONTEXT_ROWS: u16 = 2;
pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    if app.io.latest.is_empty() {
        draw_empty(f, area);
        return;
    }

    let md_state = md_exception_summary(&app.volumes.mdraid);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(md_state.is_some() as u16),
            Constraint::Min(1),
        ])
        .split(area);

    if let Some(state) = md_state {
        draw_md_exception(f, rows[0], &state);
    }
    draw_master_detail(f, rows[1], app);
}

fn pane_block<'a>(title: impl Into<Line<'a>>) -> Block<'a> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(p::FAINT).bg(p::BG))
        .title(title)
        .style(Style::default().bg(p::BG))
}

fn draw_empty(f: &mut Frame, area: Rect) {
    let block = pane_block(Span::styled(
        " IO ",
        Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
    ));
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

fn overview_title(app: &App) -> Line<'static> {
    let source = match app.io.latency_source() {
        LatencySource::AggregateAwait => "AGGREGATE AWAIT",
        LatencySource::EbpfPerRequest => "PER-REQUEST eBPF",
    };
    let spans = vec![
        Span::raw(" "),
        Span::styled(
            source,
            Style::default()
                .fg(p::BR_WHITE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" | ", Style::default().fg(p::FAINT)),
        Span::styled(
            if app.io_show_unmounted {
                "all"
            } else {
                "mounted"
            },
            Style::default()
                .fg(p::BR_WHITE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" "),
    ];
    Line::from(spans)
}

fn draw_master_detail(f: &mut Frame, area: Rect, app: &App) {
    let visible = visible_io_ticks(app);
    if visible.is_empty() {
        draw_no_mounted_io(f, area);
        return;
    }

    let (overview_height, detail_height) = master_detail_heights(area.height, visible.len());
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(overview_height),
            Constraint::Length(detail_height),
            Constraint::Min(0),
        ])
        .split(area);
    let selected = app.selected_io.min(visible.len() - 1);
    let (throughput_scale, iops_scale) = overview_workload_scales(&visible, app);
    let overview_block = pane_block(overview_title(app));
    let overview_inner = overview_block.inner(sections[0]);
    f.render_widget(overview_block, sections[0]);
    if overview_inner.height > 0 {
        draw_scale_legend(
            f,
            Rect {
                height: 1,
                ..overview_inner
            },
        );
    }
    let device_area = Rect {
        y: overview_inner.y.saturating_add(1),
        height: overview_inner.height.saturating_sub(1),
        ..overview_inner
    };
    let (start, count, _) = visible_band_window(device_area.height, visible.len(), selected);
    for (slot, tick) in visible.iter().skip(start).take(count).enumerate() {
        draw_overview_row(
            f,
            Rect {
                x: device_area.x,
                y: device_area.y + slot as u16,
                width: device_area.width,
                height: 1,
            },
            tick,
            app,
            start + slot == selected,
            throughput_scale,
            iops_scale,
        );
    }
    draw_detail(f, sections[1], visible[selected], app);
}

fn visible_band_window(height: u16, total: usize, selected: usize) -> (usize, usize, usize) {
    if total == 0 {
        return (0, 0, 0);
    }
    let selected = selected.min(total - 1);
    if height == 0 {
        return (selected, 0, selected);
    }
    let slots = (height as usize).min(total);
    let start = selected
        .saturating_add(1)
        .saturating_sub(slots)
        .min(total.saturating_sub(slots));
    (start, slots, selected)
}

fn visible_io_ticks(app: &App) -> Vec<&IoTick> {
    app.io
        .latest
        .iter()
        .filter(|tick| {
            app.io_show_unmounted
                || io_device_is_mounted(&tick.device, &app.filesystems, &app.volumes)
        })
        .collect()
}

pub(crate) fn visible_device_count(app: &App) -> usize {
    visible_io_ticks(app).len()
}

fn draw_no_mounted_io(f: &mut Frame, area: Rect) {
    let block = pane_block(Span::styled(
        " IO ",
        Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
    ));
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

fn draw_md_exception(f: &mut Frame, area: Rect, summary: &str) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    f.render_widget(
        Paragraph::new(Span::styled(
            truncate_line(summary, area.width as usize),
            Style::default().fg(p::YELLOW),
        )),
        area,
    );
}

fn md_exception_summary(arrays: &[MdRaidArray]) -> Option<String> {
    let mut exceptions: Vec<(u8, String)> = arrays
        .iter()
        .filter_map(|array| {
            let inactive = !array.state.eq_ignore_ascii_case("active");
            let missing = (array.members_total > 0 && array.members_present < array.members_total)
                || array.member_state.contains('_');
            let flagged = array
                .members
                .iter()
                .any(|member| member.flag.as_deref().is_some_and(md_failure_flag));
            let progressing = array.progress.is_some();
            if !(inactive || missing || flagged || progressing) {
                return None;
            }

            let mut facts = vec![array.name.clone()];
            if inactive && !array.state.is_empty() {
                facts.push(array.state.clone());
            }
            if missing || array.members_total > 0 {
                facts.push(format!(
                    "{}/{} members",
                    array.members_present, array.members_total
                ));
            }
            let flags: Vec<String> = array
                .members
                .iter()
                .filter_map(|member| {
                    member
                        .flag
                        .as_ref()
                        .map(|flag| format!("{}{}", member.device, flag))
                })
                .collect();
            if !flags.is_empty() {
                facts.push(format!("flags {}", flags.join(",")));
            }
            if let Some(progress) = &array.progress {
                let percent = if (progress.percent - progress.percent.round()).abs() < 0.05 {
                    format!("{:.0}%", progress.percent)
                } else {
                    format!("{:.1}%", progress.percent)
                };
                let mut operation = format!("{} {percent}", progress.op);
                if !progress.speed.is_empty() {
                    operation.push_str(&format!(" @ {}", progress.speed));
                }
                if !progress.eta.is_empty() {
                    operation.push_str(&format!(" · ETA {}", progress.eta));
                }
                facts.push(operation);
            }
            let mut affected: Vec<String> = array
                .members
                .iter()
                .map(|member| whole_disk_name(&member.device).to_string())
                .collect();
            affected.sort_unstable();
            affected.dedup();
            if !affected.is_empty() {
                let extra = affected.len().saturating_sub(3);
                let mut label = affected.into_iter().take(3).collect::<Vec<_>>().join(",");
                if extra > 0 {
                    label.push_str(&format!(" +{extra}"));
                }
                facts.push(format!("affects {label}"));
            }
            let score =
                inactive as u8 * 8 + missing as u8 * 4 + flagged as u8 * 2 + progressing as u8;
            Some((score, format!(" {}", facts.join(" · "))))
        })
        .collect();
    exceptions.sort_by(|a, b| b.0.cmp(&a.0));
    let (_, mut summary) = exceptions.first()?.clone();
    if exceptions.len() > 1 {
        summary.push_str(&format!(" · +{} arrays", exceptions.len() - 1));
    }
    Some(summary)
}

fn md_failure_flag(flag: &str) -> bool {
    flag.trim_matches(['(', ')']).eq_ignore_ascii_case("f")
}

fn draw_scale_legend(f: &mut Frame, area: Rect) {
    if area.height == 0 {
        return;
    }
    let geometry = row_geometry(area.width);
    let mut line = vec![Span::styled(
        overview_prefix_header(geometry.label),
        Style::default().fg(p::DIM),
    )];
    let lanes = latency_plot_geometry(geometry.plot);
    line.push(Span::styled(
        "R ",
        Style::default().fg(p::GREEN).add_modifier(Modifier::BOLD),
    ));
    line.extend(axis_spans(lanes.read));
    line.push(Span::styled(
        " W ",
        Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
    ));
    line.extend(axis_spans(lanes.write));
    f.render_widget(
        Paragraph::new(Line::from(line)).style(Style::default().bg(p::BG)),
        area,
    );
}

fn log_latency(us: f64) -> f64 {
    if us <= 0.0 || !us.is_finite() {
        return 0.0;
    }
    ((us.clamp(LATENCY_MIN_US, LATENCY_MAX_US).ln() - LATENCY_MIN_US.ln())
        / (LATENCY_MAX_US.ln() - LATENCY_MIN_US.ln()))
    .clamp(0.0, 1.0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RowGeometry {
    label: u16,
    plot: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OverviewPrefixGeometry {
    device: u16,
    free: u16,
    throughput: u16,
    iops: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LatencyPlotGeometry {
    read: u16,
    write: u16,
}

#[cfg(test)]
impl LatencyPlotGeometry {
    fn rendered_width(self) -> u16 {
        5 + self.read + self.write
    }
}

fn latency_plot_geometry(width: u16) -> LatencyPlotGeometry {
    let lanes = width.saturating_sub(5);
    let read = lanes / 2;
    LatencyPlotGeometry {
        read,
        write: lanes.saturating_sub(read),
    }
}

fn overview_prefix_geometry(width: u16) -> OverviewPrefixGeometry {
    let (device, free) = if width >= 24 {
        (10, 4)
    } else if width >= 16 {
        (7, 4)
    } else if width >= 10 {
        (width.saturating_sub(9), 4)
    } else {
        (width.saturating_sub(1), 0)
    };
    // Selection marker, device, free %, a gutter between the two workload
    // sparklines, and a trailing gutter before the R latency lane.
    let fixed = 1 + device + (free > 0) as u16 * (1 + free + 1) + 2;
    let workload = width.saturating_sub(fixed);
    let throughput = workload.saturating_add(1) / 2;
    OverviewPrefixGeometry {
        device,
        free,
        throughput,
        iops: workload.saturating_sub(throughput),
    }
}

fn overview_prefix_header(width: u16) -> String {
    let geometry = overview_prefix_geometry(width);
    let device = fit_overview_device("Device", geometry.device as usize);
    let mut header = format!(" {device:<width$}", width = geometry.device as usize);
    if geometry.free > 0 {
        header.push_str(&format!(
            " {:>width$} ",
            fit_overview_device("Free", geometry.free as usize),
            width = geometry.free as usize
        ));
    }
    header.push_str(&format!(
        "{:<width$} ",
        fit_overview_device("B/s", geometry.throughput as usize),
        width = geometry.throughput as usize
    ));
    header.push_str(&format!(
        "{:<width$} ",
        fit_overview_device("IOPS", geometry.iops as usize),
        width = geometry.iops as usize
    ));
    header
}

fn row_geometry(width: u16) -> RowGeometry {
    let label = if width >= 100 {
        43
    } else if width >= 70 {
        19
    } else {
        13
    }
    .min(width);
    RowGeometry {
        label,
        plot: width.saturating_sub(label),
    }
}

fn master_detail_heights(height: u16, device_count: usize) -> (u16, u16) {
    if height <= 3 {
        return (height, 0);
    }
    let detail_reserve = if height >= 34 {
        WIDE_DETAIL_HEIGHT
    } else if height >= 26 {
        COMPACT_DETAIL_HEIGHT
    } else {
        height.saturating_sub(4).min(WIDE_DETAIL_HEIGHT)
    };
    let min_overview = height.min(4);
    let detail = detail_reserve.min(height.saturating_sub(min_overview));
    let max_overview = height.saturating_sub(detail).max(1);
    let devices = device_count.max(1).min(u16::MAX as usize) as u16;
    // Top and bottom borders plus the shared column/latency scale row.
    let overview = devices.saturating_add(3).min(max_overview);
    (overview, detail.min(height.saturating_sub(overview)))
}

fn draw_overview_row(
    f: &mut Frame,
    area: Rect,
    tick: &IoTick,
    app: &App,
    selected: bool,
    throughput_scale: f64,
    iops_scale: f64,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let g = row_geometry(area.width);
    let throughput = app
        .io
        .history
        .get(&tick.device)
        .map(|history| combined_throughput(&history.workload_samples))
        .unwrap_or_default();
    let iops = app
        .io
        .history
        .get(&tick.device)
        .map(|history| combined_iops(&history.workload_samples))
        .unwrap_or_default();
    draw_overview_prefix(
        f,
        Rect {
            width: g.label,
            ..area
        },
        &tick.device,
        filesystem_free_pct(&tick.device, &app.filesystems, &app.volumes),
        &throughput,
        throughput_scale,
        &iops,
        iops_scale,
        selected,
    );

    let (read_visual, write_visual) = if app.io.latency_source() == LatencySource::EbpfPerRequest {
        let samples = app.io.traced_history.get(&tick.device);
        let lanes = latency_plot_geometry(g.plot);
        let mut read = samples
            .map(|s| request_spectrum(s, lanes.read as usize, IoLane::Read))
            .unwrap_or_else(|| "·".repeat(lanes.read as usize));
        let mut write = samples
            .map(|s| request_spectrum(s, lanes.write as usize, IoLane::Write))
            .unwrap_or_else(|| "·".repeat(lanes.write as usize));
        let read_p99 = samples.and_then(|s| directional_quantile(s, IoLane::Read, 0.99));
        let write_p99 = samples.and_then(|s| directional_quantile(s, IoLane::Write, 0.99));
        overlay_latency_marker(&mut read, read_p99);
        overlay_latency_marker(&mut write, write_p99);
        (read, write)
    } else {
        let samples = app.io.history.get(&tick.device).map(|h| &h.await_samples);
        let lanes = latency_plot_geometry(g.plot);
        let mut read = samples
            .map(|s| await_spectrum(s, lanes.read as usize, IoLane::Read))
            .unwrap_or_else(|| "·".repeat(lanes.read as usize));
        let mut write = samples
            .map(|s| await_spectrum(s, lanes.write as usize, IoLane::Write))
            .unwrap_or_else(|| "·".repeat(lanes.write as usize));
        let read_peak = samples.and_then(|s| await_peak(s, IoLane::Read));
        let write_peak = samples.and_then(|s| await_peak(s, IoLane::Write));
        overlay_latency_marker(&mut read, read_peak);
        overlay_latency_marker(&mut write, write_peak);
        (read, write)
    };
    draw_latency_plot(
        f,
        Rect {
            x: area.x + g.label,
            y: area.y,
            width: g.plot,
            height: 1,
        },
        read_visual,
        write_visual,
    );
}

fn draw_overview_prefix(
    f: &mut Frame,
    area: Rect,
    device: &str,
    free: Option<u32>,
    throughput: &[f64],
    throughput_scale: f64,
    iops: &[f64],
    iops_scale: f64,
    selected: bool,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let geometry = overview_prefix_geometry(area.width);
    let marker = if selected { "▌" } else { " " };
    let device = fit_overview_device(device, geometry.device as usize);
    let mut spans = vec![Span::styled(
        format!("{marker}{device:<width$}", width = geometry.device as usize),
        Style::default().fg(if selected { p::BR_WHITE } else { p::DIM }),
    )];
    if geometry.free > 0 {
        spans.push(Span::styled(
            format!(
                " {:>width$} ",
                format_free(free),
                width = geometry.free as usize
            ),
            Style::default().fg(p::DIM),
        ));
    }
    let text_width = area
        .width
        .saturating_sub(geometry.throughput)
        .saturating_sub(geometry.iops)
        .saturating_sub(2);
    f.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect {
            width: text_width,
            ..area
        },
    );
    if geometry.throughput > 0 {
        f.render_widget(
            BaselineSparkline::new(throughput)
                .max(throughput_scale)
                .style(Style::default().fg(p::YELLOW).bg(p::BG)),
            Rect {
                x: area.x + text_width,
                width: geometry.throughput,
                ..area
            },
        );
    }
    if geometry.iops > 0 {
        f.render_widget(
            BaselineSparkline::new(iops)
                .max(iops_scale)
                .style(Style::default().fg(p::MAGENTA).bg(p::BG)),
            Rect {
                x: area.x + text_width + geometry.throughput + 1,
                width: geometry.iops,
                ..area
            },
        );
    }
}

fn fit_overview_device(device: &str, width: usize) -> String {
    let len = device.chars().count();
    if len <= width {
        device.to_string()
    } else if width <= 1 {
        "~".repeat(width)
    } else {
        format!("{}~", device.chars().take(width - 1).collect::<String>())
    }
}

fn format_free(free: Option<u32>) -> String {
    free.map(|percent| format!("{}%", percent.min(100)))
        .unwrap_or_else(|| "--".into())
}

fn draw_latency_plot(f: &mut Frame, area: Rect, read: String, write: String) {
    let mut plot_spans = vec![Span::styled(
        "R ",
        Style::default().fg(p::GREEN).add_modifier(Modifier::BOLD),
    )];
    plot_spans.extend(spectrum_spans(read, p::GREEN));
    plot_spans.push(Span::styled(
        " W ",
        Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
    ));
    plot_spans.extend(spectrum_spans(write, p::CYAN));
    f.render_widget(Paragraph::new(Line::from(plot_spans)), area);
}

fn draw_detail(f: &mut Frame, area: Rect, tick: &IoTick, app: &App) {
    if area.height == 0 || area.width == 0 {
        return;
    }
    let header = detail_header(&tick.device, &app.filesystems, &app.volumes);
    let block = pane_block(Span::styled(
        header,
        Style::default()
            .fg(p::BR_WHITE)
            .add_modifier(Modifier::BOLD),
    ));
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height == 0 {
        return;
    }
    let context = detail_context_lines(tick, app);
    let context_rows = detail_context_row_count(inner.height, context.len());
    for (offset, line) in context.iter().take(context_rows as usize).enumerate() {
        f.render_widget(
            Paragraph::new(Span::styled(
                truncate_line(line, area.width as usize),
                Style::default().fg(p::DIM),
            )),
            Rect {
                x: inner.x,
                y: inner.y + offset as u16,
                width: inner.width,
                height: 1,
            },
        );
    }
    let body = Rect {
        y: inner.y + context_rows,
        height: inner.height.saturating_sub(context_rows),
        ..inner
    };
    let (read_area, write_area, vfs_area) = detail_areas(body);
    let workload = app
        .io
        .history
        .get(&tick.device)
        .map(|history| workload_view(&history.workload_samples));
    let await_view = app
        .io
        .history
        .get(&tick.device)
        .map(|history| await_view(&history.await_samples));
    let histograms = latency_histograms(tick, app);
    draw_direction_detail(
        f,
        read_area,
        IoLane::Read,
        &histograms.0,
        workload.as_ref(),
        await_view.as_ref(),
    );
    draw_direction_detail(
        f,
        write_area,
        IoLane::Write,
        &histograms.1,
        workload.as_ref(),
        await_view.as_ref(),
    );
    draw_vfs_activity(f, vfs_area, tick, app);
}

fn detail_context_row_count(detail_height: u16, available_lines: usize) -> u16 {
    (available_lines as u16)
        .min(MAX_DETAIL_CONTEXT_ROWS)
        .min(detail_height.saturating_sub(DIRECTION_DETAIL_HEIGHT))
}

fn detail_areas(body: Rect) -> (Rect, Rect, Rect) {
    let packed = Rect {
        height: body.height.min(WIDE_DETAIL_BODY_HEIGHT),
        ..body
    };
    let directional_height = packed.height.min(DIRECTION_DETAIL_HEIGHT);
    let separator_height = (packed.height > directional_height) as u16;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(directional_height),
            Constraint::Length(separator_height),
            Constraint::Min(0),
        ])
        .split(packed);
    let gutter = (rows[0].width > 1) as u16;
    let column_width = rows[0].width.saturating_sub(gutter) / 2;
    let read = Rect {
        width: column_width,
        ..rows[0]
    };
    let write = Rect {
        x: rows[0].x + column_width + gutter,
        width: rows[0].width.saturating_sub(column_width + gutter),
        ..rows[0]
    };
    (read, write, rows[2])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IoLane {
    Read,
    Write,
}

fn latency_histograms(tick: &IoTick, app: &App) -> ([u64; 7], [u64; 7]) {
    match app.io.latency_source() {
        LatencySource::EbpfPerRequest => app
            .io
            .traced_history
            .get(&tick.device)
            .map(request_histogram)
            .unwrap_or(([0; 7], [0; 7])),
        LatencySource::AggregateAwait => app
            .io
            .history
            .get(&tick.device)
            .map(|history| await_histogram(&history.await_samples))
            .unwrap_or(([0; 7], [0; 7])),
    }
}

fn draw_direction_detail(
    f: &mut Frame,
    area: Rect,
    lane: IoLane,
    histogram: &[u64; 7],
    workload: Option<&WorkloadView>,
    await_view: Option<&AwaitView>,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let (name, color) = match lane {
        IoLane::Read => ("READ", p::GREEN),
        IoLane::Write => ("WRITE", p::CYAN),
    };
    let total = histogram.iter().sum::<u64>();
    let block = pane_block(Line::from(vec![
        Span::raw(" "),
        Span::styled(
            name,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" | 60s | n={total} "), Style::default().fg(p::DIM)),
    ]));
    let inner = block.inner(area);
    f.render_widget(block, area);
    let label_width = 11.min(inner.width);
    for band in 0..7.min(inner.height as usize) {
        let y = inner.y + band as u16;
        f.render_widget(
            Paragraph::new(Span::styled(
                format!(" {:<10}", HEAT_LABELS[band]),
                Style::default().fg(p::DIM),
            )),
            Rect {
                x: inner.x,
                y,
                width: label_width,
                height: 1,
            },
        );
        draw_histogram_lane(
            f,
            Rect {
                x: inner.x + label_width,
                y,
                width: inner.width.saturating_sub(label_width),
                height: 1,
            },
            histogram[band],
            total,
            color,
        );
    }

    if inner.height <= 7 {
        return;
    }
    let metric_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
        ])
        .split(Rect {
            y: inner.y + 7,
            height: inner.height - 7,
            ..inner
        });
    draw_direction_metrics(f, &metric_rows, lane, workload, await_view);
}

fn draw_histogram_lane(
    f: &mut Frame,
    area: Rect,
    count: u64,
    total: u64,
    color: ratatui::style::Color,
) {
    if area.width == 0 {
        return;
    }
    let pct = histogram_percent(count, total);
    let suffix = if area.width >= 10 {
        format!(" {pct:>4.1}%")
    } else {
        String::new()
    };
    let bar_width = area.width.saturating_sub(suffix.len() as u16) as usize;
    let filled = histogram_filled_cells(pct, bar_width);
    let spans = vec![
        Span::styled("█".repeat(filled), Style::default().fg(color)),
        Span::styled(
            "·".repeat(bar_width.saturating_sub(filled)),
            Style::default().fg(p::FAINT),
        ),
        Span::styled(suffix, Style::default().fg(p::DIM)),
    ];
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn histogram_percent(count: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 * 100.0 / total as f64
    }
}

fn histogram_filled_cells(percent: f64, width: usize) -> usize {
    if percent <= 0.0 || width == 0 {
        0
    } else {
        ((percent / 100.0 * width as f64).round() as usize).max(1)
    }
}

fn request_histogram(samples: &VecDeque<TracedLatencySample>) -> ([u64; 7], [u64; 7]) {
    let mut read = [0_u64; 7];
    let mut write = [0_u64; 7];
    for sample in samples {
        for bucket in 0..LATENCY_BUCKETS {
            let us = if bucket == 0 {
                1.0
            } else {
                (1_u64 << bucket) as f64
            };
            let band = latency_band(us);
            read[band] = read[band].saturating_add(sample.read[bucket]);
            write[band] = write[band].saturating_add(sample.write[bucket]);
        }
    }
    (read, write)
}

fn await_histogram(samples: &VecDeque<AwaitSample>) -> ([u64; 7], [u64; 7]) {
    let mut read = [0_u64; 7];
    let mut write = [0_u64; 7];
    for sample in samples {
        if let Some(value) = sample.read_us {
            read[latency_band(value)] += 1;
        }
        if let Some(value) = sample.write_us {
            write[latency_band(value)] += 1;
        }
    }
    (read, write)
}

#[derive(Debug)]
struct WorkloadView {
    iops: (Vec<f64>, Vec<f64>),
    throughput: (Vec<f64>, Vec<f64>),
    request_size: (Vec<Option<f64>>, Vec<Option<f64>>),
    merges: Option<(Vec<f64>, Vec<f64>)>,
}

fn combined_throughput(samples: &VecDeque<WorkloadSample>) -> Vec<f64> {
    samples
        .iter()
        .map(|sample| sample.read_bps + sample.write_bps)
        .collect()
}

fn combined_iops(samples: &VecDeque<WorkloadSample>) -> Vec<f64> {
    samples
        .iter()
        .map(|sample| sample.read_iops + sample.write_iops)
        .collect()
}

fn shared_workload_scale<'a>(series: impl IntoIterator<Item = &'a [f64]>) -> f64 {
    series
        .into_iter()
        .flatten()
        .copied()
        .filter(|value| value.is_finite())
        .fold(0.0_f64, f64::max)
        .max(1.0)
}

fn overview_workload_scales(visible: &[&IoTick], app: &App) -> (f64, f64) {
    let throughput: Vec<Vec<f64>> = visible
        .iter()
        .map(|tick| {
            app.io
                .history
                .get(&tick.device)
                .map(|history| combined_throughput(&history.workload_samples))
                .unwrap_or_default()
        })
        .collect();
    let iops: Vec<Vec<f64>> = visible
        .iter()
        .map(|tick| {
            app.io
                .history
                .get(&tick.device)
                .map(|history| combined_iops(&history.workload_samples))
                .unwrap_or_default()
        })
        .collect();
    (
        shared_workload_scale(throughput.iter().map(Vec::as_slice)),
        shared_workload_scale(iops.iter().map(Vec::as_slice)),
    )
}

#[derive(Debug, PartialEq)]
struct AwaitView {
    read: Vec<f64>,
    write: Vec<f64>,
}

fn await_view(samples: &VecDeque<AwaitSample>) -> AwaitView {
    AwaitView {
        read: samples
            .iter()
            .map(|sample| sample.read_us.unwrap_or(0.0))
            .collect(),
        write: samples
            .iter()
            .map(|sample| sample.write_us.unwrap_or(0.0))
            .collect(),
    }
}

fn await_scale(view: &AwaitView) -> f64 {
    paired_max(&view.read, &view.write)
}

fn workload_view(samples: &VecDeque<WorkloadSample>) -> WorkloadView {
    let mut view = WorkloadView {
        iops: (
            Vec::with_capacity(samples.len()),
            Vec::with_capacity(samples.len()),
        ),
        throughput: (
            Vec::with_capacity(samples.len()),
            Vec::with_capacity(samples.len()),
        ),
        request_size: (
            Vec::with_capacity(samples.len()),
            Vec::with_capacity(samples.len()),
        ),
        merges: None,
    };
    for sample in samples {
        view.iops.0.push(sample.read_iops);
        view.iops.1.push(sample.write_iops);
        view.throughput.0.push(sample.read_bps);
        view.throughput.1.push(sample.write_bps);
        view.request_size.0.push(sample.read_request_bytes);
        view.request_size.1.push(sample.write_request_bytes);
        if let MergeRates::Available {
            read_per_sec,
            write_per_sec,
        } = sample.merge_rates
        {
            let (read, write) = view.merges.get_or_insert_with(|| {
                (
                    Vec::with_capacity(samples.len()),
                    Vec::with_capacity(samples.len()),
                )
            });
            read.push(read_per_sec);
            write.push(write_per_sec);
        }
    }
    view
}

fn draw_direction_metrics(
    f: &mut Frame,
    rows: &[Rect],
    lane: IoLane,
    workload: Option<&WorkloadView>,
    await_view: Option<&AwaitView>,
) {
    if rows.is_empty() {
        return;
    }
    let Some(workload) = workload else {
        f.render_widget(
            Paragraph::new(Span::styled(
                " collecting workload history",
                Style::default().fg(p::DIM),
            )),
            rows[0],
        );
        return;
    };
    let read_size: Vec<f64> = workload
        .request_size
        .0
        .iter()
        .map(|v| v.unwrap_or(0.0))
        .collect();
    let write_size: Vec<f64> = workload
        .request_size
        .1
        .iter()
        .map(|v| v.unwrap_or(0.0))
        .collect();
    let metrics = [
        (
            "IOPS",
            lane_values(&workload.iops, lane),
            paired_max(&workload.iops.0, &workload.iops.1),
            format_iops as fn(f64) -> String,
        ),
        (
            "Throughput",
            lane_values(&workload.throughput, lane),
            paired_max(&workload.throughput.0, &workload.throughput.1),
            fmt_rate as fn(f64) -> String,
        ),
        (
            "Request size",
            match lane {
                IoLane::Read => read_size.as_slice(),
                IoLane::Write => write_size.as_slice(),
            },
            paired_max(&read_size, &write_size),
            format_bytes as fn(f64) -> String,
        ),
    ];
    for (area, (title, values, max, formatter)) in rows.iter().take(3).zip(metrics) {
        draw_direction_metric(f, *area, title, values, max, formatter, lane);
    }
    if rows.len() < 4 {
        return;
    }
    if let Some(merges) = &workload.merges {
        draw_direction_metric(
            f,
            rows[3],
            "Merges/s",
            lane_values(merges, lane),
            paired_max(&merges.0, &merges.1),
            format_iops,
            lane,
        );
    } else {
        f.render_widget(
            Paragraph::new(Span::styled(
                " Merges/s  unavailable",
                Style::default().fg(p::DIM),
            )),
            rows[3],
        );
    }
    if rows.len() < 5 {
        return;
    }
    if let Some(await_view) = await_view {
        draw_direction_metric(
            f,
            rows[4],
            "Await",
            match lane {
                IoLane::Read => &await_view.read,
                IoLane::Write => &await_view.write,
            },
            await_scale(await_view),
            format_latency,
            lane,
        );
    } else {
        f.render_widget(
            Paragraph::new(Span::styled(
                direction_metric_label("Await", "--"),
                Style::default().fg(p::DIM),
            )),
            rows[4],
        );
    }
}

fn lane_values(pair: &(Vec<f64>, Vec<f64>), lane: IoLane) -> &[f64] {
    match lane {
        IoLane::Read => &pair.0,
        IoLane::Write => &pair.1,
    }
}

fn draw_direction_metric(
    f: &mut Frame,
    area: Rect,
    title: &str,
    values: &[f64],
    max: f64,
    formatter: fn(f64) -> String,
    lane: IoLane,
) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let color = match lane {
        IoLane::Read => p::GREEN,
        IoLane::Write => p::CYAN,
    };
    let current = values.last().copied().unwrap_or(0.0);
    let label = direction_metric_label(title, &formatter(current));
    let label_width = (label.chars().count() as u16).min(area.width);
    f.render_widget(
        Paragraph::new(Span::styled(label, Style::default().fg(color))),
        Rect {
            width: label_width,
            ..area
        },
    );
    f.render_widget(
        BaselineSparkline::new(values)
            .max(max)
            .style(Style::default().fg(color).bg(p::BG)),
        Rect {
            x: area.x + label_width,
            width: area.width.saturating_sub(label_width),
            ..area
        },
    );
}

fn direction_metric_label(title: &str, value: &str) -> String {
    format!(" {title:<12} {:>11} ", value.trim())
}

fn draw_vfs_activity(f: &mut Frame, area: Rect, tick: &IoTick, app: &App) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let block = pane_block(Line::from(vec![
        Span::styled(
            " VFS ",
            Style::default()
                .fg(p::BR_WHITE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("| 10s ", Style::default().fg(p::DIM)),
    ]));
    let inner = block.inner(area);
    f.render_widget(block, area);
    if inner.height == 0 {
        return;
    }
    if vfs_entry_capacity(inner.height) == 0 {
        draw_vfs_status(f, inner, "need 2 rows");
        return;
    }

    if app.io.hot_files_source() != VfsActivitySource::EbpfRequestedBytes {
        draw_vfs_status(f, inner, vfs_unavailable_message(app.io.hot_files_status()));
        return;
    }

    let fs_devices = filesystem_device_ids_for_io(&tick.device, &app.filesystems);
    let entries = hot_files_for_fs_devices(&app.io.hot_files, &fs_devices);
    if entries.is_empty() {
        let status = if fs_devices.is_empty() {
            "no mounted filesystem attribution"
        } else {
            "no VFS activity in the last 10s"
        };
        draw_vfs_status(f, inner, status);
        return;
    }

    let capacity = vfs_entry_capacity(inner.height);
    let visible: Vec<_> = entries.into_iter().take(capacity).collect();
    let scale = vfs_activity_scale(&visible);
    for (row, item) in visible.into_iter().enumerate() {
        draw_vfs_entry(
            f,
            Rect {
                x: inner.x,
                y: inner.y + row as u16 * 2,
                width: inner.width,
                height: 2,
            },
            item,
            scale,
        );
    }
}

fn vfs_unavailable_message(status: &EbpfStatus) -> &'static str {
    match status {
        EbpfStatus::DisabledAtBuild => "unavailable in this build",
        EbpfStatus::UnsupportedPlatform => "unavailable on this platform",
        EbpfStatus::Unavailable(_) => "VFS eBPF tracing unavailable",
        EbpfStatus::Active => "VFS activity unavailable",
    }
}

fn draw_vfs_status(f: &mut Frame, area: Rect, message: &str) {
    f.render_widget(
        Paragraph::new(Span::styled(
            format!("  {message}"),
            Style::default().fg(p::DIM),
        )),
        Rect {
            y: area.y,
            height: 1,
            ..area
        },
    );
}

pub(crate) fn vfs_entry_capacity(rows: u16) -> usize {
    (rows / 2) as usize
}

pub(crate) fn draw_vfs_entry(f: &mut Frame, area: Rect, item: &VfsFileActivity, scale: f64) {
    if area.width == 0 || area.height < 2 {
        return;
    }
    let read_ops = format_iops(item.read_ops);
    let write_ops = format_iops(item.write_ops);
    let path = vfs_display_path(item);
    let (bar_width, rate_width, ops_width) = vfs_row_layout(area.width);
    let read = vfs_rate_field(item.read_bps, rate_width, area.width < 90);
    let write = vfs_rate_field(item.write_bps, rate_width, area.width < 90);
    let bar = vfs_bar_segments(item.read_bps, item.write_bps, scale, bar_width);
    let mut spans = vec![
        Span::styled("█".repeat(bar.read), Style::default().fg(p::GREEN)),
        Span::styled(
            "▀".repeat(bar.mixed),
            Style::default().fg(p::GREEN).bg(p::CYAN),
        ),
        Span::styled("█".repeat(bar.write), Style::default().fg(p::CYAN)),
        Span::styled("·".repeat(bar.empty), Style::default().fg(p::FAINT)),
        Span::raw(" "),
    ];
    let inode = format!("inode {}", item.inode);
    let inode_width = inode.chars().count().min(area.width as usize);
    let inode_x = area.x + area.width.saturating_sub(inode_width as u16);
    let stats_width = inode_x.saturating_sub(area.x).saturating_sub(2);
    if stats_width as usize >= vfs_stats_width(bar_width, rate_width, ops_width) {
        spans.extend([
            Span::styled(
                format!("R {read} {read_ops:>ops_width$}/s"),
                Style::default().fg(p::GREEN),
            ),
            Span::styled(
                format!(" W {write} {write_ops:>ops_width$}/s"),
                Style::default().fg(p::CYAN),
            ),
        ]);
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect {
            width: stats_width,
            height: 1,
            ..area
        },
    );
    f.render_widget(
        Paragraph::new(Span::styled(inode, Style::default().fg(p::DIM))),
        Rect {
            x: inode_x,
            width: inode_width as u16,
            height: 1,
            ..area
        },
    );

    let path_indent = (bar_width + 1).min(area.width as usize) as u16;
    let path_width = area.width.saturating_sub(path_indent) as usize;
    f.render_widget(
        Paragraph::new(Span::styled(
            truncate_text(&path, path_width),
            Style::default().fg(p::DIM),
        )),
        Rect {
            x: area.x + path_indent,
            y: area.y + 1,
            width: area.width.saturating_sub(path_indent),
            height: 1,
            ..area
        },
    );
}

pub(crate) fn vfs_activity_scale(entries: &[&VfsFileActivity]) -> f64 {
    entries
        .iter()
        .map(|item| item.read_bps + item.write_bps)
        .filter(|rate| rate.is_finite())
        .fold(0.0_f64, f64::max)
}

#[derive(Debug, PartialEq, Eq)]
struct VfsBarSegments {
    read: usize,
    mixed: usize,
    write: usize,
    empty: usize,
}

fn vfs_bar_segments(read: f64, write: f64, scale: f64, width: usize) -> VfsBarSegments {
    let read = read.max(0.0);
    let write = write.max(0.0);
    let total = read + write;
    if width == 0 || !total.is_finite() || !scale.is_finite() || scale <= 0.0 {
        return VfsBarSegments {
            read: 0,
            mixed: 0,
            write: 0,
            empty: width,
        };
    }
    let filled = if total > 0.0 {
        (((total / scale).clamp(0.0, 1.0) * width as f64).round() as usize).max(1)
    } else {
        0
    };
    let (read_cells, mixed_cells, write_cells) = if filled == 1 && read > 0.0 && write > 0.0 {
        (0, 1, 0)
    } else {
        let mut read_cells = if total > 0.0 {
            ((read / total) * filled as f64).round() as usize
        } else {
            0
        };
        if filled >= 2 && read > 0.0 && write > 0.0 {
            read_cells = read_cells.clamp(1, filled - 1);
        }
        let read_cells = read_cells.min(filled);
        (read_cells, 0, filled - read_cells)
    };
    VfsBarSegments {
        read: read_cells,
        mixed: mixed_cells,
        write: write_cells,
        empty: width - filled,
    }
}

fn vfs_row_layout(width: u16) -> (usize, usize, usize) {
    if width >= 90 {
        (7, 10, 5)
    } else {
        (3, 8, 4)
    }
}

fn vfs_stats_width(bar_width: usize, rate_width: usize, ops_width: usize) -> usize {
    // Bar + gutter, then aligned R/W labels, rates, and operation fields.
    bar_width + 1 + (2 + rate_width + 1 + ops_width + 2) + (3 + rate_width + 1 + ops_width + 2)
}

fn vfs_rate_field(rate: f64, width: usize, compact: bool) -> String {
    let full = fmt_rate(rate).trim().to_string();
    let value = if compact || full.chars().count() > width {
        compact_vfs_rate(rate)
    } else {
        full
    };
    format!("{value:>width$}")
}

fn compact_vfs_rate(rate: f64) -> String {
    if !rate.is_finite() || rate < 1.0 {
        return "--".into();
    }
    let (base, units): (f64, &[&str]) = match unit_mode() {
        UnitMode::Binary => (1024.0, &["B/s", "Ki/s", "Mi/s", "Gi/s", "Ti/s", "Pi/s"]),
        UnitMode::Decimal => (1000.0, &["B/s", "K/s", "M/s", "G/s", "T/s", "P/s"]),
    };
    let mut amount = rate;
    let mut unit = 0;
    while amount >= base && unit + 1 < units.len() {
        amount /= base;
        unit += 1;
    }
    let amount = if amount >= 10.0 {
        format!("{amount:.0}")
    } else {
        format!("{amount:.1}")
    };
    format!("{amount}{}", units[unit])
}

fn truncate_text(value: &str, width: usize) -> String {
    let len = value.chars().count();
    if len <= width {
        return value.to_string();
    }
    if width <= 3 {
        return ".".repeat(width);
    }
    let mut truncated: String = value.chars().take(width - 3).collect();
    truncated.push_str("...");
    truncated
}

fn truncate_line(value: &str, width: usize) -> String {
    let len = value.chars().count();
    if len <= width {
        return value.to_string();
    }
    if width <= 3 {
        return value.chars().take(width).collect();
    }
    let mut truncated: String = value.chars().take(width - 3).collect();
    truncated.push_str("...");
    truncated
}

fn vfs_display_path(item: &VfsFileActivity) -> String {
    let fallback = if item.basename.is_empty() {
        format!("inode {}", item.inode)
    } else {
        format!("{} [inode {}]", item.basename, item.inode)
    };
    if !item.path.is_empty() && item.path != fallback {
        return item.path.clone();
    }
    if !item.basename.is_empty() {
        format!("[unresolved] {}", item.basename)
    } else {
        "[unresolved] inode".into()
    }
}

fn hot_files_for_fs_devices<'a>(
    entries: &'a [VfsFileActivity],
    fs_devices: &HashSet<(u32, u32)>,
) -> Vec<&'a VfsFileActivity> {
    let mut filtered: Vec<_> = entries
        .iter()
        .filter(|entry| fs_devices.contains(&(entry.fs_device.major, entry.fs_device.minor)))
        .collect();
    filtered.sort_by(|a, b| {
        (b.read_bps + b.write_bps)
            .total_cmp(&(a.read_bps + a.write_bps))
            .then_with(|| b.write_ops.total_cmp(&a.write_ops))
    });
    filtered
}

fn filesystems_for_io_device<'a>(device: &str, filesystems: &'a [FsTick]) -> Vec<&'a FsTick> {
    filesystems
        .iter()
        .filter(|fs| mount_label_for_device(fs, device).is_some())
        .collect()
}

fn filesystem_free_pct(device: &str, filesystems: &[FsTick], volumes: &VolumeTick) -> Option<u32> {
    attributable_filesystems(device, filesystems, volumes)
        .into_iter()
        .filter(|fs| fs.size_bytes > 0)
        .map(|fs| {
            (fs.used_bytes as f64 / fs.size_bytes as f64 * 100.0)
                .round()
                .clamp(0.0, 100.0) as u32
        })
        .max()
        .map(|used| 100 - used)
}

#[cfg(target_os = "linux")]
fn filesystem_device_ids_for_io(device: &str, filesystems: &[FsTick]) -> HashSet<(u32, u32)> {
    filesystems_for_io_device(device, filesystems)
        .into_iter()
        .filter_map(|fs| std::fs::metadata(&fs.mount).ok())
        .map(|metadata| {
            let dev = metadata.dev();
            (linux_dev_major(dev), linux_dev_minor(dev))
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
fn filesystem_device_ids_for_io(_device: &str, _filesystems: &[FsTick]) -> HashSet<(u32, u32)> {
    HashSet::new()
}

#[cfg(target_os = "linux")]
fn linux_dev_major(dev: u64) -> u32 {
    (((dev >> 8) & 0xfff) | ((dev >> 32) & 0xffff_f000)) as u32
}

#[cfg(target_os = "linux")]
fn linux_dev_minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & 0xffff_ff00)) as u32
}

fn paired_max(read: &[f64], write: &[f64]) -> f64 {
    read.iter()
        .chain(write)
        .copied()
        .filter(|v| v.is_finite())
        .fold(0.0_f64, f64::max)
        .max(1.0)
}

fn format_latency(us: f64) -> String {
    if us <= 0.0 || !us.is_finite() {
        "--".to_string()
    } else if us >= 1_000_000.0 {
        format!("{:.1}s", us / 1_000_000.0)
    } else if us >= 10_000.0 {
        format!("{:.0}ms", us / 1_000.0)
    } else if us >= 1_000.0 {
        format!("{:.1}ms", us / 1_000.0)
    } else {
        format!("{:.0}us", us)
    }
}

fn format_bytes(value: f64) -> String {
    if !value.is_finite() || value <= 0.0 {
        "--".into()
    } else if value >= 1024.0 * 1024.0 {
        format!("{:.1}M", value / 1024.0 / 1024.0)
    } else if value >= 1024.0 {
        format!("{:.0}K", value / 1024.0)
    } else {
        format!("{value:.0}B")
    }
}

fn axis_spans(width: u16) -> Vec<Span<'static>> {
    if width == 0 {
        return Vec::new();
    }
    let mut chars = vec!['─'; width as usize];
    for (value, label) in [
        (50.0, "50us"),
        (1_000.0, "1ms"),
        (10_000.0, "10ms"),
        (100_000.0, "100ms"),
        (1_000_000.0, "1s"),
    ] {
        let pos = (log_latency(value) * width.saturating_sub(1) as f64).round() as usize;
        for (offset, ch) in label.chars().enumerate() {
            let start = pos.saturating_sub(label.len() / 2);
            if start + offset < chars.len() {
                chars[start + offset] = ch;
            }
        }
    }
    vec![Span::styled(
        chars.into_iter().collect::<String>(),
        Style::default().fg(p::DIM),
    )]
}

fn bucket_spans(width: usize) -> Vec<(usize, Range<usize>)> {
    if width == 0 {
        return Vec::new();
    }
    let mut spans = Vec::new();
    let mut start = 0;
    let mut previous = bucket_for_column(0, width);
    for column in 1..width {
        let bucket = bucket_for_column(column, width);
        if bucket != previous {
            spans.push((previous, start..column));
            start = column;
            previous = bucket;
        }
    }
    spans.push((previous, start..width));
    spans
}

fn bucket_for_column(column: usize, width: usize) -> usize {
    let fraction = (column as f64 + 0.5) / width as f64;
    let latency =
        (LATENCY_MIN_US.ln() + fraction * (LATENCY_MAX_US.ln() - LATENCY_MIN_US.ln())).exp();
    (latency.log2().floor() as usize).min(LATENCY_BUCKETS - 1)
}

fn request_spectrum(samples: &VecDeque<TracedLatencySample>, width: usize, lane: IoLane) -> String {
    if width == 0 {
        return String::new();
    }
    let counts: Vec<u64> = (0..LATENCY_BUCKETS)
        .map(|bucket| {
            samples.iter().fold(0_u64, |sum, sample| {
                sum.saturating_add(match lane {
                    IoLane::Read => sample.read[bucket],
                    IoLane::Write => sample.write[bucket],
                })
            })
        })
        .collect();
    let total = counts.iter().copied().sum();
    let mut chars = vec!['·'; width];
    for (bucket, span) in bucket_spans(width) {
        let ch = density_char(counts[bucket], total);
        chars[span].fill(ch);
    }
    let first_bucket = bucket_for_column(0, width);
    let last_bucket = bucket_for_column(width - 1, width);
    let below: u64 = counts[..first_bucket].iter().copied().sum();
    let above: u64 = counts[last_bucket + 1..].iter().copied().sum();
    if below > 0 {
        chars[0] = density_char(below, total);
    }
    if above > 0 {
        chars[width - 1] = density_char(above, total);
    }
    chars.into_iter().collect()
}

fn await_spectrum(samples: &VecDeque<AwaitSample>, width: usize, lane: IoLane) -> String {
    let mut counts = vec![0_u64; width];
    for value in samples.iter().filter_map(|sample| match lane {
        IoLane::Read => sample.read_us,
        IoLane::Write => sample.write_us,
    }) {
        let column = (log_latency(value) * width.saturating_sub(1) as f64).round() as usize;
        counts[column] += 1;
    }
    let total = counts.iter().copied().sum();
    counts
        .into_iter()
        .map(|count| density_char(count, total))
        .collect()
}

/// Fixed lane-share thresholds keep density comparable across devices:
/// <1%, 1-5%, 5-20%, and >=20% of the lane's observations.
fn density_char(count: u64, total: u64) -> char {
    if count == 0 || total == 0 {
        return '·';
    }
    let percent = count as f64 * 100.0 / total as f64;
    if percent < 1.0 {
        '░'
    } else if percent < 5.0 {
        '▒'
    } else if percent < 20.0 {
        '▓'
    } else {
        '█'
    }
}

fn overlay_latency_marker(spectrum: &mut String, latency_us: Option<f64>) {
    let Some(latency_us) = latency_us else {
        return;
    };
    let mut chars: Vec<char> = spectrum.chars().collect();
    if chars.is_empty() {
        return;
    }
    let position =
        (log_latency(latency_us) * chars.len().saturating_sub(1) as f64).round() as usize;
    chars[position] = '◆';
    *spectrum = chars.into_iter().collect();
}

fn spectrum_spans(spectrum: String, color: ratatui::style::Color) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut density = String::new();
    for ch in spectrum.chars() {
        if ch == '◆' {
            if !density.is_empty() {
                spans.push(Span::styled(
                    std::mem::take(&mut density),
                    Style::default().fg(color),
                ));
            }
            spans.push(Span::styled(
                "◆",
                Style::default()
                    .fg(p::BR_WHITE)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            density.push(ch);
        }
    }
    if !density.is_empty() {
        spans.push(Span::styled(density, Style::default().fg(color)));
    }
    spans
}

fn latency_band(us: f64) -> usize {
    HEAT_BOUNDS_US
        .iter()
        .position(|bound| us < *bound)
        .unwrap_or(6)
}

fn directional_quantile(
    samples: &VecDeque<TracedLatencySample>,
    lane: IoLane,
    quantile: f64,
) -> Option<f64> {
    histogram_counts_quantile(
        (0..LATENCY_BUCKETS).map(|index| {
            samples.iter().fold(0_u64, |total, sample| {
                total.saturating_add(match lane {
                    IoLane::Read => sample.read[index],
                    IoLane::Write => sample.write[index],
                })
            })
        }),
        quantile,
    )
}

fn histogram_counts_quantile(counts: impl IntoIterator<Item = u64>, quantile: f64) -> Option<f64> {
    let counts: Vec<u64> = counts.into_iter().collect();
    let total: u64 = counts.iter().copied().sum();
    if total == 0 {
        return None;
    }
    let target = ((total as f64 * quantile.clamp(0.0, 1.0)).ceil() as u64).max(1);
    let mut seen = 0_u64;
    for (index, count) in counts.into_iter().enumerate() {
        seen = seen.saturating_add(count);
        if seen >= target {
            return Some(if index + 1 == LATENCY_BUCKETS {
                (1_u64 << index) as f64
            } else {
                (1_u64 << (index + 1)) as f64
            });
        }
    }
    None
}

fn await_peak(samples: &VecDeque<AwaitSample>, lane: IoLane) -> Option<f64> {
    samples
        .iter()
        .filter_map(|sample| match lane {
            IoLane::Read => sample.read_us,
            IoLane::Write => sample.write_us,
        })
        .reduce(f64::max)
}

fn format_iops(iops: f64) -> String {
    if !iops.is_finite() || iops < 0.1 {
        "--".to_string()
    } else if iops >= 1_000.0 {
        format!("{:.1}k", iops / 1_000.0)
    } else {
        format!("{iops:.0}")
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

fn detail_header(device: &str, filesystems: &[FsTick], volumes: &VolumeTick) -> String {
    let mut chains: Vec<String> = attributable_filesystems(device, filesystems, volumes)
        .into_iter()
        .map(|fs| topology_chain(device, fs, volumes))
        .collect();
    chains.sort_unstable();
    chains.dedup();
    if chains.is_empty() {
        return format!(" {device} | no mount ");
    }
    let extra = chains.len().saturating_sub(2);
    let mut topology = chains.into_iter().take(2).collect::<Vec<_>>().join("; ");
    if extra > 0 {
        topology.push_str(&format!(" +{extra} mounts"));
    }
    format!(" {device} | {topology} ")
}

fn topology_chain(device: &str, fs: &FsTick, volumes: &VolumeTick) -> String {
    let source = disk_name(&fs.device);
    if let Some(array) = md_array_for_source(source, &volumes.mdraid) {
        let array_label = if array.level.is_empty() {
            array.name.clone()
        } else {
            format!("{}/{}", array.name, array.level)
        };
        let members = format_md_members(&array.members, device);
        if members.is_empty() {
            return format!("{} → {array_label}", fs.mount);
        }
        return format!("{} → {array_label} → {{{members}}}", fs.mount);
    }

    if let Some(container) = apfs_container_for_source(source, &volumes.containers) {
        let mut nodes = vec![fs.mount.clone(), source.to_string(), container.bsd.clone()];
        if let Some(store) = container.physical_store.as_deref() {
            nodes.push(store.to_string());
            let whole = whole_disk_name(store);
            if whole != store {
                nodes.push(whole.to_string());
            }
        }
        nodes.dedup();
        return nodes.join(" → ");
    }

    let mut nodes = vec![fs.mount.clone(), source.to_string()];
    let resolved = resolved_block_name(&fs.device);
    if resolved != source {
        nodes.push(resolved.clone());
    }
    let whole = whole_disk_name(&resolved);
    if whole != resolved && whole == disk_name(device) {
        nodes.push(whole.to_string());
    }
    nodes.dedup();
    nodes.join(" → ")
}

fn format_md_members(members: &[MdRaidMember], selected: &str) -> String {
    members
        .iter()
        .map(|member| {
            let marker = if whole_disk_name(&member.device) == disk_name(selected) {
                " (selected)"
            } else {
                ""
            };
            format!("{}{marker}", member.device)
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn md_array_for_source<'a>(source: &str, arrays: &'a [MdRaidArray]) -> Option<&'a MdRaidArray> {
    arrays
        .iter()
        .find(|array| disk_name(&array.name) == disk_name(source))
}

fn md_array_contains_device(array: &MdRaidArray, device: &str) -> bool {
    array
        .members
        .iter()
        .any(|member| whole_disk_name(&member.device) == disk_name(device))
}

fn apfs_container_for_source<'a>(
    source: &str,
    containers: &'a [ApfsContainer],
) -> Option<&'a ApfsContainer> {
    containers
        .iter()
        .find(|container| disk_name(&container.bsd) == whole_disk_name(source))
}

fn apfs_container_contains_device(container: &ApfsContainer, device: &str) -> bool {
    container
        .physical_store
        .as_deref()
        .is_some_and(|store| whole_disk_name(disk_name(store)) == disk_name(device))
}

fn attributable_filesystems<'a>(
    device: &str,
    filesystems: &'a [FsTick],
    volumes: &VolumeTick,
) -> Vec<&'a FsTick> {
    filesystems
        .iter()
        .filter(|fs| {
            direct_mount_label_for_device(fs, device).is_some()
                || md_array_for_source(disk_name(&fs.device), &volumes.mdraid).is_some_and(
                    |array| {
                        disk_name(&array.name) == disk_name(device)
                            || md_array_contains_device(array, device)
                    },
                )
                || apfs_container_for_source(disk_name(&fs.device), &volumes.containers)
                    .is_some_and(|container| apfs_container_contains_device(container, device))
                || mount_label_for_device(fs, device).is_some()
        })
        .collect()
}

fn detail_context_lines(tick: &IoTick, app: &App) -> Vec<String> {
    let device = device_for_io(&tick.device, &app.devices);
    let filesystems = attributable_filesystems(&tick.device, &app.filesystems, &app.volumes);
    let mut lines = Vec::new();
    if let Some(facts) = device_and_filesystem_facts(device, &filesystems) {
        lines.push(facts);
    }
    let smart = smart_for_io(&tick.device, device, &app.smart.by_device);
    if let Some(facts) = smart_facts(smart, device.and_then(|device| device.smart_ok)) {
        lines.push(facts);
    }
    lines
}

fn device_for_io<'a>(device: &str, devices: &'a [DeviceTick]) -> Option<&'a DeviceTick> {
    devices
        .iter()
        .find(|candidate| disk_name(&candidate.name) == disk_name(device))
}

fn smart_for_io<'a>(
    device: &str,
    device_tick: Option<&DeviceTick>,
    smart: &'a HashMap<String, SmartTick>,
) -> Option<&'a SmartTick> {
    smart
        .get(disk_name(device))
        .or_else(|| device_tick.and_then(|device| smart.get(disk_name(&device.name))))
}

fn device_and_filesystem_facts(
    device: Option<&DeviceTick>,
    filesystems: &[&FsTick],
) -> Option<String> {
    let mut facts = Vec::new();
    if let Some(device) = device {
        if meaningful_fact(&device.model) {
            facts.push(device.model.clone());
        }

        // Some virtualized environments expose NVMe media as an sd* SCSI disk
        // and report rotational=1. Keep the model, but do not present the
        // resulting SATA/HDD guesses as physical facts.
        if !model_encodes_nvme_identity(device) {
            if meaningful_fact(&device.bus) {
                facts.push(device.bus.clone());
            }
            if device.kind.label() != "?" {
                facts.push(device.kind.label().to_string());
            }
        }
    }

    let mut fs_types: Vec<&str> = filesystems
        .iter()
        .map(|fs| fs.fs_type.as_str())
        .filter(|fs_type| meaningful_fact(fs_type))
        .collect();
    fs_types.sort_unstable();
    fs_types.dedup();
    if !fs_types.is_empty() {
        facts.push(fs_types.join(","));
    }

    let mut seen = HashSet::new();
    let (free, total) = filesystems
        .iter()
        .filter(|fs| fs.size_bytes > 0)
        .filter(|fs| {
            seen.insert(format!(
                "{}:{}:{}",
                fs.device, fs.size_bytes, fs.avail_bytes
            ))
        })
        .fold((0_u64, 0_u64), |(free, total), fs| {
            (
                free.saturating_add(fs.avail_bytes),
                total.saturating_add(fs.size_bytes),
            )
        });
    if total > 0 {
        facts.push(format!("{} free / {}", fmt_size(free), fmt_size(total)));
    }
    let inode_values: Vec<u32> = filesystems.iter().filter_map(|fs| fs.inode_pct).collect();
    if let Some(max_inode) = inode_values.iter().copied().max() {
        let label = if inode_values.len() > 1 {
            "inodes max"
        } else {
            "inodes"
        };
        facts.push(format!("{label} {max_inode}% used"));
    }
    (!facts.is_empty()).then(|| format!(" {}", facts.join(" · ")))
}

fn model_encodes_nvme_identity(device: &DeviceTick) -> bool {
    let model = device.model.to_ascii_lowercase();
    model
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| word == "nvme")
}

fn smart_facts(smart: Option<&SmartTick>, fallback: Option<bool>) -> Option<String> {
    let mut facts = Vec::new();
    if let Some(smart) = smart {
        if let Some(temperature) = smart.temperature_c {
            facts.push(format!("SMART temp {temperature}C"));
        }
        if let Some(wear) = smart.percentage_used {
            facts.push(format!("wear {wear}%"));
        }
        if let Some(spare) = smart.available_spare {
            facts.push(format!("spare {spare}%"));
        }
        if let Some(hours) = smart.power_on_hours {
            facts.push(format!("power-on {hours}h"));
        }
        for attr in &smart.ata_attrs {
            if let Some(label) = ata_evidence_label(attr) {
                let raw = if attr.raw.is_empty() {
                    attr.value.to_string()
                } else {
                    attr.raw.clone()
                };
                facts.push(format!("{label} raw {raw}"));
            }
        }
    } else if let Some(ok) = fallback {
        facts.push(if ok {
            "SMART reported verified".into()
        } else {
            "SMART reported failing".into()
        });
    }
    (!facts.is_empty()).then(|| format!(" {}", facts.join(" · ")))
}

fn ata_evidence_label(attr: &AtaAttr) -> Option<&'static str> {
    match attr.id {
        5 => Some("reallocated"),
        187 => Some("reported uncorrectable"),
        197 => Some("pending"),
        198 => Some("offline uncorrectable"),
        _ if attr.name.to_ascii_lowercase().contains("media") => Some("media errors"),
        _ => None,
    }
}

fn meaningful_fact(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value != "—"
        && value != "-"
        && value != "?"
        && !value.eq_ignore_ascii_case("unknown")
}

fn io_device_is_mounted(device: &str, filesystems: &[FsTick], volumes: &VolumeTick) -> bool {
    !attributable_filesystems(device, filesystems, volumes).is_empty()
}

fn mount_label_for_device(fs: &FsTick, io_device: &str) -> Option<String> {
    if let Some(label) = direct_mount_label_for_device(fs, io_device) {
        return Some(label);
    }

    let stacked = stacked_members(&fs.device)?;
    mount_label_for_device_with_members(fs, io_device, &stacked)
}

fn direct_mount_label_for_device(fs: &FsTick, io_device: &str) -> Option<String> {
    let fs_device = resolved_block_name(&fs.device);
    if block_source_matches_io(&fs_device, io_device) {
        return Some(fs.mount.clone());
    }
    None
}

fn block_source_matches_io(source: &str, io_device: &str) -> bool {
    let io = disk_name(io_device);
    source == io || whole_disk_name(source) == io
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

    let kernel_name = resolved_block_name(device);
    let slaves_dir = format!("/sys/block/{}/slaves", kernel_name);
    if !std::path::Path::new(&slaves_dir).is_dir() {
        return None;
    }

    let mut out = Vec::new();
    expand(&kernel_name, 4, &mut out);
    out.sort();
    out.dedup();
    Some(out)
}

fn disk_name(device: &str) -> &str {
    device.strip_prefix("/dev/").unwrap_or(device)
}

fn block_name_with_mapper_target(device: &str, target: Option<&Path>) -> String {
    let name = disk_name(device);
    if !name.starts_with("mapper/") {
        return name.to_string();
    }
    target
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string())
}

fn resolved_block_name(device: &str) -> String {
    #[cfg(target_os = "linux")]
    {
        let target = disk_name(device)
            .starts_with("mapper/")
            .then(|| std::fs::read_link(format!("/dev/{}", disk_name(device))).ok())
            .flatten();
        block_name_with_mapper_target(device, target.as_deref())
    }
    #[cfg(not(target_os = "linux"))]
    {
        block_name_with_mapper_target(device, None)
    }
}

fn whole_disk_name(device: &str) -> &str {
    if let Some((base, part)) = device.rsplit_once('p') {
        if base.starts_with("nvme")
            || base.starts_with("mmcblk")
            || base.starts_with("md")
            || base.starts_with("dm-")
        {
            if part.chars().all(|c| c.is_ascii_digit()) {
                return base;
            }
        }
    }

    if device
        .strip_prefix("md")
        .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
        || device
            .strip_prefix("dm-")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()))
    {
        return device;
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
    use crate::collect::ebpf::BlockDeviceId;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

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

    fn fs_usage(device: &str, mount: &str, used: u64, size: u64) -> FsTick {
        FsTick {
            used_bytes: used,
            size_bytes: size,
            ..fs(device, mount)
        }
    }

    fn md_array() -> MdRaidArray {
        MdRaidArray {
            name: "md0".into(),
            level: "raid1".into(),
            state: "active".into(),
            size_bytes: 1 << 30,
            members_total: 2,
            members_present: 2,
            member_state: "UU".into(),
            members: vec![
                MdRaidMember {
                    device: "sdd1".into(),
                    index: 0,
                    flag: None,
                },
                MdRaidMember {
                    device: "sde1".into(),
                    index: 1,
                    flag: None,
                },
            ],
            progress: None,
        }
    }

    fn hot_file(major: u32, minor: u32, read_bps: f64, write_bps: f64) -> VfsFileActivity {
        VfsFileActivity {
            fs_device: BlockDeviceId { major, minor },
            inode: 42,
            pid: 7,
            tgid: 7,
            comm: "writer".into(),
            basename: "data.bin".into(),
            path: "/srv/data.bin".into(),
            read_bps,
            write_bps,
            read_ops: 2.0,
            write_ops: 3.0,
        }
    }

    #[test]
    fn maps_linux_partition_mounts_to_whole_disk() {
        let filesystems = vec![fs("/dev/sda1", "/"), fs("/dev/sda2", "/home")];

        assert_eq!(
            mounts_for_device("sda", &filesystems),
            Some("/, /home".to_string())
        );
        assert!(io_device_is_mounted(
            "sda",
            &filesystems,
            &VolumeTick::default()
        ));
        assert!(!io_device_is_mounted(
            "sdb",
            &filesystems,
            &VolumeTick::default()
        ));
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
    fn stacked_mount_is_included_for_selected_member() {
        let filesystems = vec![fs("/dev/md0", "/mnt/optane")];
        let members = vec!["sdd".to_string(), "sde".to_string()];

        let selected: Vec<_> = filesystems
            .iter()
            .filter(|fs| mount_label_for_device_with_members(fs, "sde", &members).is_some())
            .collect();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].mount, "/mnt/optane");
    }

    #[test]
    fn selected_device_vfs_filter_uses_filesystem_device_id_and_sorts() {
        let entries = vec![
            hot_file(8, 1, 0.0, 10.0),
            hot_file(8, 2, 0.0, 1_000.0),
            hot_file(8, 1, 500.0, 0.0),
        ];
        let ids = HashSet::from([(8, 1)]);

        let filtered = hot_files_for_fs_devices(&entries, &ids);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].read_bps, 500.0);
        assert_eq!(filtered[1].write_bps, 10.0);
    }

    #[test]
    fn vfs_paths_distinguish_resolved_paths_from_collector_fallbacks() {
        let mut item = hot_file(8, 1, 1.0, 0.0);
        assert_eq!(vfs_display_path(&item), "/srv/data.bin");

        item.path = "data.bin [inode 42]".into();
        assert_eq!(vfs_display_path(&item), "[unresolved] data.bin");

        item.path.clear();
        assert_eq!(vfs_display_path(&item), "[unresolved] data.bin");

        item.basename.clear();
        item.path = "inode 42".into();
        assert_eq!(vfs_display_path(&item), "[unresolved] inode");
    }

    #[test]
    fn vfs_unavailable_states_are_factual() {
        assert_eq!(
            vfs_unavailable_message(&EbpfStatus::DisabledAtBuild),
            "unavailable in this build"
        );
        assert_eq!(
            vfs_unavailable_message(&EbpfStatus::UnsupportedPlatform),
            "unavailable on this platform"
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
    fn histogram_quantiles_are_directional_and_request_weighted() {
        let mut first = TracedLatencySample::default();
        first.read[8] = 99;
        first.write[15] = 1;
        let mut second = TracedLatencySample::default();
        second.read[9] = 100;
        let history = std::collections::VecDeque::from([first, second]);

        assert_eq!(
            directional_quantile(&history, IoLane::Read, 0.50),
            Some(1024.0)
        );
        assert_eq!(
            directional_quantile(&history, IoLane::Read, 0.99),
            Some(1024.0)
        );
        assert_eq!(
            directional_quantile(&history, IoLane::Write, 1.0),
            Some(65536.0)
        );
    }

    #[test]
    fn request_spectrum_fills_each_bucket_contiguously() {
        let mut sample = TracedLatencySample::default();
        sample.read[8] = 100;
        sample.write[16] = 2;
        let history = std::collections::VecDeque::from([sample]);
        let read = request_spectrum(&history, 80, IoLane::Read);
        let write = request_spectrum(&history, 80, IoLane::Write);
        let inactive_write = request_spectrum(
            &VecDeque::from([{
                let mut sample = TracedLatencySample::default();
                sample.read[8] = 1;
                sample
            }]),
            80,
            IoLane::Write,
        );

        assert_eq!(read.chars().count(), 80);
        assert_eq!(write.chars().count(), 80);
        assert!(inactive_write.chars().all(|ch| ch == '·'));
        for (bucket, spectrum) in [(8, read), (16, write)] {
            let (_, span) = bucket_spans(80)
                .into_iter()
                .find(|(index, _)| *index == bucket)
                .expect("visible bucket span");
            let chars: Vec<char> = spectrum.chars().collect();
            assert!(chars[span].iter().all(|ch| *ch != '·'));
        }
    }

    #[test]
    fn bucket_spans_cover_axis_without_gaps_or_overlap() {
        let spans = bucket_spans(73);
        assert_eq!(spans.first().unwrap().1.start, 0);
        assert_eq!(spans.last().unwrap().1.end, 73);
        assert!(spans
            .windows(2)
            .all(|pair| pair[0].1.end == pair[1].1.start));
    }

    #[test]
    fn request_histogram_preserves_direction_and_fixed_latency_bands() {
        let mut early = TracedLatencySample::default();
        early.read[7] = 5; // 128us: first band
        let mut late = TracedLatencySample::default();
        late.write[18] = 3; // 262ms: final band
        let samples = VecDeque::from([early, late]);
        let (read, write) = request_histogram(&samples);

        assert_eq!(read[0], 5);
        assert_eq!(write[6], 3);
        assert_eq!(read.iter().chain(&write).copied().sum::<u64>(), 8);
    }

    #[test]
    fn aggregate_histogram_keeps_read_and_write_observations_distinct() {
        let samples = VecDeque::from([
            AwaitSample {
                read_us: Some(500.0),
                write_us: None,
            },
            AwaitSample {
                read_us: Some(8_000.0),
                write_us: Some(8_000.0),
            },
        ]);
        let (read, write) = await_histogram(&samples);

        assert_eq!(read[1], 1);
        assert_eq!(read[3], 1);
        assert_eq!(write[3], 1);
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
    fn free_space_uses_least_free_attributable_mounted_filesystem() {
        let filesystems = vec![
            fs_usage("/dev/sda1", "/", 40, 100),
            fs_usage("/dev/sda2", "/home", 85, 100),
            fs_usage("/dev/sda3", "/unknown", 1, 0),
            fs_usage("/dev/sdb1", "/other", 99, 100),
        ];

        let volumes = VolumeTick::default();
        assert_eq!(filesystem_free_pct("sda", &filesystems, &volumes), Some(15));
        assert_eq!(filesystem_free_pct("sdb", &filesystems, &volumes), Some(1));
        assert_eq!(filesystem_free_pct("sdc", &filesystems, &volumes), None);
    }

    #[test]
    fn detail_header_moves_mount_attribution_and_has_factual_fallback() {
        let filesystems = vec![fs("/dev/sda1", "/"), fs("/dev/sda2", "/home")];

        assert_eq!(
            detail_header("sda", &filesystems, &VolumeTick::default()),
            " sda | / → sda1 → sda; /home → sda2 → sda "
        );
        assert_eq!(
            detail_header("sdb", &filesystems, &VolumeTick::default()),
            " sdb | no mount "
        );
    }

    #[test]
    fn detail_header_renders_collected_md_topology_and_selected_member() {
        let filesystems = vec![fs("/dev/md0", "/mnt/data")];
        let volumes = VolumeTick {
            mdraid: vec![md_array()],
            ..VolumeTick::default()
        };

        assert_eq!(
            detail_header("sdd", &filesystems, &volumes),
            " sdd | /mnt/data → md0/raid1 → {sdd1 (selected),sde1} "
        );
    }

    #[test]
    fn apfs_topology_uses_collected_container_and_physical_store() {
        let filesystems = vec![fs("/dev/disk3s1", "/")];
        let volumes = VolumeTick {
            containers: vec![ApfsContainer {
                bsd: "disk3".into(),
                physical_store: Some("disk0s2".into()),
                ..ApfsContainer::default()
            }],
            ..VolumeTick::default()
        };

        assert_eq!(
            detail_header("disk0", &filesystems, &volumes),
            " disk0 | / → disk3s1 → disk3 → disk0s2 → disk0 "
        );
        assert_eq!(
            attributable_filesystems("disk0", &filesystems, &volumes).len(),
            1
        );
    }

    #[test]
    fn logical_devices_do_not_inherit_member_device_or_smart_facts() {
        let member = DeviceTick {
            name: "sda".into(),
            kind: crate::collect::devices::DeviceKind::Ssd,
            model: "member model".into(),
            bus: "SATA".into(),
            size_bytes: 1,
            used_bytes: 0,
            is_removable: false,
            firmware: None,
            serial: None,
            smart_ok: Some(true),
            idle: false,
        };
        let smart = HashMap::from([("sda".into(), SmartTick::default())]);

        assert!(device_for_io("md0", std::slice::from_ref(&member)).is_none());
        assert!(device_for_io("dm-0", std::slice::from_ref(&member)).is_none());
        assert!(smart_for_io("md0", None, &smart).is_none());
        assert!(smart_for_io("dm-0", None, &smart).is_none());
    }

    #[test]
    fn mapper_and_physical_device_normalization_is_explicit() {
        assert_eq!(
            block_name_with_mapper_target("/dev/mapper/vg-data", Some(Path::new("../dm-0"))),
            "dm-0"
        );
        assert!(block_source_matches_io("dm-0", "dm-0"));
        assert_eq!(whole_disk_name("sda1"), "sda");
        assert_eq!(whole_disk_name("nvme0n1p1"), "nvme0n1");
        assert_eq!(whole_disk_name("md0"), "md0");
        assert_eq!(whole_disk_name("dm-0"), "dm-0");
        assert!(!md_array_contains_device(&md_array(), "md0"));
    }

    #[test]
    fn device_filesystem_and_smart_facts_only_emit_available_evidence() {
        let device = DeviceTick {
            name: "sda".into(),
            kind: crate::collect::devices::DeviceKind::Ssd,
            model: "FastDisk".into(),
            bus: "SATA".into(),
            size_bytes: 1 << 40,
            used_bytes: 0,
            is_removable: false,
            firmware: None,
            serial: None,
            smart_ok: Some(true),
            idle: false,
        };
        let filesystem = FsTick {
            fs_type: "ext4".into(),
            size_bytes: 100 << 30,
            avail_bytes: 25 << 30,
            inode_pct: Some(42),
            ..fs("/dev/sda1", "/")
        };
        let facts = device_and_filesystem_facts(Some(&device), &[&filesystem]).unwrap();
        assert_eq!(
            facts,
            " FastDisk · SATA · SSD · ext4 · 25 GiB free / 100 GiB · inodes 42% used"
        );
        assert!(!facts.contains("device 1 TiB"));
        assert!(!facts.contains("model "));
        assert!(!facts.contains("bus "));
        assert!(!facts.contains("kind "));
        assert!(!facts.contains("fs "));
        assert!(!facts.contains("--"));
        assert!(!facts.contains("healthy"));

        let smart = SmartTick {
            temperature_c: Some(37),
            percentage_used: Some(8),
            available_spare: Some(99),
            power_on_hours: Some(1234),
            ata_attrs: vec![
                AtaAttr {
                    id: 5,
                    raw: "3".into(),
                    ..AtaAttr::default()
                },
                AtaAttr {
                    id: 197,
                    raw: "1".into(),
                    ..AtaAttr::default()
                },
            ],
            ..SmartTick::default()
        };
        let smart = smart_facts(Some(&smart), Some(false)).unwrap();
        assert!(smart.contains("SMART temp 37C"));
        assert!(smart.contains("wear 8% · spare 99% · power-on 1234h"));
        assert!(smart.contains("reallocated raw 3 · pending raw 1"));
        assert!(!smart.contains("failing"));
        assert_eq!(
            smart_facts(None, Some(false)).as_deref(),
            Some(" SMART reported failing")
        );
    }

    #[test]
    fn nvme_model_suppresses_contradictory_virtualized_bus_and_kind() {
        let device = DeviceTick {
            name: "sdf".into(),
            kind: crate::collect::devices::DeviceKind::Hdd,
            model: "NVMe WD_BLACK SN850X".into(),
            bus: "SATA / internal".into(),
            size_bytes: 4 << 40,
            used_bytes: 0,
            is_removable: false,
            firmware: None,
            serial: None,
            smart_ok: None,
            idle: false,
        };
        let filesystem = FsTick {
            fs_type: "ext4".into(),
            size_bytes: 100 << 30,
            avail_bytes: 25 << 30,
            ..fs("/dev/sdf1", "/home")
        };

        let facts = device_and_filesystem_facts(Some(&device), &[&filesystem]).unwrap();
        assert_eq!(
            facts,
            " NVMe WD_BLACK SN850X · ext4 · 25 GiB free / 100 GiB"
        );
        assert!(!facts.contains("SATA"));
        assert!(!facts.contains("HDD"));
        assert!(!facts.contains("4 TiB"));
    }

    #[test]
    fn md_state_line_only_reports_exceptional_arrays() {
        let normal = md_array();
        assert_eq!(md_exception_summary(&[normal.clone()]), None);

        let mut degraded = normal;
        degraded.members_present = 1;
        degraded.member_state = "U_".into();
        degraded.members[1].flag = Some("(F)".into());
        degraded.progress = Some(crate::collect::volumes::MdRaidProgress {
            op: "resync".into(),
            percent: 41.0,
            eta: "10min".into(),
            speed: "121 MiB/s".into(),
        });
        let summary = md_exception_summary(&[degraded]).unwrap();
        assert!(summary.contains("md0 · 1/2 members"));
        assert!(summary.contains("flags sde1(F)"));
        assert!(summary.contains("resync 41% @ 121 MiB/s"));
        assert!(summary.contains("affects sdd,sde"));
    }

    #[test]
    fn md_state_ignores_nonfailure_flags_and_incomplete_zero_counts() {
        for flag in ["(S)", "(W)"] {
            let mut array = md_array();
            array.members[0].flag = Some(flag.into());
            assert_eq!(md_exception_summary(&[array]), None);
        }

        let mut incomplete = md_array();
        incomplete.members_total = 0;
        incomplete.members_present = 0;
        incomplete.members.clear();
        incomplete.member_state.clear();
        assert_eq!(md_exception_summary(&[incomplete.clone()]), None);

        incomplete.member_state = "U_".into();
        let summary = md_exception_summary(&[incomplete]).unwrap();
        assert!(summary.starts_with(" md0 · 0/0 members"));

        let mut failed = md_array();
        failed.members[0].flag = Some("(f)".into());
        assert!(md_exception_summary(&[failed]).is_some());
    }

    #[test]
    fn context_rows_preserve_directional_and_normal_vfs_bodies() {
        assert_eq!(detail_context_row_count(28, 2), 2);
        let (_, _, tall_vfs) = detail_areas(Rect::new(0, 0, 130, 25));
        assert_eq!(tall_vfs.height, 10);

        assert_eq!(detail_context_row_count(23, 2), 2);
        let (_, _, compact_vfs) = detail_areas(Rect::new(0, 0, 110, 18));
        assert_eq!(compact_vfs.height, 3);

        assert_eq!(detail_context_row_count(14, 2), 0);
        let (read, write, _) = detail_areas(Rect::new(0, 0, 60, 13));
        assert_eq!((read.height, write.height), (13, 13));
    }

    #[test]
    fn bands_are_single_column_and_scroll_to_selection() {
        assert_eq!(visible_band_window(3, 6, 0), (0, 3, 0));
        assert_eq!(visible_band_window(3, 6, 4), (2, 3, 4));
        assert_eq!(visible_band_window(3, 6, 5), (3, 3, 5));
    }

    #[test]
    fn undersized_band_area_still_has_one_visible_device() {
        assert_eq!(visible_band_window(1, 10, 7), (7, 1, 7));
        assert_eq!(visible_band_window(0, 10, 7), (7, 0, 7));
        assert_eq!(visible_band_window(0, 0, 0), (0, 0, 0));
    }

    #[test]
    fn pane_layout_reserves_borders_and_one_separator_row() {
        assert_eq!(master_detail_heights(28, 30), (5, 23));
        assert_eq!(master_detail_heights(28, 8), (5, 23));
        assert_eq!(master_detail_heights(8, 8), (4, 4));
        assert_eq!(master_detail_heights(1, 8), (1, 0));
        let (overview, detail) = master_detail_heights(28, 8);
        assert!(overview + detail <= 28);
        assert_eq!(row_geometry(60).label + row_geometry(60).plot, 60);
        assert_eq!(row_geometry(130).label, 43);
        assert_eq!(row_geometry(130).plot, 87);
        assert_eq!(latency_plot_geometry(row_geometry(110).plot).read, 31);
    }

    #[test]
    fn overview_workload_combines_directions_and_shares_visible_scales() {
        let slow = VecDeque::from([WorkloadSample {
            read_iops: 1.0,
            write_iops: 2.0,
            read_bps: 10.0,
            write_bps: 20.0,
            ..WorkloadSample::default()
        }]);
        let fast = VecDeque::from([WorkloadSample {
            read_iops: 10.0,
            write_iops: 30.0,
            read_bps: 100.0,
            write_bps: 300.0,
            ..WorkloadSample::default()
        }]);
        let slow_throughput = combined_throughput(&slow);
        let fast_throughput = combined_throughput(&fast);
        let slow_iops = combined_iops(&slow);
        let fast_iops = combined_iops(&fast);

        assert_eq!(slow_throughput, vec![30.0]);
        assert_eq!(fast_throughput, vec![400.0]);
        assert_eq!(slow_iops, vec![3.0]);
        assert_eq!(fast_iops, vec![40.0]);
        assert_eq!(
            shared_workload_scale([slow_throughput.as_slice(), fast_throughput.as_slice()]),
            400.0
        );
        assert_eq!(
            shared_workload_scale([slow_iops.as_slice(), fast_iops.as_slice()]),
            40.0
        );
    }

    #[test]
    fn overview_headers_and_rows_share_column_and_latency_boundaries() {
        let width = 60;
        let geometry = row_geometry(width);
        assert_eq!(geometry.label, 13);
        assert_eq!(overview_prefix_geometry(geometry.label).throughput, 0);
        assert_eq!(overview_prefix_geometry(geometry.label).iops, 0);
        assert_eq!(
            overview_prefix_geometry(30),
            OverviewPrefixGeometry {
                device: 10,
                free: 4,
                throughput: 6,
                iops: 5,
            }
        );
        assert_eq!(overview_prefix_header(30), " Device     Free B/s    IOPS  ");
        assert_eq!(overview_prefix_header(30).chars().count(), 30);
        assert_eq!(overview_prefix_header(43).chars().count(), 43);
        let lanes = latency_plot_geometry(geometry.plot);
        let backend = TestBackend::new(width, 1);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                draw_overview_prefix(
                    frame,
                    Rect::new(0, 0, geometry.label, 1),
                    "nvme0n1",
                    Some(85),
                    &[100.0],
                    100.0,
                    &[10.0],
                    10.0,
                    true,
                );
                draw_latency_plot(
                    frame,
                    Rect::new(geometry.label, 0, geometry.plot, 1),
                    "·".repeat(lanes.read as usize),
                    "·".repeat(lanes.write as usize),
                );
            })
            .expect("draw narrow overview");
        let buffer = terminal.backend().buffer();
        let line = (0..width)
            .map(|x| buffer.cell((x, 0)).unwrap().symbol())
            .collect::<String>();

        assert!(line.starts_with("▌nvm~  85%"));
        assert_eq!(buffer.cell((geometry.label - 1, 0)).unwrap().symbol(), " ");
        assert_eq!(buffer.cell((geometry.label, 0)).unwrap().symbol(), "R");
    }

    #[test]
    fn overview_workload_sparklines_keep_separate_gutters() {
        let width = 44;
        let backend = TestBackend::new(width, 1);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                draw_overview_prefix(
                    frame,
                    Rect::new(0, 0, 43, 1),
                    "nvme0n1",
                    Some(85),
                    &[100.0],
                    100.0,
                    &[10.0],
                    10.0,
                    true,
                );
                frame.render_widget(Paragraph::new("R"), Rect::new(43, 0, 1, 1));
            })
            .expect("draw overview prefix");
        let buffer = terminal.backend().buffer();

        assert_ne!(buffer.cell((28, 0)).unwrap().symbol(), " ");
        assert_eq!(buffer.cell((29, 0)).unwrap().symbol(), " ");
        assert_ne!(buffer.cell((41, 0)).unwrap().symbol(), " ");
        assert_eq!(buffer.cell((42, 0)).unwrap().symbol(), " ");
        assert_eq!(buffer.cell((43, 0)).unwrap().symbol(), "R");
    }

    #[test]
    fn latency_plot_reserves_all_separators_and_keeps_right_edge_marker_visible() {
        for width in [80, 130] {
            let row = row_geometry(width);
            let lanes = latency_plot_geometry(row.plot);
            assert_eq!(lanes.rendered_width(), row.plot);
            let mut write = "·".repeat(lanes.write as usize);
            overlay_latency_marker(&mut write, Some(LATENCY_MAX_US));
            let backend = TestBackend::new(row.plot, 1);
            let mut terminal = Terminal::new(backend).expect("terminal");
            terminal
                .draw(|frame| {
                    draw_latency_plot(
                        frame,
                        frame.area(),
                        "·".repeat(lanes.read as usize),
                        write.clone(),
                    )
                })
                .expect("draw latency plot");

            assert_eq!(
                terminal
                    .backend()
                    .buffer()
                    .cell((row.plot - 1, 0))
                    .unwrap()
                    .symbol(),
                "◆"
            );
        }
    }

    #[test]
    fn latency_scale_is_fixed_and_logarithmic() {
        assert_eq!(log_latency(0.0), 0.0);
        assert_eq!(log_latency(LATENCY_MIN_US), 0.0);
        assert!((log_latency(LATENCY_MAX_US) - 1.0).abs() < f64::EPSILON);
        assert!(log_latency(1_000.0) < log_latency(10_000.0));
        assert_eq!(log_latency(10_000_000.0), 1.0);
    }

    #[test]
    fn density_glyphs_have_fixed_lane_share_meaning() {
        assert_eq!(density_char(0, 100), '·');
        assert_eq!(density_char(1, 200), '░'); // 0.5%
        assert_eq!(density_char(1, 100), '▒'); // 1%
        assert_eq!(density_char(5, 100), '▓'); // 5%
        assert_eq!(density_char(20, 100), '█'); // 20%
        assert_eq!(density_char(50, 1_000), density_char(5, 100));
    }

    #[test]
    fn latency_marker_uses_fixed_log_axis_and_preserves_width() {
        let mut spectrum = "·········".to_string();
        overlay_latency_marker(&mut spectrum, Some(LATENCY_MIN_US));
        assert_eq!(spectrum.chars().next(), Some('◆'));
        assert_eq!(spectrum.chars().count(), 9);

        overlay_latency_marker(&mut spectrum, Some(LATENCY_MAX_US));
        assert_eq!(spectrum.chars().last(), Some('◆'));

        let unchanged = spectrum.clone();
        overlay_latency_marker(&mut spectrum, None);
        assert_eq!(spectrum, unchanged);
    }

    #[test]
    fn paired_graphs_share_one_scale() {
        assert_eq!(paired_max(&[1.0, 3.0], &[2.0, 9.0]), 9.0);
        assert_eq!(paired_max(&[], &[]), 1.0);
    }

    #[test]
    fn pane_borders_match_the_original_overview_style() {
        let backend = TestBackend::new(24, 4);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| frame.render_widget(pane_block(" pane "), frame.area()))
            .expect("draw pane");
        let buffer = terminal.backend().buffer();

        for (x, y) in [(0, 0), (23, 0), (0, 3), (23, 3)] {
            let expected = match (x, y) {
                (0, 0) => "┌",
                (23, 0) => "┐",
                (0, 3) => "└",
                (23, 3) => "┘",
                _ => unreachable!(),
            };
            assert_eq!(buffer.cell((x, y)).unwrap().symbol(), expected);
        }
        assert_eq!(buffer.cell((0, 1)).unwrap().symbol(), "│");
        assert_eq!(buffer.cell((23, 1)).unwrap().symbol(), "│");
        assert_eq!(buffer.cell((12, 3)).unwrap().symbol(), "─");
    }

    #[test]
    fn histogram_percentages_use_directional_totals() {
        assert_eq!(histogram_percent(1, 4), 25.0);
        assert_eq!(histogram_percent(0, 0), 0.0);
    }

    #[test]
    fn histogram_bars_show_every_nonzero_band() {
        assert_eq!(histogram_filled_cells(0.0, 10), 0);
        assert_eq!(histogram_filled_cells(0.1, 10), 1);
        assert_eq!(histogram_filled_cells(0.9, 10), 1);
        assert_eq!(histogram_filled_cells(1.0, 10), 1);
        assert_eq!(histogram_filled_cells(10.0, 10), 1);
        assert_eq!(histogram_filled_cells(10.0, 20), 2);
    }

    #[test]
    fn detail_layout_is_responsive_and_bounded() {
        let wide = Rect::new(0, 0, 130, 18);
        let (read, write, vfs) = detail_areas(wide);
        assert_eq!((read.height, write.height), (14, 14));
        assert_eq!((read.width, write.width), (64, 65));
        assert_eq!(write.x, read.x + read.width + 1);
        assert_eq!(vfs.width, 130);
        assert_eq!(vfs.height, 3);
        assert_eq!(vfs.y, 15);

        let tall = Rect::new(0, 0, 130, 70);
        let (read, write, vfs) = detail_areas(tall);
        assert_eq!((read.height, write.height), (14, 14));
        assert_eq!((vfs.y, vfs.height), (15, 11));
        assert_eq!(vfs_entry_capacity(vfs.height.saturating_sub(2)), 4);
        assert_eq!(vfs.y + vfs.height, WIDE_DETAIL_BODY_HEIGHT);

        let (overview, detail) = master_detail_heights(68, 5);
        assert_eq!((overview, detail), (8, WIDE_DETAIL_HEIGHT));
        assert_eq!(overview + detail, 36);

        let narrow = Rect::new(0, 0, 72, 12);
        let (read, write, vfs) = detail_areas(narrow);
        assert_eq!((read.width, write.width), (35, 36));
        assert_eq!((read.height, write.height), (12, 12));
        assert_eq!(vfs.height, 0);

        let tiny = Rect::new(0, 0, 20, 3);
        let (read, write, vfs) = detail_areas(tiny);
        assert_eq!((read.width, write.width), (9, 10));
        assert_eq!((read.height, write.height), (3, 3));
        assert_eq!(vfs.height, 0);
    }

    #[test]
    fn directional_detail_columns_have_explicit_gutter() {
        let (read, write, _) = detail_areas(Rect::new(3, 4, 57, 12));
        assert_eq!(read.width + 1 + write.width, 57);
        assert_eq!(write.x, read.x + read.width + 1);
    }

    #[test]
    fn directional_metric_labels_have_one_fixed_graph_origin() {
        let labels = [
            direction_metric_label("IOPS", "73"),
            direction_metric_label("Throughput", "9.9 MiB/s"),
            direction_metric_label("Request size", "139K"),
            direction_metric_label("Merges/s", "3.6k"),
            direction_metric_label("Await", "2.1ms"),
            direction_metric_label("IOPS", "--"),
        ];
        assert!(labels.iter().all(|label| label.chars().count() == 26));
        assert!(labels.iter().all(|label| label.ends_with(' ')));
    }

    #[test]
    fn vfs_path_text_only_truncates_at_its_row_edge() {
        assert_eq!(truncate_text("Cache worker foo", 12), "Cache wor...");
        assert_eq!(truncate_text("short", 12), "short");
        assert_eq!(truncate_text("long", 3), "...");
    }

    #[test]
    fn vfs_activity_bars_share_a_combined_rate_scale() {
        let hot = hot_file(8, 1, 75.0, 25.0);
        let cool = hot_file(8, 1, 10.0, 10.0);
        let entries = [&hot, &cool];
        let scale = vfs_activity_scale(&entries);

        assert_eq!(scale, 100.0);
        assert_eq!(
            vfs_bar_segments(75.0, 25.0, scale, 4),
            VfsBarSegments {
                read: 3,
                mixed: 0,
                write: 1,
                empty: 0,
            }
        );
        assert_eq!(
            vfs_bar_segments(10.0, 10.0, scale, 4),
            VfsBarSegments {
                read: 0,
                mixed: 1,
                write: 0,
                empty: 3,
            }
        );
        assert_eq!(vfs_bar_segments(0.01, 0.01, scale, 4).mixed, 1);
        assert_eq!(
            vfs_bar_segments(0.0, 0.0, scale, 4),
            VfsBarSegments {
                read: 0,
                mixed: 0,
                write: 0,
                empty: 4,
            }
        );
    }

    #[test]
    fn vfs_entry_renders_stats_and_inode_above_the_full_width_path() {
        let mut item = hot_file(8, 1, 75.0, 25.0);
        item.path = "/mnt/data/a/deliberately-long-file-name.db".into();
        item.inode = 217_317_381;
        let backend = TestBackend::new(80, 2);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| draw_vfs_entry(frame, frame.area(), &item, 100.0))
            .expect("draw VFS entry");
        let buffer = terminal.backend().buffer();

        for x in 0..2 {
            let cell = buffer.cell((x, 0)).expect("read bar cell");
            assert_eq!(cell.symbol(), "█");
            assert_eq!(cell.fg, p::GREEN);
        }
        let write_cell = buffer.cell((2, 0)).expect("write bar cell");
        assert_eq!(write_cell.symbol(), "█");
        assert_eq!(write_cell.fg, p::CYAN);
        assert_eq!(buffer.cell((3, 0)).unwrap().symbol(), " ");
        assert_eq!(buffer.cell((4, 0)).unwrap().symbol(), "R");
        let line = |y| {
            (0..80)
                .map(|x| buffer.cell((x, y)).unwrap().symbol())
                .collect::<String>()
        };
        assert!(line(0).ends_with("inode 217317381"));
        assert!(line(1).starts_with("    /mnt/data/a/deliberately-long-file-name.db"));
    }

    #[test]
    fn vfs_path_starts_under_read_label_at_compact_and_wide_widths() {
        for (width, expected_x) in [(80, 4), (100, 8)] {
            let mut item = hot_file(8, 1, 75.0, 25.0);
            item.path = "/resolved/path".into();
            let backend = TestBackend::new(width, 2);
            let mut terminal = Terminal::new(backend).expect("terminal");
            terminal
                .draw(|frame| draw_vfs_entry(frame, frame.area(), &item, 100.0))
                .expect("draw VFS entry");
            let buffer = terminal.backend().buffer();

            assert_eq!(buffer.cell((expected_x, 0)).unwrap().symbol(), "R");
            assert_eq!(buffer.cell((expected_x, 1)).unwrap().symbol(), "/");
            assert!((0..expected_x).all(|x| buffer.cell((x, 1)).unwrap().symbol() == " "));
        }
    }

    #[test]
    fn vfs_entry_renders_unresolved_fallback_without_duplicate_inode() {
        let mut item = hot_file(8, 1, 75.0, 25.0);
        item.path = "data.bin [inode 42]".into();
        let backend = TestBackend::new(80, 2);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| draw_vfs_entry(frame, frame.area(), &item, 100.0))
            .expect("draw VFS entry");
        let buffer = terminal.backend().buffer();
        let row = (0..80)
            .map(|x| buffer.cell((x, 1)).unwrap().symbol())
            .collect::<String>();

        assert!(row.trim().starts_with("[unresolved] data.bin"));
        assert!(!row.contains("inode 42"));
    }

    #[test]
    fn vfs_entry_renders_one_cell_mixed_activity_in_both_colors() {
        let item = hot_file(8, 1, 10.0, 10.0);
        let backend = TestBackend::new(80, 2);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| draw_vfs_entry(frame, frame.area(), &item, 100.0))
            .expect("draw VFS entry");
        let cell = terminal.backend().buffer().cell((0, 0)).unwrap();

        assert_eq!(cell.symbol(), "▀");
        assert_eq!(cell.fg, p::GREEN);
        assert_eq!(cell.bg, p::CYAN);
    }

    #[test]
    fn compact_vfs_layout_preserves_inode_and_aligned_stats() {
        let (bar_width, rate_width, ops_width) = vfs_row_layout(58);

        assert_eq!((bar_width, rate_width, ops_width), (3, 8, 4));
        assert_eq!(vfs_stats_width(bar_width, rate_width, ops_width), 39);
        assert_eq!(vfs_row_layout(90), (7, 10, 5));
    }

    #[test]
    fn vfs_capacity_only_counts_complete_two_row_entries() {
        assert_eq!(vfs_entry_capacity(0), 0);
        assert_eq!(vfs_entry_capacity(1), 0);
        assert_eq!(vfs_entry_capacity(2), 1);
        assert_eq!(vfs_entry_capacity(5), 2);
    }

    #[test]
    fn vfs_rate_fields_keep_columns_fixed() {
        let rates = [
            38.0 * 1024.0 * 1024.0,
            6.6 * 1024.0 * 1024.0,
            575.0 * 1024.0,
        ];
        for rate in rates {
            assert_eq!(vfs_rate_field(rate, 10, false).chars().count(), 10);
            assert_eq!(vfs_rate_field(rate, 8, true).chars().count(), 8);
        }
        assert_eq!(vfs_rate_field(rates[1], 10, false), " 6.6 MiB/s");
        assert_eq!(vfs_rate_field(rates[1], 8, true), " 6.6Mi/s");
    }

    #[test]
    fn workload_adapter_keeps_directional_series_aligned() {
        let samples = VecDeque::from([WorkloadSample {
            read_iops: 2.0,
            write_iops: 5.0,
            read_bps: 2048.0,
            write_bps: 8192.0,
            read_request_bytes: Some(1024.0),
            write_request_bytes: Some(4096.0),
            merge_rates: MergeRates::Available {
                read_per_sec: 1.0,
                write_per_sec: 3.0,
            },
        }]);
        let view = workload_view(&samples);
        assert_eq!(view.iops, (vec![2.0], vec![5.0]));
        assert_eq!(view.throughput, (vec![2048.0], vec![8192.0]));
        assert_eq!(view.merges, Some((vec![1.0], vec![3.0])));
    }

    #[test]
    fn await_adapter_preserves_idle_ticks_and_directional_alignment() {
        let samples = VecDeque::from([
            AwaitSample {
                read_us: Some(250.0),
                write_us: None,
            },
            AwaitSample {
                read_us: None,
                write_us: Some(2_000.0),
            },
            AwaitSample::default(),
        ]);

        let view = await_view(&samples);

        assert_eq!(view.read, vec![250.0, 0.0, 0.0]);
        assert_eq!(view.write, vec![0.0, 2_000.0, 0.0]);
        assert_eq!(view.read.len(), samples.len());
        assert_eq!(view.write.len(), samples.len());
    }

    #[test]
    fn await_directional_graphs_share_one_scale() {
        let view = AwaitView {
            read: vec![100.0, 500.0],
            write: vec![1_000.0, 8_000.0],
        };

        assert_eq!(await_scale(&view), 8_000.0);
    }

    #[test]
    fn full_direction_detail_renders_await_after_existing_metrics() {
        let workload = WorkloadView {
            iops: (vec![1.0], vec![2.0]),
            throughput: (vec![1024.0], vec![2048.0]),
            request_size: (vec![Some(4096.0)], vec![Some(8192.0)]),
            merges: Some((vec![3.0], vec![4.0])),
        };
        let await_view = AwaitView {
            read: vec![500.0, 2_000.0],
            write: vec![1_000.0, 8_000.0],
        };
        let backend = TestBackend::new(64, DIRECTION_DETAIL_HEIGHT);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| {
                draw_direction_detail(
                    frame,
                    frame.area(),
                    IoLane::Read,
                    &[0; 7],
                    Some(&workload),
                    Some(&await_view),
                )
            })
            .expect("draw direction detail");
        let buffer = terminal.backend().buffer();
        let row = |y| {
            (0..26)
                .map(|x| buffer.cell((x, y)).unwrap().symbol())
                .collect::<String>()
        };

        let title = (0..64)
            .map(|x| buffer.cell((x, 0)).unwrap().symbol())
            .collect::<String>();
        assert!(title.contains("READ | 60s | n=0"));
        assert!(!title.contains("last 60s"));
        assert!(!title.contains("latency distribution"));
        assert!(row(8).contains("IOPS"));
        assert!(row(9).contains("Throughput"));
        assert!(row(10).contains("Request size"));
        assert!(row(11).contains("Merges/s"));
        assert!(row(12).contains("Await"));
        assert!(row(12).contains("2.0ms"));
    }

    #[test]
    fn workload_adapter_preserves_unavailable_merges() {
        let samples = VecDeque::from([WorkloadSample {
            merge_rates: MergeRates::Unavailable,
            ..WorkloadSample::default()
        }]);
        assert_eq!(workload_view(&samples).merges, None);
    }
}
