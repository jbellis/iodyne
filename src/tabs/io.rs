//! Per-device IO overview.
//!
//! Every device uses the same fixed logarithmic latency scale, split into
//! read and write lanes. The selected device drives a compact histogram and
//! aligned workload graphs.

use std::collections::{HashSet, VecDeque};
use std::ops::Range;

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
use crate::collect::{
    AwaitSample, FsTick, IoTick, MergeRates, TracedLatencySample, WorkloadSample,
};
use crate::ui::format::{fmt_rate, unit_mode, UnitMode};
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
const WIDE_DETAIL_HEIGHT: u16 = 26;
const WIDE_DETAIL_BODY_HEIGHT: u16 = WIDE_DETAIL_HEIGHT - 1;
const COMPACT_DETAIL_HEIGHT: u16 = 19;
const DIRECTION_DETAIL_HEIGHT: u16 = 13;

pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    if app.io.latest.is_empty() {
        draw_empty(f, area);
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(area);

    draw_summary_line(f, rows[0], app);
    draw_scale_legend(f, rows[1], app.io.latency_source());
    draw_master_detail(f, rows[2], app);
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
    let source = match app.io.latency_source() {
        LatencySource::AggregateAwait => "AGGREGATE AWAIT",
        LatencySource::EbpfPerRequest => "PER-REQUEST eBPF",
    };
    let mut spans = vec![
        Span::raw(" "),
        Span::styled(
            source,
            Style::default()
                .fg(p::BR_WHITE)
                .add_modifier(Modifier::BOLD),
        ),
    ];
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
    spans.push(Span::styled(
        "   j/k selects detail",
        Style::default().fg(p::DIM),
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
            Constraint::Length((detail_height > 0) as u16),
            Constraint::Length(detail_height),
            Constraint::Min(0),
        ])
        .split(area);
    let selected = app.selected_io.min(visible.len() - 1);
    let throughput_scale = overview_throughput_scale(&visible, app);
    let (start, count, _) = visible_band_window(sections[0].height, visible.len(), selected);
    for (slot, tick) in visible.iter().skip(start).take(count).enumerate() {
        draw_overview_row(
            f,
            Rect {
                x: sections[0].x,
                y: sections[0].y + slot as u16,
                width: sections[0].width,
                height: 1,
            },
            tick,
            app,
            start + slot == selected,
            throughput_scale,
        );
    }
    draw_detail(f, sections[2], visible[selected], app);
}

fn visible_band_window(height: u16, total: usize, selected: usize) -> (usize, usize, usize) {
    if total == 0 {
        return (0, 0, 0);
    }
    let slots = (height.max(1) as usize).min(total);
    let selected = selected.min(total - 1);
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
            app.io_show_unmounted || io_device_is_mounted(&tick.device, &app.filesystems)
        })
        .collect()
}

pub(crate) fn visible_device_count(app: &App) -> usize {
    visible_io_ticks(app).len()
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

fn draw_scale_legend(f: &mut Frame, area: Rect, source: LatencySource) {
    if area.height == 0 {
        return;
    }
    let geometry = row_geometry(area.width);
    let mode = match source {
        LatencySource::AggregateAwait => "◆ peak",
        LatencySource::EbpfPerRequest => "◆ p99",
    };
    let mut line = vec![Span::styled(
        format!(
            " {mode:<width$}",
            width = geometry.label.saturating_sub(1) as usize
        ),
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
    fullness: u16,
    throughput: u16,
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
    let (device, fullness) = if width >= 24 {
        (10, 4)
    } else if width >= 16 {
        (7, 4)
    } else if width >= 10 {
        (width.saturating_sub(8), 4)
    } else {
        (width.saturating_sub(1), 0)
    };
    let fixed = 1 + device + (fullness > 0) as u16 * (1 + fullness + 1);
    OverviewPrefixGeometry {
        device,
        fullness,
        throughput: width.saturating_sub(fixed),
    }
}

fn row_geometry(width: u16) -> RowGeometry {
    let label = if width >= 100 {
        30
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
    if height <= 2 {
        return (height, 0);
    }
    let detail_reserve = if height >= 32 {
        WIDE_DETAIL_HEIGHT
    } else if height >= 24 {
        COMPACT_DETAIL_HEIGHT
    } else {
        height.saturating_sub(6).min(WIDE_DETAIL_HEIGHT)
    };
    let max_overview = height.saturating_sub(detail_reserve + 1).max(1);
    let devices = device_count.max(1).min(u16::MAX as usize) as u16;
    let overview = devices.min(max_overview);
    (
        overview,
        detail_reserve.min(height.saturating_sub(overview + 1)),
    )
}

fn draw_overview_row(
    f: &mut Frame,
    area: Rect,
    tick: &IoTick,
    app: &App,
    selected: bool,
    throughput_scale: f64,
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
    draw_overview_prefix(
        f,
        Rect {
            width: g.label,
            ..area
        },
        &tick.device,
        filesystem_fullness_pct(&tick.device, &app.filesystems),
        &throughput,
        throughput_scale,
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
    fullness: Option<u32>,
    throughput: &[f64],
    throughput_scale: f64,
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
    if geometry.fullness > 0 {
        spans.push(Span::styled(
            format!(
                " {:>width$} ",
                format_fullness(fullness),
                width = geometry.fullness as usize
            ),
            Style::default().fg(p::DIM),
        ));
    }
    let text_width = area.width.saturating_sub(geometry.throughput);
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

fn format_fullness(fullness: Option<u32>) -> String {
    fullness
        .map(|percent| format!("{}%", percent.min(100)))
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
    let header = detail_header(&tick.device, &app.filesystems);
    f.render_widget(
        Paragraph::new(Span::styled(
            header,
            Style::default()
                .fg(p::BR_WHITE)
                .add_modifier(Modifier::BOLD),
        )),
        Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: 1,
        },
    );
    if area.height <= 1 {
        return;
    }
    let body = Rect {
        y: area.y + 1,
        height: area.height - 1,
        ..area
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
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                format!(" {name}"),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!(" · last 60s · latency distribution · {total}"),
                Style::default().fg(p::DIM),
            ),
        ])),
        Rect { height: 1, ..area },
    );
    let label_width = 11.min(area.width);
    for band in 0..7.min(area.height.saturating_sub(1) as usize) {
        let y = area.y + 1 + band as u16;
        f.render_widget(
            Paragraph::new(Span::styled(
                format!(" {:<10}", HEAT_LABELS[band]),
                Style::default().fg(p::DIM),
            )),
            Rect {
                x: area.x,
                y,
                width: label_width,
                height: 1,
            },
        );
        draw_histogram_lane(
            f,
            Rect {
                x: area.x + label_width,
                y,
                width: area.width.saturating_sub(label_width),
                height: 1,
            },
            histogram[band],
            total,
            color,
        );
    }

    if area.height <= 8 {
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
            y: area.y + 8,
            height: area.height - 8,
            ..area
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

fn shared_throughput_scale<'a>(series: impl IntoIterator<Item = &'a [f64]>) -> f64 {
    series
        .into_iter()
        .flatten()
        .copied()
        .filter(|value| value.is_finite())
        .fold(0.0_f64, f64::max)
        .max(1.0)
}

fn overview_throughput_scale(visible: &[&IoTick], app: &App) -> f64 {
    let series: Vec<Vec<f64>> = visible
        .iter()
        .map(|tick| {
            app.io
                .history
                .get(&tick.device)
                .map(|history| combined_throughput(&history.workload_samples))
                .unwrap_or_default()
        })
        .collect();
    shared_throughput_scale(series.iter().map(Vec::as_slice))
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
    let data_rows = area.height.saturating_sub(1);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(
                " VFS activity · rolling 10s",
                Style::default()
                    .fg(p::BR_WHITE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" · requested rates · ops/s", Style::default().fg(p::DIM)),
            if data_rows == 0 {
                Span::styled(" · need 2 data rows", Style::default().fg(p::DIM))
            } else {
                Span::raw("")
            },
        ])),
        Rect { height: 1, ..area },
    );
    if area.height <= 1 {
        return;
    }
    if vfs_entry_capacity(data_rows) == 0 {
        draw_vfs_status(f, area, "need 2 rows to show VFS activity");
        return;
    }

    if app.io.hot_files_source() != VfsActivitySource::EbpfRequestedBytes {
        draw_vfs_status(f, area, vfs_unavailable_message(app.io.hot_files_status()));
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
        draw_vfs_status(f, area, status);
        return;
    }

    let capacity = vfs_entry_capacity(data_rows);
    let visible: Vec<_> = entries.into_iter().take(capacity).collect();
    let scale = vfs_activity_scale(&visible);
    for (row, item) in visible.into_iter().enumerate() {
        draw_vfs_entry(
            f,
            Rect {
                x: area.x,
                y: area.y + 1 + row as u16 * 2,
                width: area.width,
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
            y: area.y + 1,
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

    let path_width = area.width.saturating_sub(2) as usize;
    f.render_widget(
        Paragraph::new(Span::styled(
            format!("  {}", truncate_text(&path, path_width)),
            Style::default().fg(p::DIM),
        )),
        Rect {
            y: area.y + 1,
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

fn vfs_display_path(item: &VfsFileActivity) -> String {
    if !item.path.is_empty() {
        item.path.clone()
    } else if !item.basename.is_empty() {
        item.basename.clone()
    } else {
        format!("inode {}", item.inode)
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

fn filesystem_fullness_pct(device: &str, filesystems: &[FsTick]) -> Option<u32> {
    filesystems_for_io_device(device, filesystems)
        .into_iter()
        .filter(|fs| fs.size_bytes > 0)
        .map(|fs| {
            (fs.used_bytes as f64 / fs.size_bytes as f64 * 100.0)
                .round()
                .clamp(0.0, 100.0) as u32
        })
        .max()
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

fn detail_header(device: &str, filesystems: &[FsTick]) -> String {
    let mounts = mounts_for_device(device, filesystems).unwrap_or_else(|| "[unmounted]".into());
    format!(" {device} detail · {mounts}")
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
    fn vfs_paths_fall_back_to_basename_then_inode() {
        let mut item = hot_file(8, 1, 1.0, 0.0);
        item.path.clear();
        assert_eq!(vfs_display_path(&item), "data.bin");
        item.basename.clear();
        assert_eq!(vfs_display_path(&item), "inode 42");
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
    fn fullness_uses_maximum_attributable_mounted_filesystem() {
        let filesystems = vec![
            fs_usage("/dev/sda1", "/", 40, 100),
            fs_usage("/dev/sda2", "/home", 85, 100),
            fs_usage("/dev/sda3", "/unknown", 1, 0),
            fs_usage("/dev/sdb1", "/other", 99, 100),
        ];

        assert_eq!(filesystem_fullness_pct("sda", &filesystems), Some(85));
        assert_eq!(filesystem_fullness_pct("sdb", &filesystems), Some(99));
        assert_eq!(filesystem_fullness_pct("sdc", &filesystems), None);
    }

    #[test]
    fn detail_header_moves_mount_attribution_and_has_factual_fallback() {
        let filesystems = vec![fs("/dev/sda1", "/"), fs("/dev/sda2", "/home")];

        assert_eq!(detail_header("sda", &filesystems), " sda detail · /, /home");
        assert_eq!(
            detail_header("sdb", &filesystems),
            " sdb detail · [unmounted]"
        );
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
        assert_eq!(visible_band_window(0, 0, 0), (0, 0, 0));
    }

    #[test]
    fn compact_layout_reserves_exactly_one_separator_row() {
        assert_eq!(master_detail_heights(28, 30), (8, 19));
        assert_eq!(master_detail_heights(28, 8), (8, 19));
        assert_eq!(master_detail_heights(8, 8), (5, 2));
        assert_eq!(master_detail_heights(1, 8), (1, 0));
        let (overview, detail) = master_detail_heights(28, 8);
        assert!(overview + 1 + detail <= 28);
        assert_eq!(row_geometry(60).label + row_geometry(60).plot, 60);
        assert_eq!(row_geometry(130).label.saturating_sub(1), 29);
        assert_eq!(row_geometry(130).plot, 100);
    }

    #[test]
    fn overview_throughput_combines_directions_and_shares_visible_scale() {
        let slow = VecDeque::from([WorkloadSample {
            read_bps: 10.0,
            write_bps: 20.0,
            ..WorkloadSample::default()
        }]);
        let fast = VecDeque::from([WorkloadSample {
            read_bps: 100.0,
            write_bps: 300.0,
            ..WorkloadSample::default()
        }]);
        let slow = combined_throughput(&slow);
        let fast = combined_throughput(&fast);

        assert_eq!(slow, vec![30.0]);
        assert_eq!(fast, vec![400.0]);
        assert_eq!(
            shared_throughput_scale([slow.as_slice(), fast.as_slice()]),
            400.0
        );
    }

    #[test]
    fn narrow_overview_prefix_keeps_fullness_and_throughput_before_latency() {
        let width = 60;
        let geometry = row_geometry(width);
        assert_eq!(geometry.label, 13);
        assert_eq!(overview_prefix_geometry(geometry.label).throughput, 1);
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

        assert!(line.starts_with("▌nvme~  85% "));
        assert_ne!(buffer.cell((geometry.label - 1, 0)).unwrap().symbol(), " ");
        assert_eq!(buffer.cell((geometry.label, 0)).unwrap().symbol(), "R");
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
        assert_eq!((read.height, write.height), (13, 13));
        assert_eq!((read.width, write.width), (64, 65));
        assert_eq!(write.x, read.x + read.width + 1);
        assert_eq!(vfs.width, 130);
        assert_eq!(vfs.height, 4);
        assert_eq!(vfs.y, 14);

        let tall = Rect::new(0, 0, 130, 70);
        let (read, write, vfs) = detail_areas(tall);
        assert_eq!((read.height, write.height), (13, 13));
        assert_eq!((vfs.y, vfs.height), (14, 11));
        assert_eq!(vfs_entry_capacity(vfs.height.saturating_sub(1)), 5);
        assert_eq!(vfs.y + vfs.height, WIDE_DETAIL_BODY_HEIGHT);

        let (overview, detail) = master_detail_heights(68, 5);
        assert_eq!((overview, detail), (5, WIDE_DETAIL_HEIGHT));
        assert_eq!(overview + 1 + detail, 32);

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
        assert!(line(1).starts_with("  /mnt/data/a/deliberately-long-file-name.db"));
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
