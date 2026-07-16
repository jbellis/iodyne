//! Custom baseline-aware sparkline rendered with braille cells.
//!
//! Differences from `ratatui::widgets::Sparkline`:
//! 1. **High resolution.** Each terminal cell carries a 2x4 braille dot
//!    grid, giving smoother graphs without increasing layout size.
//! 2. **Quiet baseline.** Sampled zeroes keep a dim bottom-row dot, while
//!    columns without data remain blank.
//! 3. **Right-anchored.** Newest sample is at the right edge. If the
//!    sample series is shorter than the area, the leading cells remain
//!    blank; once the ring fills, samples scroll left as expected.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::Widget;

const BRAILLE_BASE: u32 = 0x2800;
const BRAILLE_DOTS: [[u8; 4]; 2] = [
    [0x01, 0x02, 0x04, 0x40], // left column: dots 1,2,3,7
    [0x08, 0x10, 0x20, 0x80], // right column: dots 4,5,6,8
];

pub struct BaselineSparkline<'a> {
    samples: &'a [f64],
    fg: Color,
    bg: Color,
    /// Optional explicit max. When `None` we auto-scale to the largest
    /// value in the visible window.
    max: Option<f64>,
}

/// Render a one-row sparkline into text for places such as block titles that
/// accept styled spans rather than widgets. This intentionally uses the same
/// braille renderer as the throughput and IOPS graphs.
pub fn sparkline_symbols(samples: &[f64], width: u16, max: f64) -> String {
    if width == 0 {
        return String::new();
    }
    let area = Rect::new(0, 0, width, 1);
    let mut buffer = Buffer::empty(area);
    BaselineSparkline::new(samples)
        .max(max)
        .render(area, &mut buffer);
    (0..width)
        .map(|x| buffer.cell((x, 0)).map_or(" ", |cell| cell.symbol()))
        .collect()
}

impl<'a> BaselineSparkline<'a> {
    pub fn new(samples: &'a [f64]) -> Self {
        Self {
            samples,
            fg: Color::Reset,
            bg: Color::Reset,
            max: None,
        }
    }

    pub fn style(mut self, style: Style) -> Self {
        if let Some(fg) = style.fg {
            self.fg = fg;
        }
        if let Some(bg) = style.bg {
            self.bg = bg;
        }
        self
    }

    pub fn max(mut self, m: f64) -> Self {
        self.max = Some(m);
        self
    }
}

impl<'a> Widget for BaselineSparkline<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let w = area.width as usize;
        let dot_w = w * 2;
        let dot_h = area.height as usize * 4;
        let n = self.samples.len();
        // How many leading dot-columns lack real data.
        let leading = dot_w.saturating_sub(n);
        // Slice the rightmost `dot_w` samples from the data.
        let start = n.saturating_sub(dot_w);
        let visible = &self.samples[start..];

        let max = match self.max {
            Some(m) if m > 0.0 => m,
            _ => visible.iter().cloned().fold(0.0_f64, f64::max).max(1.0),
        };

        let mut dots = vec![0_u8; w * area.height as usize];
        let mut has_signal = vec![false; w * area.height as usize];

        for (visible_x, value) in visible.iter().copied().enumerate() {
            let x = leading + visible_x;
            let normalized = (value / max).clamp(0.0, 1.0);
            let filled = (normalized * dot_h as f64).round() as usize;
            // Every sampled value gets at least the bottom dot. Zeroes are
            // dim while small positive values use the metric color, preserving
            // activity without overstating its height on a shared scale.
            let filled = filled.max(1).min(dot_h);

            for y_from_bottom in 0..filled {
                let dot_y = dot_h - 1 - y_from_bottom;
                let cell_x = x / 2;
                let dot_x = x % 2;
                let cell_y = dot_y / 4;
                let dot_row = dot_y % 4;
                let idx = cell_y * w + cell_x;
                dots[idx] |= BRAILLE_DOTS[dot_x][dot_row];
                has_signal[idx] |= value > 0.0;
            }
        }

        for cell_y in 0..area.height as usize {
            for cell_x in 0..w {
                let mask = dots[cell_y * w + cell_x];
                let ch = if mask == 0 {
                    ' '
                } else {
                    char::from_u32(BRAILLE_BASE + mask as u32).unwrap_or(' ')
                };
                let cx = area.x + cell_x as u16;
                let cy = area.y + cell_y as u16;
                if let Some(cell) = buf.cell_mut((cx, cy)) {
                    let fg = if mask != 0 && !has_signal[cell_y * w + cell_x] {
                        Color::DarkGray
                    } else {
                        self.fg
                    };
                    cell.set_char(ch).set_fg(fg).set_bg(self.bg);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(samples: &[f64]) -> Buffer {
        let area = Rect::new(0, 0, 4, 1);
        let mut buf = Buffer::empty(area);
        BaselineSparkline::new(samples)
            .style(Style::default().fg(Color::Cyan))
            .render(area, &mut buf);
        buf
    }

    #[test]
    fn empty_series_renders_blank_cells() {
        let area = Rect::new(0, 0, 4, 1);
        let mut buf = Buffer::empty(area);
        buf.set_string(0, 0, "xxxx", Style::default().fg(Color::Red));
        BaselineSparkline::new(&[])
            .style(Style::default().fg(Color::Cyan))
            .render(area, &mut buf);

        for x in 0..4 {
            assert_eq!(buf.cell((x, 0)).unwrap().symbol(), " ");
        }
    }

    #[test]
    fn sampled_zeroes_are_dim_and_right_anchored() {
        let buf = render(&[0.0, 0.0]);

        for x in 0..3 {
            assert_eq!(buf.cell((x, 0)).unwrap().symbol(), " ");
        }
        let last = buf.cell((3, 0)).unwrap();
        assert_eq!(last.symbol(), "\u{28c0}");
        assert_eq!(last.fg, Color::DarkGray);
    }

    #[test]
    fn positive_samples_use_metric_color() {
        let buf = render(&[0.0, 1.0]);
        let last = buf.cell((3, 0)).unwrap();

        assert_ne!(last.symbol(), "\u{2800}");
        assert_eq!(last.fg, Color::Cyan);
    }

    #[test]
    fn positive_samples_below_shared_scale_use_the_colored_baseline() {
        let area = Rect::new(0, 0, 1, 1);
        let mut buffer = Buffer::empty(area);
        BaselineSparkline::new(&[0.0, 1.0])
            .max(100.0)
            .style(Style::default().fg(Color::Cyan))
            .render(area, &mut buffer);

        let cell = buffer.cell((0, 0)).unwrap();
        assert_eq!(cell.symbol(), "\u{28c0}");
        assert_eq!(cell.fg, Color::Cyan);
    }

    #[test]
    fn title_symbols_use_the_same_braille_renderer() {
        let samples = [0.0, 50.0, 100.0];
        let symbols = sparkline_symbols(&samples, 2, 100.0);
        let area = Rect::new(0, 0, 2, 1);
        let mut buffer = Buffer::empty(area);
        BaselineSparkline::new(&samples)
            .max(100.0)
            .render(area, &mut buffer);
        let rendered = (0..2)
            .map(|x| buffer.cell((x, 0)).unwrap().symbol())
            .collect::<String>();

        assert_eq!(symbols, rendered);
    }

    #[test]
    fn title_symbols_render_low_positive_percentages_as_one_dot() {
        assert_eq!(sparkline_symbols(&[3.0], 1, 100.0), "⢀");
    }
}
