//! Custom baseline-aware sparkline.
//!
//! Differences from `ratatui::widgets::Sparkline`:
//! 1. **Fixed cell width.** One sample = one terminal cell, always.
//!    No stretching, no padding-induced visual breathing.
//! 2. **Visible baseline.** Cells without data, and zero-valued cells,
//!    render as `▁` so the chart fills its area from frame zero.
//! 3. **Right-anchored.** Newest sample is at the right edge. If the
//!    sample series is shorter than the area, the leading cells show
//!    the baseline; once the ring fills, samples scroll left as
//!    expected.

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::Widget;

const BLOCKS: [char; 8] = ['\u{2581}', '\u{2582}', '\u{2583}', '\u{2584}', '\u{2585}', '\u{2586}', '\u{2587}', '\u{2588}'];

pub struct BaselineSparkline<'a> {
    samples: &'a [f64],
    fg: Color,
    bg: Color,
    /// Optional explicit max. When `None` we auto-scale to the largest
    /// value in the visible window.
    max: Option<f64>,
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

    #[allow(dead_code)]
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
        let h = area.height as usize;
        let n = self.samples.len();
        // How many leading cells lack real data — baseline-fill them.
        let leading = w.saturating_sub(n);
        // Slice the rightmost `w` samples from the data.
        let start = n.saturating_sub(w);
        let visible = &self.samples[start..];

        let max = match self.max {
            Some(m) if m > 0.0 => m,
            _ => visible
                .iter()
                .cloned()
                .fold(0.0_f64, f64::max)
                .max(1.0),
        };

        for x in 0..w {
            let value = if x < leading {
                0.0
            } else {
                visible[x - leading]
            };
            let normalized = (value / max).clamp(0.0, 1.0);
            let total_subcells = (normalized * (h as f64) * 8.0).round() as usize;
            let full_cells = total_subcells / 8;
            let partial = total_subcells % 8;

            for row in 0..h {
                let from_bottom = h - 1 - row;
                let ch = if from_bottom < full_cells {
                    '\u{2588}' // full block
                } else if from_bottom == full_cells && partial > 0 {
                    BLOCKS[partial - 1]
                } else if from_bottom == 0 {
                    // Always draw a baseline at the bottom row so the
                    // chart is visually grounded even for zero values.
                    BLOCKS[0]
                } else {
                    ' '
                };
                let cx = area.x + x as u16;
                let cy = area.y + row as u16;
                if let Some(cell) = buf.cell_mut((cx, cy)) {
                    cell.set_char(ch).set_fg(self.fg).set_bg(self.bg);
                }
            }
        }
    }
}
