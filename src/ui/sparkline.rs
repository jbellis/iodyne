//! Custom baseline-aware sparkline rendered with braille cells.
//!
//! Differences from `ratatui::widgets::Sparkline`:
//! 1. **High resolution.** Each terminal cell carries a 2x4 braille dot
//!    grid, giving smoother graphs without increasing layout size.
//! 2. **Visible baseline.** Cells without data, and zero-valued cells,
//!    keep a bottom-row dot so the chart is visually grounded.
//! 3. **Right-anchored.** Newest sample is at the right edge. If the
//!    sample series is shorter than the area, the leading cells show
//!    the baseline; once the ring fills, samples scroll left as
//!    expected.

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
        // How many leading dot-columns lack real data — baseline-fill them.
        let leading = dot_w.saturating_sub(n);
        // Slice the rightmost `dot_w` samples from the data.
        let start = n.saturating_sub(dot_w);
        let visible = &self.samples[start..];

        let max = match self.max {
            Some(m) if m > 0.0 => m,
            _ => visible.iter().cloned().fold(0.0_f64, f64::max).max(1.0),
        };

        let mut dots = vec![0_u8; w * area.height as usize];

        for x in 0..dot_w {
            let value = if x < leading {
                0.0
            } else {
                visible[x - leading]
            };
            let normalized = (value / max).clamp(0.0, 1.0);
            let filled = (normalized * dot_h as f64).round() as usize;
            let filled = filled.max(1).min(dot_h);

            for y_from_bottom in 0..filled {
                let dot_y = dot_h - 1 - y_from_bottom;
                let cell_x = x / 2;
                let dot_x = x % 2;
                let cell_y = dot_y / 4;
                let dot_row = dot_y % 4;
                let idx = cell_y * w + cell_x;
                dots[idx] |= BRAILLE_DOTS[dot_x][dot_row];
            }
        }

        for cell_y in 0..area.height as usize {
            for cell_x in 0..w {
                let mask = dots[cell_y * w + cell_x];
                let ch = char::from_u32(BRAILLE_BASE + mask as u32).unwrap_or('\u{2800}');
                let cx = area.x + cell_x as u16;
                let cy = area.y + cell_y as u16;
                if let Some(cell) = buf.cell_mut((cx, cy)) {
                    cell.set_char(ch).set_fg(self.fg).set_bg(self.bg);
                }
            }
        }
    }
}
