//! Color palette matching `source/tui/grid.jsx` constant `C`.
//! Hex values byte-identical to the design handoff so JSX mockups and
//! the real terminal render the same.

#![allow(dead_code)]

use ratatui::style::Color;

pub const BG: Color = Color::Rgb(0x0c, 0x14, 0x18);
pub const FG: Color = Color::Rgb(0xc5, 0xd1, 0xd6);
pub const DIM: Color = Color::Rgb(0x6b, 0x80, 0x88);
pub const FAINT: Color = Color::Rgb(0x44, 0x56, 0x60);

pub const RED: Color = Color::Rgb(0xff, 0x78, 0x78);
pub const GREEN: Color = Color::Rgb(0x5c, 0xd9, 0x89);
pub const YELLOW: Color = Color::Rgb(0xf0, 0xc0, 0x60);
pub const CYAN: Color = Color::Rgb(0x5f, 0xdc, 0xff);
pub const MAGENTA: Color = Color::Rgb(0xd9, 0x7a, 0xff);
pub const WHITE: Color = Color::Rgb(0xe6, 0xf0, 0xf2);

pub const BR_GREEN: Color = Color::Rgb(0x9a, 0xe6, 0xb4);
pub const BR_CYAN: Color = Color::Rgb(0x86, 0xe6, 0xff);
pub const BR_WHITE: Color = Color::Rgb(0xff, 0xff, 0xff);

pub const SEL_BG: Color = Color::Rgb(0x1a, 0x33, 0x40);
pub const WARN_BG: Color = Color::Rgb(0x3a, 0x2c, 0x14);
pub const ERR_BG: Color = Color::Rgb(0x3a, 0x1c, 0x1c);
pub const OK_BG: Color = Color::Rgb(0x16, 0x32, 0x1f);
