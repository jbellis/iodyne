use ratatui::layout::Rect;
use ratatui::Frame;

use crate::app::App;

pub mod devices;
pub mod fs;
pub mod insights;
pub mod io;
pub mod overview;
pub mod smart;
pub mod volumes;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TabId {
    Overview,
    Devices,
    Volumes,
    Fs,
    Io,
    Smart,
    Insights,
}

pub const ALL_TABS: &[TabId] = &[
    TabId::Overview,
    TabId::Devices,
    TabId::Volumes,
    TabId::Fs,
    TabId::Io,
    TabId::Smart,
    TabId::Insights,
];

impl TabId {
    pub fn label(&self) -> &'static str {
        match self {
            TabId::Overview => "Overview",
            TabId::Devices => "Devices",
            TabId::Volumes => "Volumes",
            TabId::Fs => "FS",
            TabId::Io => "IO",
            TabId::Smart => "SMART",
            TabId::Insights => "Insights",
        }
    }

    pub fn number(&self) -> usize {
        ALL_TABS.iter().position(|t| t == self).unwrap() + 1
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "overview" => Some(TabId::Overview),
            "devices" => Some(TabId::Devices),
            "volumes" => Some(TabId::Volumes),
            "fs" | "filesystems" => Some(TabId::Fs),
            "io" => Some(TabId::Io),
            "smart" => Some(TabId::Smart),
            "insights" => Some(TabId::Insights),
            _ => None,
        }
    }
}

pub fn draw(f: &mut Frame, area: Rect, app: &App) {
    match app.active_tab {
        TabId::Overview => overview::draw(f, area, app),
        TabId::Devices => devices::draw(f, area, app),
        TabId::Volumes => volumes::draw(f, area, app),
        TabId::Fs => fs::draw(f, area, app),
        TabId::Io => io::draw(f, area, app),
        TabId::Smart => smart::draw(f, area, app),
        TabId::Insights => insights::draw(f, area, app),
    }
}

#[cfg(test)]
mod tests {
    use super::{TabId, ALL_TABS};

    #[test]
    fn exposes_seven_numbered_tabs() {
        assert_eq!(ALL_TABS.len(), 7);
        assert_eq!(TabId::Insights.number(), 7);
    }

    #[test]
    fn removed_hot_files_tab_does_not_parse() {
        assert_eq!(TabId::from_str("hot"), None);
        assert_eq!(TabId::from_str("hotfiles"), None);
        assert_eq!(TabId::from_str("insights"), Some(TabId::Insights));
    }
}
