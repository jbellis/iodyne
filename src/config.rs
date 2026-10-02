use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ui::format::UnitMode;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopView {
    #[default]
    Volumes,
    Devices,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub unit_mode: UnitMode,
    pub io_show_unmounted: bool,
    pub top_view: TopView,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            unit_mode: UnitMode::Binary,
            io_show_unmounted: false,
            top_view: TopView::Volumes,
        }
    }
}

impl Settings {
    pub fn load() -> Self {
        let Some(path) = config_path() else {
            return Self::default();
        };
        let Ok(text) = std::fs::read_to_string(path) else {
            return Self::default();
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    #[cfg_attr(test, allow(dead_code))]
    pub fn save(&self) {
        let Some(path) = config_path() else {
            return;
        };
        let Some(parent) = path.parent() else {
            return;
        };
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
        let Ok(text) = serde_json::to_string_pretty(self) else {
            return;
        };
        let _ = std::fs::write(path, text);
    }
}

pub fn config_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("iodyne/config.json"));
    }
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join(".config")
            .join("iodyne")
            .join("config.json")
    })
}

#[cfg(test)]
mod tests {
    use super::{Settings, TopView};

    #[test]
    fn existing_settings_default_to_volumes_and_top_view_round_trips() {
        let existing: Settings = serde_json::from_str(r#"{"io_show_unmounted":true}"#)
            .expect("existing settings deserialize");
        assert_eq!(existing.top_view, TopView::Volumes);
        assert!(existing.io_show_unmounted);

        let devices = Settings {
            top_view: TopView::Devices,
            ..Settings::default()
        };
        let serialized = serde_json::to_string(&devices).expect("settings serialize");
        let restored: Settings = serde_json::from_str(&serialized).expect("settings deserialize");
        assert_eq!(restored.top_view, TopView::Devices);
    }
}
