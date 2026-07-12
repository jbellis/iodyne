use chrono::Local;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::{HostInfo, LiveState};
use crate::ui::palette as p;

pub fn draw_header(f: &mut Frame, area: Rect, host: &HostInfo, live: LiveState) {
    let mut left: Vec<Span> = Vec::new();
    left.push(Span::styled(" \u{25cf}", Style::default().fg(p::GREEN)));
    left.push(Span::styled(
        " DiskWatch",
        Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
    ));
    left.push(Span::styled(
        format!(" v{}", env!("CARGO_PKG_VERSION")),
        Style::default().fg(p::DIM),
    ));
    left.push(Span::styled("  \u{2502}  ", Style::default().fg(p::FAINT)));
    left.push(Span::styled("host ", Style::default().fg(p::DIM)));
    left.push(Span::styled(
        host.hostname.clone(),
        Style::default().fg(p::FG),
    ));
    left.push(Span::styled("  ", Style::default().fg(p::DIM)));
    left.push(Span::styled(host.os.clone(), Style::default().fg(p::FG)));
    left.push(Span::styled("  up ", Style::default().fg(p::DIM)));
    left.push(Span::styled(
        format_uptime(host.uptime_secs),
        Style::default().fg(p::FG),
    ));
    left.push(Span::styled("  ", Style::default().fg(p::DIM)));
    left.push(Span::styled(
        format!("{} devs", host.device_count),
        Style::default().fg(p::FG),
    ));
    left.push(Span::styled(" attached", Style::default().fg(p::DIM)));

    let (label, color) = match live {
        LiveState::Live => ("LIVE", p::GREEN),
        LiveState::Paused => ("PAUSE", p::YELLOW),
    };
    let ts = Local::now().format("%H:%M:%S").to_string();
    let right_text = format!("\u{25cf} {}  {}", label, ts);
    let right_w = right_text.chars().count() as u16 + 1;
    let right = vec![Span::styled(
        right_text,
        Style::default().fg(color).add_modifier(Modifier::BOLD),
    )];

    let left_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width.saturating_sub(right_w),
        height: 1,
    };
    let right_area = Rect {
        x: area.x + area.width.saturating_sub(right_w),
        y: area.y,
        width: right_w,
        height: 1,
    };

    f.render_widget(
        Paragraph::new(Line::from(left)).style(Style::default().bg(p::BG).fg(p::FG)),
        left_area,
    );
    f.render_widget(
        Paragraph::new(Line::from(right)).style(Style::default().bg(p::BG)),
        right_area,
    );
}

pub fn draw_footer(f: &mut Frame, area: Rect) {
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::raw(" "));
    let groups: &[&[(char, &str)]] = &[
        &[('p', "Pause"), (',', "Settings")],
        &[('u', "mounted/all"), ('j', "Select")],
        &[('q', "Quit")],
    ];
    for (gi, g) in groups.iter().enumerate() {
        if gi > 0 {
            spans.push(Span::styled(" \u{2502} ", Style::default().fg(p::FAINT)));
        }
        for (k, label) in g.iter() {
            spans.push(Span::styled(
                if *k == 'j' {
                    "j/k".into()
                } else {
                    k.to_string()
                },
                Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(
                format!(":{} ", label),
                Style::default().fg(p::DIM),
            ));
        }
    }
    // Divider row above the footer text.
    let divider_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: 1,
    };
    let text_area = Rect {
        x: area.x,
        y: area.y + 1,
        width: area.width,
        height: 1,
    };
    let divider: String = "\u{2500}".repeat(area.width as usize);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            divider,
            Style::default().fg(p::FAINT).bg(p::BG),
        ))),
        divider_area,
    );
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(p::BG)),
        text_area,
    );
}

fn format_uptime(secs: u64) -> String {
    let d = secs / 86_400;
    let h = (secs % 86_400) / 3600;
    let m = (secs % 3600) / 60;
    if d > 0 {
        format!("{}d {:02}:{:02}", d, h, m)
    } else {
        format!("{:02}:{:02}", h, m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn footer_names_only_implemented_commands() {
        let backend = TestBackend::new(100, 2);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| draw_footer(frame, frame.area()))
            .expect("draw footer");
        let buffer = terminal.backend().buffer();
        let text = (0..100)
            .map(|x| buffer.cell((x, 1)).unwrap().symbol())
            .collect::<String>();

        for expected in [
            "p:Pause",
            ",:Settings",
            "u:mounted/all",
            "j/k:Select",
            "q:Quit",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text:?}");
        }
        let stale = [
            ["Snap", "shot"].concat(),
            ["Di", "ff"].concat(),
            ["Pro", "file"].concat(),
            ["R", "ec"].concat(),
            ["Fil", "ter"].concat(),
            ["T", "ab"].concat(),
            format!("{}-{}", 1, 9),
        ];
        for stale in stale {
            assert!(!text.contains(&stale), "stale {stale:?} in {text:?}");
        }
    }
}
