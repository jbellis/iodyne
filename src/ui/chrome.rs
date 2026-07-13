use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::ui::palette as p;

pub fn draw_footer(f: &mut Frame, area: Rect) {
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::raw(" "));
    let groups: &[&[(&str, &str)]] = &[
        &[("p", "Pause"), (",", "Settings")],
        &[("u", "mounted/all"), ("j/k", "Select")],
        &[("-/+", "Sample"), ("q", "Quit")],
    ];
    for (gi, g) in groups.iter().enumerate() {
        if gi > 0 {
            spans.push(Span::styled(" \u{2502} ", Style::default().fg(p::FAINT)));
        }
        for (key, label) in g.iter() {
            spans.push(Span::styled(
                *key,
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
            "-/+:Sample",
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
