use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::ui::palette as p;

pub fn draw_footer(f: &mut Frame, area: Rect, show_unmounted: bool, collection_source: &str) {
    let mut spans: Vec<Span> = Vec::new();
    spans.push(Span::raw(" "));
    let groups: &[&[(&str, &str)]] = &[
        &[("p", "Pause"), (",", "Settings")],
        &[("j/k", "Select")],
        &[("-/+", "Sample"), ("q", "Quit")],
    ];
    for (gi, group) in groups.iter().enumerate() {
        if gi > 0 {
            spans.push(Span::styled(" \u{2502} ", Style::default().fg(p::FAINT)));
        }
        if gi == 1 {
            spans.push(Span::styled(
                "u",
                Style::default().fg(p::CYAN).add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled(":", Style::default().fg(p::DIM)));
            for (label, active) in [
                ("mounted", !show_unmounted),
                ("/", false),
                ("all", show_unmounted),
            ] {
                let style = if active {
                    Style::default()
                        .fg(p::BR_WHITE)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(p::DIM)
                };
                spans.push(Span::styled(label, style));
            }
            spans.push(Span::raw(" "));
        }
        for (key, label) in group.iter() {
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
    let source_width = collection_source
        .chars()
        .count()
        .saturating_add(2)
        .min(text_area.width as usize) as u16;
    let source_area = Rect {
        x: text_area.right().saturating_sub(source_width),
        width: source_width,
        ..text_area
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw(" "),
            Span::styled(
                collection_source.to_string(),
                Style::default()
                    .fg(p::BR_WHITE)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
        ]))
        .style(Style::default().bg(p::BG)),
        source_area,
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
            .draw(|frame| draw_footer(frame, frame.area(), false, "PER-REQUEST eBPF"))
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

    #[test]
    fn footer_highlights_only_the_active_device_filter_with_foreground() {
        for (show_unmounted, active, inactive) in
            [(false, "mounted", "all"), (true, "all", "mounted")]
        {
            let backend = TestBackend::new(100, 2);
            let mut terminal = Terminal::new(backend).expect("terminal");
            terminal
                .draw(|frame| draw_footer(frame, frame.area(), show_unmounted, "PER-REQUEST eBPF"))
                .expect("draw footer");
            let buffer = terminal.backend().buffer();
            let text = (0..100)
                .map(|x| buffer.cell((x, 1)).unwrap().symbol())
                .collect::<String>();
            let active_x = text.find(active).expect("active filter label") as u16;
            let inactive_x = text.find(inactive).expect("inactive filter label") as u16;

            assert_eq!(buffer.cell((active_x, 1)).unwrap().fg, p::BR_WHITE);
            assert_eq!(buffer.cell((inactive_x, 1)).unwrap().fg, p::DIM);
            assert_eq!(buffer.cell((active_x, 1)).unwrap().bg, p::BG);
            assert_eq!(buffer.cell((inactive_x, 1)).unwrap().bg, p::BG);
        }
    }
}
