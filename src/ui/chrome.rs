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
        &[("j/k", "Select"), ("Tab", "Detail")],
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
    let text_area = area;
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
