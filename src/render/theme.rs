use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, BorderType, Padding};

pub(super) const BORDER: Style = Style::new().fg(Color::DarkGray);
pub(super) const TITLE: Style = Style::new()
    .fg(Color::LightCyan)
    .add_modifier(Modifier::BOLD);
pub(super) const MUTED: Style = Style::new().fg(Color::DarkGray);
pub(super) const HINT: Style = Style::new().fg(Color::Gray);
pub(super) const FILTER: Style = Style::new().fg(Color::White).add_modifier(Modifier::BOLD);
pub(super) const KEY: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD);

pub(super) const TCP: Style = Style::new().fg(Color::LightCyan);
pub(super) const UDP: Style = Style::new().fg(Color::LightGreen);
pub(super) const OTHER: Style = Style::new().fg(Color::LightMagenta);
pub(super) const BAD: Style = Style::new().fg(Color::Red).add_modifier(Modifier::BOLD);

pub(super) const SELECTED: Style = Style::new()
    .fg(Color::Black)
    .bg(Color::Cyan)
    .add_modifier(Modifier::BOLD);

pub(super) const CLIENT: Style = Style::new().fg(Color::Indexed(180));
pub(super) const SERVER: Style = Style::new().fg(Color::Indexed(110));
pub(super) const FOLLOW: Style = Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD);

pub(super) const CAPTURING: Style = Style::new().fg(Color::Green).add_modifier(Modifier::BOLD);
pub(super) const PAUSED: Style = Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD);
pub(super) const ENDED: Style = Style::new().fg(Color::Red).add_modifier(Modifier::BOLD);

pub(super) fn panel(title: &str) -> Block<'static> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(BORDER)
        .padding(Padding::horizontal(1))
        .title(Span::styled(format!(" {title} "), TITLE))
}
