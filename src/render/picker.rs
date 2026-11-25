use super::conversations::{Conversations, Key};
use super::text::human_bytes;
use super::theme::{self, panel};
use ratatui::Frame;
use ratatui::layout::{Constraint, Flex, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Clear, HighlightSpacing, List, ListState, Paragraph};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Picker {
    keys: Vec<Key>,
    selected: usize,
}

impl Picker {
    pub(super) fn open(conversations: &Conversations, current: Option<Key>) -> Self {
        let keys = conversations.recent();
        let selected = current
            .and_then(|current| keys.iter().position(|key| *key == current))
            .unwrap_or(0);
        Self { keys, selected }
    }

    pub(super) fn up(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub(super) fn down(&mut self) {
        if self.selected + 1 < self.keys.len() {
            self.selected += 1;
        }
    }

    pub(super) fn selected(&self) -> Option<Key> {
        self.keys.get(self.selected).copied()
    }

    pub(super) fn draw(&self, frame: &mut Frame, conversations: &Conversations) {
        let area = popup_area(frame.area(), self.keys.len());
        frame.render_widget(Clear, area);
        let block = panel("conversations");
        if self.keys.is_empty() {
            let empty = Line::styled("no conversations yet", theme::MUTED);
            frame.render_widget(Paragraph::new(empty).block(block), area);
            return;
        }
        let rows: Vec<Line> = self
            .keys
            .iter()
            .map(|key| row(key, conversations))
            .collect();
        let list = List::new(rows)
            .block(block)
            .highlight_style(theme::SELECTED)
            .highlight_symbol("▶ ")
            .highlight_spacing(HighlightSpacing::Always);
        let mut state = ListState::default().with_selected(Some(self.selected));
        frame.render_stateful_widget(list, area, &mut state);
    }
}

fn row(key: &Key, conversations: &Conversations) -> Line<'static> {
    let Some(conversation) = conversations.get(key) else {
        return Line::styled("(gone)", theme::MUTED);
    };
    Line::from(vec![
        Span::raw(format!("{} ", key.protocol_name())),
        Span::styled(conversation.client().to_string(), theme::CLIENT),
        Span::styled(" <> ", theme::MUTED),
        Span::styled(conversation.server().to_string(), theme::SERVER),
        Span::styled(
            format!(
                "  {} pkts  {}",
                conversation.packets(),
                human_bytes(conversation.bytes())
            ),
            theme::HINT,
        ),
    ])
}

fn popup_area(screen: Rect, rows: usize) -> Rect {
    let height = u16::try_from(rows.max(1))
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let [area] = Layout::horizontal([Constraint::Percentage(80)])
        .flex(Flex::Center)
        .areas(screen);
    let [area] = Layout::vertical([Constraint::Max(height)])
        .flex(Flex::Center)
        .areas(area);
    area
}
