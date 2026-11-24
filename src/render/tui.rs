use super::conversations::{Conversations, Key};
use super::stream::{Side, Stream};
use super::summary::summary;
use super::text::{printable, wrap, wrap_tagged};
use super::theme::{self, panel};
use crate::capture::Feed;
use crate::error::YeyoError;
use crate::packet::link::LinkType;
use crate::packet::{Packet, Transport};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::{DefaultTerminal, Frame};
use std::io;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

const TICK: Duration = Duration::from_millis(100);
const MAX_FRAMES_PER_TICK: usize = 10_000;
const PROTO_TCP: u8 = 6;
const KEYS: [(&str, &str); 4] = [
    ("q", "quit"),
    ("space", "pause"),
    ("c", "clear"),
    ("f", "follow"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Quit,
}

#[derive(Debug, Default)]
pub struct View {
    capture_filter: Option<String>,
    latest: Option<Line<'static>>,
    latest_key: Option<Key>,
    payload: String,
    live: Stream,
    conversations: Conversations,
    following: Option<Key>,
    packets: u64,
    ended: bool,
    paused: bool,
}

impl View {
    pub fn new(capture_filter: Option<&str>) -> Self {
        Self {
            capture_filter: capture_filter
                .map(|expr| printable(expr.as_bytes()).replace('\n', " ")),
            ..Self::default()
        }
    }

    pub fn packet(&mut self, len: u32, packet: &Packet<'_>) {
        self.packets += 1;
        if self.paused {
            return;
        }
        let payload = printable(packet.payload);
        let recorded = self.conversations.record(packet, len, &payload);
        let key = recorded.map(|(key, _)| key);
        self.live
            .push(recorded.map(|(_, side)| side), payload.clone());
        if self.following.is_some() && key != self.following {
            return;
        }
        let style = match packet.transport {
            Some(Transport::Tcp(_)) => theme::TCP,
            Some(Transport::Udp(_)) => theme::UDP,
            None => theme::OTHER,
        };
        self.latest = Some(Line::from(vec![
            Span::styled(summary(packet), style),
            Span::styled(format!(" len {len}"), theme::MUTED),
        ]));
        self.latest_key = key;
        self.payload = payload;
    }

    pub fn bad(&mut self, len: u32, err: &YeyoError) {
        self.packets += 1;
        if self.paused || self.following.is_some() {
            return;
        }
        self.latest = Some(Line::from(vec![
            Span::styled(format!("bad packet: {err}"), theme::BAD),
            Span::styled(format!(", len {len}"), theme::MUTED),
        ]));
        self.latest_key = None;
        self.payload.clear();
    }

    pub fn stream(&self) -> String {
        self.shown_stream().text()
    }

    pub fn end(&mut self) {
        self.ended = true;
    }

    pub fn key(&mut self, key: KeyEvent) -> Flow {
        if key.kind != KeyEventKind::Press {
            return Flow::Continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Flow::Quit,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Flow::Quit;
            }
            KeyCode::Char(' ') => self.paused = !self.paused,
            KeyCode::Char('c') => self.clear_stream(),
            KeyCode::Char('f') => self.toggle_follow(),
            _ => {}
        }
        Flow::Continue
    }

    pub fn draw(&self, frame: &mut Frame) {
        let [filter, packet, payload, stream, footer] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        frame.render_widget(
            Paragraph::new(self.filter_line()).block(panel("filter")),
            filter,
        );
        let latest = match &self.latest {
            Some(line) => line.clone(),
            None => Line::styled("waiting for packets...", theme::MUTED),
        };
        frame.render_widget(Paragraph::new(latest).block(panel("packet")), packet);
        let block = panel("payload");
        let inner = block.inner(payload);
        let rows = wrap(&self.payload, usize::from(inner.width));
        let shown = &rows[..rows.len().min(usize::from(inner.height))];
        frame.render_widget(Paragraph::new(shown.join("\n")).block(block), payload);
        self.draw_stream(frame, stream);
        frame.render_widget(Paragraph::new(self.footer_line()), footer);
    }

    fn footer_line(&self) -> Line<'static> {
        let mut spans = vec![Span::raw(" ")];
        for (key, label) in KEYS {
            spans.push(Span::styled(format!(" {key} "), theme::KEY));
            spans.push(Span::styled(format!(" {label}  "), theme::HINT));
        }
        let count = match self.packets {
            1 => "1 packet".to_string(),
            n => format!("{n} packets"),
        };
        let (state, style) = if self.ended {
            ("ended", theme::ENDED)
        } else if self.paused {
            ("paused", theme::PAUSED)
        } else {
            ("capturing", theme::CAPTURING)
        };
        spans.push(Span::styled(format!("{count} | "), theme::HINT));
        spans.push(Span::styled(state, style));
        Line::from(spans)
    }

    fn filter_line(&self) -> Line<'static> {
        let mut spans = vec![Span::styled("capture ", theme::HINT)];
        spans.push(match &self.capture_filter {
            Some(expr) => Span::styled(expr.clone(), theme::FILTER),
            None => Span::styled("all packets", theme::MUTED),
        });
        spans.push(Span::styled("  │  ", theme::BORDER));
        spans.extend(self.follow_spans());
        Line::from(spans)
    }

    fn follow_spans(&self) -> Vec<Span<'static>> {
        let followed = self
            .following
            .and_then(|key| Some((key, self.conversations.get(&key)?)));
        let Some((key, conversation)) = followed else {
            return vec![Span::styled(
                "none (f follows the current packet's conversation)",
                theme::MUTED,
            )];
        };
        let protocol = if key.protocol() == PROTO_TCP {
            "TCP"
        } else {
            "UDP"
        };
        vec![
            Span::styled("following ", theme::FOLLOW),
            Span::raw(format!("{protocol} ")),
            Span::styled(conversation.client().to_string(), theme::CLIENT),
            Span::styled(" <> ", theme::MUTED),
            Span::styled(conversation.server().to_string(), theme::SERVER),
        ]
    }

    fn draw_stream(&self, frame: &mut Frame, area: Rect) {
        let block = match self.following {
            Some(_) => panel("stream").border_style(theme::FOLLOW),
            None => panel("stream"),
        };
        let inner = block.inner(area);
        let rows = wrap_tagged(&self.shown_stream().parts(), usize::from(inner.width));
        let start = rows.len().saturating_sub(usize::from(inner.height));
        let lines: Vec<Line> = rows
            .into_iter()
            .skip(start)
            .map(|row| {
                let spans: Vec<Span> = row
                    .into_iter()
                    .map(|(side, text)| Span::styled(text, side_style(side)))
                    .collect();
                Line::from(spans)
            })
            .collect();
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn shown_stream(&self) -> &Stream {
        match self.following.and_then(|key| self.conversations.get(&key)) {
            Some(conversation) => conversation.stream(),
            None => &self.live,
        }
    }

    fn clear_stream(&mut self) {
        match self
            .following
            .and_then(|key| self.conversations.get_mut(&key))
        {
            Some(conversation) => conversation.clear(),
            None => self.live.clear(),
        }
    }

    fn toggle_follow(&mut self) {
        if self.following.is_some() {
            self.following = None;
        } else {
            self.following = self.latest_key;
        }
        self.conversations.pin(self.following);
    }
}

fn side_style(side: Option<Side>) -> Style {
    match side {
        Some(Side::Client) => theme::CLIENT,
        Some(Side::Server) => theme::SERVER,
        None => Style::new(),
    }
}

pub fn show_tui(
    feed: &Feed,
    link_type: LinkType,
    capture_filter: Option<&str>,
) -> Result<(), YeyoError> {
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(e) => {
            ratatui::restore();
            return Err(output(e));
        }
    };
    let shown = run(&mut terminal, feed, link_type, View::new(capture_filter));
    let restored = ratatui::try_restore().map_err(output);
    shown?;
    restored
}

fn run(
    terminal: &mut DefaultTerminal,
    feed: &Feed,
    link_type: LinkType,
    mut view: View,
) -> Result<(), YeyoError> {
    loop {
        drain(feed, link_type, &mut view);
        terminal.draw(|frame| view.draw(frame)).map_err(output)?;
        if event::poll(TICK).map_err(output)?
            && let Event::Key(key) = event::read().map_err(output)?
            && view.key(key) == Flow::Quit
        {
            return Ok(());
        }
    }
}

fn drain(feed: &Feed, link_type: LinkType, view: &mut View) {
    for _ in 0..MAX_FRAMES_PER_TICK {
        match feed.try_recv() {
            Ok(frame) => match Packet::parse(link_type, &frame.data) {
                Ok(packet) => view.packet(frame.len, &packet),
                Err(e) => view.bad(frame.len, &e),
            },
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                view.end();
                return;
            }
        }
    }
}

fn output(e: io::Error) -> YeyoError {
    YeyoError::Output(e.to_string())
}
