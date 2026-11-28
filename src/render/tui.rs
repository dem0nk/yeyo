use super::conversations::{Conversation, Conversations, Key, Target, protocol_name};
use super::highlight::{Mark, marks};
use super::picker::Picker;
use super::stream::{Side, Stream};
use super::summary::summary;
use super::text::{printable, wrap_tagged};
use super::theme::{self, panel};
use crate::capture::Feed;
use crate::error::YeyoError;
use crate::filter::Filter;
use crate::packet::link::LinkType;
use crate::packet::{Packet, Transport};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::{DefaultTerminal, Frame};
use std::cell::Cell;
use std::io;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

const TICK: Duration = Duration::from_millis(100);
const MAX_FRAMES_PER_TICK: usize = 10_000;
const KEYS: [(&str, &str); 5] = [
    ("q", "quit"),
    ("space", "pause"),
    ("c", "clear"),
    ("f", "follow"),
    ("↑↓", "scroll"),
];
const PICKER_KEYS: [(&str, &str); 4] = [
    ("↑↓", "move"),
    ("enter", "follow"),
    ("s", "server"),
    ("esc", "close"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Quit,
}

#[derive(Debug, Default)]
enum Mode {
    #[default]
    Live,
    Picking(Picker),
    Following(Following),
}

#[derive(Debug)]
struct Following {
    target: Target,
    stream: Stream,
}

#[derive(Debug, Default)]
pub struct View {
    capture_filter: Option<String>,
    display_filter: Option<String>,
    latest: Option<Line<'static>>,
    latest_key: Option<Key>,
    payload: String,
    live: Stream,
    conversations: Conversations,
    mode: Mode,
    scroll_top: Option<usize>,
    page: Cell<usize>,
    max_top: Cell<usize>,
    packets: u64,
    ended: bool,
    paused: bool,
}

impl View {
    pub fn new(capture_filter: Option<&str>) -> Self {
        Self {
            capture_filter: capture_filter.map(one_line),
            ..Self::default()
        }
    }

    pub fn with_display_filter(mut self, expr: Option<&str>) -> Self {
        self.display_filter = expr.map(one_line);
        self
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
        if let Mode::Following(following) = &mut self.mode {
            let (Some(key), Some(endpoints)) = (key, packet.endpoints()) else {
                return;
            };
            if !following.target.matches(&key) {
                return;
            }
            let side = following.target.side(&endpoints);
            following.stream.push(Some(side), payload.clone());
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
        if self.paused || matches!(self.mode, Mode::Following(_)) {
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
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Flow::Quit;
        }
        if let Mode::Picking(picker) = &mut self.mode {
            match key.code {
                KeyCode::Char('q') => return Flow::Quit,
                KeyCode::Up | KeyCode::Char('k') => picker.up(),
                KeyCode::Down | KeyCode::Char('j') => picker.down(),
                KeyCode::Enter => self.follow_selected(Target::connection),
                KeyCode::Char('s') => self.follow_selected(Target::server),
                KeyCode::Esc | KeyCode::Char('f') => self.mode = Mode::Live,
                _ => {}
            }
            return Flow::Continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Flow::Quit,
            KeyCode::Char(' ') => self.paused = !self.paused,
            KeyCode::Char('c') => self.clear_stream(),
            KeyCode::Char('f') => self.toggle_follow(),
            KeyCode::Up | KeyCode::Char('k') => self.scroll_up(1),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_down(1),
            KeyCode::PageUp => self.scroll_up(self.page.get()),
            KeyCode::PageDown => self.scroll_down(self.page.get()),
            KeyCode::Home | KeyCode::Char('g') => self.scroll_up(usize::MAX),
            KeyCode::End | KeyCode::Char('G') => self.scroll_top = None,
            _ => {}
        }
        Flow::Continue
    }

    pub fn draw(&self, frame: &mut Frame) {
        let [filter, packet, payload, stream, footer] = Layout::vertical([
            Constraint::Length(4),
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Min(3),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        frame.render_widget(
            Paragraph::new(self.filter_lines()).block(panel("filter")),
            filter,
        );
        let latest = match &self.latest {
            Some(line) => line.clone(),
            None => Line::styled("waiting for packets...", theme::MUTED),
        };
        frame.render_widget(Paragraph::new(latest).block(panel("packet")), packet);
        let block = panel("payload");
        let inner = block.inner(payload);
        let rows = wrap_tagged(&marked(&[(None, &self.payload)]), usize::from(inner.width));
        let shown: Vec<Line> = rows
            .into_iter()
            .take(usize::from(inner.height))
            .map(styled_row)
            .collect();
        frame.render_widget(Paragraph::new(shown).block(block), payload);
        self.draw_stream(frame, stream);
        let status = self.status_line();
        let [keys, status_area] = Layout::horizontal([
            Constraint::Min(0),
            Constraint::Length(u16::try_from(status.width()).unwrap_or(u16::MAX)),
        ])
        .areas(footer);
        frame.render_widget(Paragraph::new(self.keys_line()), keys);
        frame.render_widget(Paragraph::new(status), status_area);
        if let Mode::Picking(picker) = &self.mode {
            picker.draw(frame, &self.conversations);
        }
    }

    fn keys_line(&self) -> Line<'static> {
        let mut spans = vec![Span::raw(" ")];
        let keys: &[(&str, &str)] = match self.mode {
            Mode::Picking(_) => &PICKER_KEYS,
            _ => &KEYS,
        };
        for (key, label) in keys {
            spans.push(Span::styled(format!(" {key} "), theme::KEY));
            spans.push(Span::styled(format!(" {label}  "), theme::HINT));
        }
        Line::from(spans)
    }

    fn status_line(&self) -> Line<'static> {
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
        Line::from(vec![
            Span::styled(format!("{count} | "), theme::HINT),
            Span::styled(state, style),
            Span::raw(" "),
        ])
    }

    fn filter_lines(&self) -> Vec<Line<'static>> {
        let mut spans = vec![Span::styled("capture ", theme::HINT)];
        spans.push(match &self.capture_filter {
            Some(expr) => Span::styled(expr.clone(), theme::FILTER),
            None => Span::styled("all packets", theme::MUTED),
        });
        spans.push(Span::styled("  │  ", theme::BORDER));
        spans.push(Span::styled("display ", theme::HINT));
        spans.push(match &self.display_filter {
            Some(expr) => Span::styled(expr.clone(), theme::FILTER),
            None => Span::styled("none", theme::MUTED),
        });
        vec![Line::from(spans), Line::from(self.follow_spans())]
    }

    fn follow_spans(&self) -> Vec<Span<'static>> {
        let Mode::Following(following) = &self.mode else {
            return vec![Span::styled(
                "follow none (f picks a conversation)",
                theme::MUTED,
            )];
        };
        match following.target {
            Target::Connection {
                key,
                client,
                server,
            } => vec![
                Span::styled("following ", theme::FOLLOW),
                Span::raw(format!("{} ", key.protocol_name())),
                Span::styled(client.to_string(), theme::CLIENT),
                Span::styled(" <> ", theme::MUTED),
                Span::styled(server.to_string(), theme::SERVER),
            ],
            Target::Server {
                protocol,
                client,
                server,
            } => vec![
                Span::styled("following server ", theme::FOLLOW),
                Span::raw(format!("{} ", protocol_name(protocol))),
                Span::styled(client.to_string(), theme::CLIENT),
                Span::styled(" > ", theme::MUTED),
                Span::styled(server.to_string(), theme::SERVER),
            ],
        }
    }

    fn draw_stream(&self, frame: &mut Frame, area: Rect) {
        let mut block = match self.mode {
            Mode::Following(_) => panel("stream").border_style(theme::FOLLOW),
            _ => panel("stream"),
        };
        if self.scroll_top.is_some() {
            block =
                block.title(Line::styled(" scrolled · End = live ", theme::FOLLOW).right_aligned());
        }
        let inner = block.inner(area);
        let height = usize::from(inner.height);
        let rows = wrap_tagged(
            &marked(&self.shown_stream().parts()),
            usize::from(inner.width),
        );
        let max_top = rows.len().saturating_sub(height);
        self.page.set(height.max(1));
        self.max_top.set(max_top);
        let start = self.scroll_top.map_or(max_top, |top| top.min(max_top));
        let lines: Vec<Line> = rows
            .into_iter()
            .skip(start)
            .take(height)
            .map(styled_row)
            .collect();
        frame.render_widget(Paragraph::new(lines).block(block), area);
    }

    fn shown_stream(&self) -> &Stream {
        match &self.mode {
            Mode::Following(following) => &following.stream,
            _ => &self.live,
        }
    }

    fn scroll_up(&mut self, rows: usize) {
        let max_top = self.max_top.get();
        if max_top == 0 {
            return;
        }
        let top = self.scroll_top.unwrap_or(max_top).min(max_top);
        self.scroll_top = Some(top.saturating_sub(rows));
    }

    fn scroll_down(&mut self, rows: usize) {
        let Some(top) = self.scroll_top else {
            return;
        };
        let top = top.saturating_add(rows);
        self.scroll_top = (top < self.max_top.get()).then_some(top);
    }

    fn clear_stream(&mut self) {
        self.scroll_top = None;
        match &mut self.mode {
            Mode::Following(following) => following.stream.clear(),
            _ => self.live.clear(),
        }
    }

    fn toggle_follow(&mut self) {
        self.scroll_top = None;
        self.mode = match self.mode {
            Mode::Following(_) => Mode::Live,
            _ => Mode::Picking(Picker::open(&self.conversations, self.latest_key)),
        };
    }

    fn follow_selected(&mut self, target: fn(Key, &Conversation) -> Target) {
        let Mode::Picking(picker) = &self.mode else {
            return;
        };
        let Some(key) = picker.selected() else {
            return;
        };
        let Some(conversation) = self.conversations.get(&key) else {
            return;
        };
        let target = target(key, conversation);
        let mut stream = Stream::default();
        for conversation in self.conversations.matching(&target) {
            for (side, text) in conversation.stream().parts() {
                stream.push(side, text.to_string());
            }
        }
        self.mode = Mode::Following(Following { target, stream });
        self.scroll_top = None;
    }
}

fn side_style(side: Option<Side>) -> Style {
    match side {
        Some(Side::Client) => theme::CLIENT,
        Some(Side::Server) => theme::SERVER,
        None => Style::new(),
    }
}

type Tag = (Option<Side>, Mark);

fn marked<'a>(parts: &[(Option<Side>, &'a str)]) -> Vec<(Tag, &'a str)> {
    let mut out = Vec::new();
    let mut previous: Option<(Option<Side>, &str)> = None;
    for &(side, text) in parts {
        if let Some((last_side, last_text)) = previous
            && last_side != side
            && !last_text.ends_with('\n')
        {
            out.push(((last_side, Mark::Plain), "\n"));
        }
        out.extend(
            marks(text)
                .into_iter()
                .map(|(mark, piece)| ((side, mark), piece)),
        );
        previous = Some((side, text));
    }
    out
}

fn styled_row(row: Vec<(Tag, String)>) -> Line<'static> {
    let spans: Vec<Span> = row
        .into_iter()
        .map(|((side, mark), text)| Span::styled(text, mark_style(side, mark)))
        .collect();
    Line::from(spans)
}

fn mark_style(side: Option<Side>, mark: Mark) -> Style {
    match mark {
        Mark::Plain => side_style(side),
        Mark::Method | Mark::Header | Mark::Key => side_style(side).add_modifier(theme::KEYWORD),
        Mark::Secret => theme::SECRET,
    }
}

fn one_line(expr: &str) -> String {
    printable(expr.as_bytes()).replace('\n', " ")
}

pub fn show_tui(
    feed: &Feed,
    link_type: LinkType,
    capture_filter: Option<&str>,
    display_filter: Option<&Filter>,
) -> Result<(), YeyoError> {
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(e) => {
            ratatui::restore();
            return Err(output(e));
        }
    };
    let view = View::new(capture_filter).with_display_filter(display_filter.map(Filter::text));
    let shown = run(&mut terminal, feed, link_type, display_filter, view);
    let restored = ratatui::try_restore().map_err(output);
    shown?;
    restored
}

fn run(
    terminal: &mut DefaultTerminal,
    feed: &Feed,
    link_type: LinkType,
    filter: Option<&Filter>,
    mut view: View,
) -> Result<(), YeyoError> {
    loop {
        drain(feed, link_type, filter, &mut view);
        terminal.draw(|frame| view.draw(frame)).map_err(output)?;
        if event::poll(TICK).map_err(output)?
            && let Event::Key(key) = event::read().map_err(output)?
            && view.key(key) == Flow::Quit
        {
            return Ok(());
        }
    }
}

fn drain(feed: &Feed, link_type: LinkType, filter: Option<&Filter>, view: &mut View) {
    for _ in 0..MAX_FRAMES_PER_TICK {
        match feed.try_recv() {
            Ok(frame) => match (Packet::parse(link_type, &frame.data), filter) {
                (Ok(packet), Some(filter)) if !filter.matches(&packet) => {}
                (Ok(packet), _) => view.packet(frame.len, &packet),
                (Err(_), Some(_)) => {}
                (Err(e), None) => view.bad(frame.len, &e),
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
