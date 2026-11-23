use super::summary::summary;
use super::text::{printable, wrap, wrap_tagged};
use super::theme::{self, panel};
use crate::capture::Feed;
use crate::error::YeyoError;
use crate::packet::link::LinkType;
use crate::packet::{Endpoints, Packet, Transport};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::{DefaultTerminal, Frame};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

const TICK: Duration = Duration::from_millis(100);
const MAX_FRAMES_PER_TICK: usize = 10_000;
const STREAM_LIMIT: usize = 64 * 1024;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Side {
    Client,
    Server,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lock {
    protocol: u8,
    client: SocketAddr,
    server: SocketAddr,
}

impl Lock {
    fn side(&self, endpoints: &Endpoints) -> Option<Side> {
        if endpoints.protocol != self.protocol {
            return None;
        }
        if endpoints.src == self.client && endpoints.dst == self.server {
            Some(Side::Client)
        } else if endpoints.src == self.server && endpoints.dst == self.client {
            Some(Side::Server)
        } else {
            None
        }
    }
}

#[derive(Debug)]
struct Chunk {
    side: Option<Side>,
    text: String,
}

#[derive(Debug, Default)]
pub struct View {
    capture_filter: Option<String>,
    latest: Option<Line<'static>>,
    latest_endpoints: Option<Endpoints>,
    payload: String,
    stream: VecDeque<Chunk>,
    stream_len: usize,
    lock: Option<Lock>,
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
        let endpoints = packet.endpoints();
        let side = match (self.lock, endpoints) {
            (None, _) => None,
            (Some(lock), Some(endpoints)) => match lock.side(&endpoints) {
                Some(side) => Some(side),
                None => return,
            },
            (Some(_), None) => return,
        };
        let style = match packet.transport {
            Some(Transport::Tcp(_)) => theme::TCP,
            Some(Transport::Udp(_)) => theme::UDP,
            None => theme::OTHER,
        };
        self.latest = Some(Line::from(vec![
            Span::styled(summary(packet), style),
            Span::styled(format!(" len {len}"), theme::MUTED),
        ]));
        self.latest_endpoints = endpoints;
        self.payload = printable(packet.payload);
        self.push_stream(side, self.payload.clone());
    }

    pub fn bad(&mut self, len: u32, err: &YeyoError) {
        self.packets += 1;
        if self.paused || self.lock.is_some() {
            return;
        }
        self.latest = Some(Line::from(vec![
            Span::styled(format!("bad packet: {err}"), theme::BAD),
            Span::styled(format!(", len {len}"), theme::MUTED),
        ]));
        self.latest_endpoints = None;
        self.payload.clear();
    }

    pub fn stream(&self) -> String {
        self.stream
            .iter()
            .map(|chunk| chunk.text.as_str())
            .collect()
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
            KeyCode::Char('f') => self.toggle_lock(),
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
        spans.extend(self.lock_spans());
        Line::from(spans)
    }

    fn lock_spans(&self) -> Vec<Span<'static>> {
        let Some(lock) = self.lock else {
            return vec![Span::styled(
                "none (f follows the current packet's conversation)",
                theme::MUTED,
            )];
        };
        let protocol = if lock.protocol == PROTO_TCP {
            "TCP"
        } else {
            "UDP"
        };
        vec![
            Span::styled("following ", theme::FOLLOW),
            Span::raw(format!("{protocol} ")),
            Span::styled(lock.client.to_string(), theme::CLIENT),
            Span::styled(" <> ", theme::MUTED),
            Span::styled(lock.server.to_string(), theme::SERVER),
        ]
    }

    fn draw_stream(&self, frame: &mut Frame, area: Rect) {
        let block = match self.lock {
            Some(_) => panel("stream").border_style(theme::FOLLOW),
            None => panel("stream"),
        };
        let inner = block.inner(area);
        let parts: Vec<(Option<Side>, &str)> = self
            .stream
            .iter()
            .map(|chunk| (chunk.side, chunk.text.as_str()))
            .collect();
        let rows = wrap_tagged(&parts, usize::from(inner.width));
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

    fn toggle_lock(&mut self) {
        if self.lock.take().is_some() {
            self.clear_stream();
            return;
        }
        if let Some(endpoints) = self.latest_endpoints {
            self.lock = Some(Lock {
                protocol: endpoints.protocol,
                client: endpoints.src,
                server: endpoints.dst,
            });
            self.clear_stream();
            self.push_stream(Some(Side::Client), self.payload.clone());
        }
    }

    fn push_stream(&mut self, side: Option<Side>, text: String) {
        if text.is_empty() {
            return;
        }
        self.stream_len += text.len();
        self.stream.push_back(Chunk { side, text });
        self.trim_stream();
    }

    fn clear_stream(&mut self) {
        self.stream.clear();
        self.stream_len = 0;
    }

    fn trim_stream(&mut self) {
        while self.stream_len > STREAM_LIMIT {
            let excess = self.stream_len - STREAM_LIMIT;
            let Some(front) = self.stream.front_mut() else {
                break;
            };
            if front.text.len() <= excess {
                self.stream_len -= front.text.len();
                self.stream.pop_front();
            } else {
                let mut cut = excess;
                while !front.text.is_char_boundary(cut) {
                    cut += 1;
                }
                front.text.drain(..cut);
                self.stream_len -= cut;
            }
        }
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
