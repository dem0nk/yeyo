use super::summary::summary;
use super::text::{printable, wrap, wrap_tagged};
use crate::capture::Feed;
use crate::error::YeyoError;
use crate::packet::link::LinkType;
use crate::packet::{Endpoints, Packet};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::{DefaultTerminal, Frame};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

const TICK: Duration = Duration::from_millis(100);
const MAX_FRAMES_PER_TICK: usize = 10_000;
const STREAM_LIMIT: usize = 64 * 1024;
const CLIENT_COLOR: Color = Color::LightRed;
const SERVER_COLOR: Color = Color::LightBlue;
const PROTO_TCP: u8 = 6;

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
    latest: Option<String>,
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
        self.latest = Some(format!("{} len {len}", summary(packet)));
        self.latest_endpoints = endpoints;
        self.payload = printable(packet.payload);
        self.push_stream(side, self.payload.clone());
    }

    pub fn bad(&mut self, len: u32, err: &YeyoError) {
        self.packets += 1;
        if self.paused || self.lock.is_some() {
            return;
        }
        self.latest = Some(format!("bad packet: {err}, len {len}"));
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

        let latest = self.latest.as_deref().unwrap_or("waiting for packets...");
        let state = if self.ended {
            "ended"
        } else if self.paused {
            "paused"
        } else {
            "capturing"
        };
        let count = match self.packets {
            1 => "1 packet".to_string(),
            n => format!("{n} packets"),
        };

        frame.render_widget(
            Paragraph::new(self.lock_line()).block(Block::bordered().title(" filter ")),
            filter,
        );
        frame.render_widget(
            Paragraph::new(latest).block(Block::bordered().title(" packet ")),
            packet,
        );
        let block = Block::bordered().title(" payload ");
        let inner = block.inner(payload);
        let rows = wrap(&self.payload, usize::from(inner.width));
        let shown = &rows[..rows.len().min(usize::from(inner.height))];
        frame.render_widget(Paragraph::new(shown.join("\n")).block(block), payload);
        self.draw_stream(frame, stream);
        frame.render_widget(
            Paragraph::new(format!(
                " q quit | space pause | c clear | f follow | {count} | {state}"
            )),
            footer,
        );
    }

    fn lock_line(&self) -> Line<'static> {
        let Some(lock) = self.lock else {
            return Line::from("none (f follows the current packet's conversation)");
        };
        let protocol = if lock.protocol == PROTO_TCP {
            "TCP"
        } else {
            "UDP"
        };
        Line::from(vec![
            Span::raw(format!("following {protocol} ")),
            Span::styled(lock.client.to_string(), Style::new().fg(CLIENT_COLOR)),
            Span::raw(" <> "),
            Span::styled(lock.server.to_string(), Style::new().fg(SERVER_COLOR)),
        ])
    }

    fn draw_stream(&self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered().title(" stream ");
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
        Some(Side::Client) => Style::new().fg(CLIENT_COLOR),
        Some(Side::Server) => Style::new().fg(SERVER_COLOR),
        None => Style::new(),
    }
}

pub fn show_tui(feed: &Feed, link_type: LinkType) -> Result<(), YeyoError> {
    let mut terminal = match ratatui::try_init() {
        Ok(terminal) => terminal,
        Err(e) => {
            ratatui::restore();
            return Err(output(e));
        }
    };
    let shown = run(&mut terminal, feed, link_type);
    let restored = ratatui::try_restore().map_err(output);
    shown?;
    restored
}

fn run(terminal: &mut DefaultTerminal, feed: &Feed, link_type: LinkType) -> Result<(), YeyoError> {
    let mut view = View::default();
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
