use super::summary::summary;
use super::text::{printable, wrap};
use crate::capture::Feed;
use crate::error::YeyoError;
use crate::packet::Packet;
use crate::packet::link::LinkType;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::widgets::{Block, Paragraph};
use ratatui::{DefaultTerminal, Frame};
use std::io;
use std::sync::mpsc::TryRecvError;
use std::time::Duration;

const TICK: Duration = Duration::from_millis(100);
const MAX_FRAMES_PER_TICK: usize = 10_000;
const STREAM_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Quit,
}

#[derive(Debug, Default)]
pub struct View {
    latest: Option<String>,
    payload: String,
    stream: String,
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
        self.latest = Some(format!("{} len {len}", summary(packet)));
        self.payload = printable(packet.payload);
        self.stream.push_str(&self.payload);
        self.trim_stream();
    }

    pub fn bad(&mut self, len: u32, err: &YeyoError) {
        self.packets += 1;
        if self.paused {
            return;
        }
        self.latest = Some(format!("bad packet: {err}, len {len}"));
        self.payload.clear();
    }

    pub fn stream(&self) -> &str {
        &self.stream
    }

    pub fn end(&mut self) {
        self.ended = true;
    }

    pub fn key(&mut self, key: KeyEvent) -> Flow {
        if key.kind != KeyEventKind::Press {
            return Flow::Continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => Flow::Quit,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Flow::Quit,
            KeyCode::Char(' ') => {
                self.paused = !self.paused;
                Flow::Continue
            }
            KeyCode::Char('c') => {
                self.stream.clear();
                Flow::Continue
            }
            _ => Flow::Continue,
        }
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

        frame.render_widget(Block::bordered().title(" filter "), filter);
        frame.render_widget(
            Paragraph::new(latest).block(Block::bordered().title(" packet ")),
            packet,
        );
        boxed_rows(frame, " payload ", &self.payload, payload, Rows::First);
        boxed_rows(frame, " stream ", &self.stream, stream, Rows::Last);
        frame.render_widget(
            Paragraph::new(format!(
                " q quit | space pause | c clear | {count} | {state}"
            )),
            footer,
        );
    }

    fn trim_stream(&mut self) {
        if self.stream.len() <= STREAM_LIMIT {
            return;
        }
        let mut cut = self.stream.len() - STREAM_LIMIT;
        while !self.stream.is_char_boundary(cut) {
            cut += 1;
        }
        self.stream.drain(..cut);
    }
}

enum Rows {
    First,
    Last,
}

fn boxed_rows(frame: &mut Frame, title: &str, text: &str, area: Rect, rows: Rows) {
    let block = Block::bordered().title(title);
    let inner = block.inner(area);
    let all = wrap(text, usize::from(inner.width));
    let height = usize::from(inner.height);
    let shown = match rows {
        Rows::First => &all[..all.len().min(height)],
        Rows::Last => &all[all.len().saturating_sub(height)..],
    };
    frame.render_widget(Paragraph::new(shown.join("\n")).block(block), area);
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
