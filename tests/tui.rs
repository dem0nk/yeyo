mod common;

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use std::error::Error;
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::Packet;
use yeyo::packet::link::LinkType;
use yeyo::render::{Flow, View};

fn screen(view: &View, width: u16, height: u16) -> Result<String, Box<dyn Error>> {
    let mut terminal = Terminal::new(TestBackend::new(width, height))?;
    terminal.draw(|frame| view.draw(frame))?;
    let buffer = terminal.backend().buffer();
    Ok(buffer.content.iter().map(|cell| cell.symbol()).collect())
}

fn udp_packet(view: &mut View, src_port: u16) -> Result<(), Box<dyn Error>> {
    let udp = common::udp(src_port, 53, b"q");
    let ip = common::ipv4(17, [10, 0, 0, 1], [8, 8, 8, 8], &udp);
    let packet = Packet::parse(LinkType::Raw, &ip)?;
    view.packet(64, &packet);
    Ok(())
}

fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
    KeyEvent::new(code, modifiers)
}

#[test]
fn test_view_empty_shows_waiting_ok() -> Result<(), Box<dyn Error>> {
    let text = screen(&View::default(), 80, 20)?;

    assert!(text.contains("waiting for packets..."));
    assert!(text.contains("0 packets | capturing"));
    Ok(())
}

#[test]
fn test_view_shows_boxes_ok() -> Result<(), Box<dyn Error>> {
    let text = screen(&View::default(), 80, 20)?;

    for title in [" filter ", " packet ", " payload ", " stream ", " q quit "] {
        assert!(text.contains(title), "missing {title:?}");
    }
    Ok(())
}

#[test]
fn test_view_latest_packet_replaces_previous_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    udp_packet(&mut view, 1111)?;
    udp_packet(&mut view, 2222)?;
    let text = screen(&view, 80, 20)?;

    assert!(text.contains("10.0.0.1:2222 > 8.8.8.8:53 UDP len 64"));
    assert!(!text.contains("1111"));
    assert!(text.contains("2 packets"));
    Ok(())
}

#[test]
fn test_view_single_packet_count_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    udp_packet(&mut view, 1111)?;
    let text = screen(&view, 80, 20)?;

    assert!(text.contains("1 packet |"));
    Ok(())
}

#[test]
fn test_view_bad_packet_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    let err = YeyoError::Truncated {
        layer: Layer::Udp,
        needed: 8,
        got: 3,
    };

    view.bad(31, &err);
    let text = screen(&view, 100, 20)?;

    assert!(text.contains("bad packet: truncated UDP header: needed 8 bytes, got 3, len 31"));
    assert!(text.contains("1 packet |"));
    Ok(())
}

#[test]
fn test_view_ended_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    view.end();
    let text = screen(&view, 80, 20)?;

    assert!(text.contains("| ended"));
    Ok(())
}

#[test]
fn test_view_tiny_terminal_does_not_panic_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    udp_packet(&mut view, 1111)?;

    for (width, height) in [(1, 1), (5, 2), (20, 4), (80, 1)] {
        screen(&view, width, height)?;
    }
    Ok(())
}

#[test]
fn test_key_quit_ok() {
    let mut view = View::default();

    assert_eq!(
        view.key(press(KeyCode::Char('q'), KeyModifiers::NONE)),
        Flow::Quit
    );
    assert_eq!(
        view.key(press(KeyCode::Esc, KeyModifiers::NONE)),
        Flow::Quit
    );
    assert_eq!(
        view.key(press(KeyCode::Char('c'), KeyModifiers::CONTROL)),
        Flow::Quit
    );
}

#[test]
fn test_key_other_continues_ok() {
    let mut view = View::default();

    assert_eq!(
        view.key(press(KeyCode::Char('c'), KeyModifiers::NONE)),
        Flow::Continue
    );
    assert_eq!(
        view.key(press(KeyCode::Char('x'), KeyModifiers::NONE)),
        Flow::Continue
    );
    assert_eq!(
        view.key(press(KeyCode::Enter, KeyModifiers::NONE)),
        Flow::Continue
    );
}

#[test]
fn test_key_release_ignored_ok() {
    let mut view = View::default();
    let mut release = press(KeyCode::Char('q'), KeyModifiers::NONE);
    release.kind = KeyEventKind::Release;

    assert_eq!(view.key(release), Flow::Continue);
}
