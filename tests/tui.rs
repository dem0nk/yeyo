mod common;

use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::style::Color;
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

fn tcp_payload(view: &mut View, payload: &[u8]) -> Result<(), Box<dyn Error>> {
    let tcp = common::tcp(51000, 80, 0x18, payload);
    let ip = common::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &tcp);
    let packet = Packet::parse(LinkType::Raw, &ip)?;
    view.packet(64, &packet);
    Ok(())
}

fn key(view: &mut View, code: KeyCode) -> Flow {
    view.key(press(code, KeyModifiers::NONE))
}

fn send(
    view: &mut View,
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let tcp = common::tcp(src.1, dst.1, 0x18, payload);
    let ip = common::ipv4(6, src.0, dst.0, &tcp);
    let packet = Packet::parse(LinkType::Raw, &ip)?;
    view.packet(64, &packet);
    Ok(())
}

fn drawn(view: &View) -> Result<Buffer, Box<dyn Error>> {
    let mut terminal = Terminal::new(TestBackend::new(80, 20))?;
    terminal.draw(|frame| view.draw(frame))?;
    Ok(terminal.backend().buffer().clone())
}

fn last_color_of(buffer: &Buffer, needle: &str) -> Option<Color> {
    let cells = &buffer.content;
    let wanted: Vec<String> = needle.chars().map(String::from).collect();
    (0..cells.len().saturating_sub(wanted.len()))
        .rev()
        .find(|&i| {
            wanted
                .iter()
                .enumerate()
                .all(|(j, c)| cells[i + j].symbol() == c.as_str())
        })
        .map(|i| cells[i].fg)
}

const CLIENT: ([u8; 4], u16) = ([10, 0, 0, 1], 51000);
const SERVER: ([u8; 4], u16) = ([10, 0, 0, 2], 80);
const OTHER: ([u8; 4], u16) = ([10, 0, 0, 9], 4444);

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

    for title in [" filter ", " packet ", " payload ", " stream ", " quit "] {
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

#[test]
fn test_view_payload_shown_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    tcp_payload(&mut view, b"GET /login HTTP/1.1\r\nHost: example.com\r\n")?;
    let text = screen(&view, 80, 20)?;

    assert!(text.contains("GET /login HTTP/1.1"));
    assert!(text.contains("Host: example.com"));
    Ok(())
}

#[test]
fn test_view_payload_escape_never_reaches_screen_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    tcp_payload(&mut view, b"\x1b[2Jboom")?;
    let text = screen(&view, 80, 20)?;

    assert!(!text.contains('\x1b'));
    assert!(text.contains(".[2Jboom"));
    Ok(())
}

#[test]
fn test_view_stream_appends_in_order_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    tcp_payload(&mut view, b"user=")?;
    tcp_payload(&mut view, b"admin")?;
    udp_packet(&mut view, 1111)?;

    assert_eq!(view.stream(), "user=adminq");
    Ok(())
}

#[test]
fn test_view_stream_shows_newest_rows_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    for i in 0..50 {
        tcp_payload(&mut view, format!("line {i}\n").as_bytes())?;
    }
    let text = screen(&view, 80, 20)?;

    assert!(text.contains("line 49"));
    assert!(!text.contains("line 0 "));
    Ok(())
}

#[test]
fn test_view_stream_bounded_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    let chunk = "é".repeat(700);

    for _ in 0..100 {
        tcp_payload(&mut view, chunk.as_bytes())?;
    }
    tcp_payload(&mut view, b"END")?;

    assert!(
        view.stream().len() <= 64 * 1024,
        "len {}",
        view.stream().len()
    );
    assert!(view.stream().ends_with("END"));
    Ok(())
}

#[test]
fn test_key_clear_empties_stream_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    tcp_payload(&mut view, b"secret")?;

    let flow = key(&mut view, KeyCode::Char('c'));

    assert_eq!(flow, Flow::Continue);
    assert_eq!(view.stream(), "");
    Ok(())
}

#[test]
fn test_key_pause_freezes_view_but_counts_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    udp_packet(&mut view, 1111)?;

    key(&mut view, KeyCode::Char(' '));
    udp_packet(&mut view, 2222)?;
    tcp_payload(&mut view, b"hidden")?;
    let text = screen(&view, 80, 20)?;

    assert!(text.contains("1111"));
    assert!(!text.contains("2222"));
    assert!(!view.stream().contains("hidden"));
    assert!(text.contains("3 packets | paused"));
    Ok(())
}

#[test]
fn test_key_pause_twice_resumes_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    key(&mut view, KeyCode::Char(' '));
    key(&mut view, KeyCode::Char(' '));
    udp_packet(&mut view, 2222)?;
    let text = screen(&view, 80, 20)?;

    assert!(text.contains("2222"));
    assert!(text.contains("| capturing"));
    Ok(())
}

#[test]
fn test_view_bad_packet_clears_payload_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    tcp_payload(&mut view, b"old payload")?;
    let err = YeyoError::Truncated {
        layer: Layer::Tcp,
        needed: 20,
        got: 3,
    };

    view.bad(23, &err);
    let text = screen(&view, 100, 30)?;

    assert_eq!(text.matches("old payload").count(), 1);
    Ok(())
}

#[test]
fn test_lock_follows_conversation_both_directions_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"GET / ")?;

    key(&mut view, KeyCode::Char('f'));
    send(&mut view, OTHER, SERVER, b"noise ")?;
    send(&mut view, SERVER, CLIENT, b"200 OK ")?;
    send(&mut view, CLIENT, OTHER, b"noise ")?;

    assert_eq!(view.stream(), "GET / 200 OK ");
    Ok(())
}

#[test]
fn test_lock_colours_client_and_server_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"REQUEST")?;
    key(&mut view, KeyCode::Char('f'));

    send(&mut view, SERVER, CLIENT, b"RESPONSE")?;
    let buffer = drawn(&view)?;

    assert_eq!(last_color_of(&buffer, "REQUEST"), Some(Color::LightRed));
    assert_eq!(last_color_of(&buffer, "RESPONSE"), Some(Color::LightBlue));
    Ok(())
}

#[test]
fn test_lock_shown_in_filter_bar_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;

    key(&mut view, KeyCode::Char('f'));
    let text = screen(&view, 80, 20)?;

    assert!(text.contains("following TCP 10.0.0.1:51000 <> 10.0.0.2:80"));
    Ok(())
}

#[test]
fn test_lock_ignores_other_traffic_on_screen_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;
    key(&mut view, KeyCode::Char('f'));

    send(&mut view, OTHER, SERVER, b"noise")?;
    udp_packet(&mut view, 1111)?;
    let text = screen(&view, 80, 20)?;

    assert!(text.contains("10.0.0.1:51000 > 10.0.0.2:80 TCP"));
    assert!(!text.contains("noise"));
    assert!(text.contains("3 packets"));
    Ok(())
}

#[test]
fn test_lock_same_ports_other_protocol_ignored_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"tcp ")?;
    key(&mut view, KeyCode::Char('f'));

    let udp = common::udp(CLIENT.1, SERVER.1, b"udp");
    let ip = common::ipv4(17, CLIENT.0, SERVER.0, &udp);
    view.packet(64, &Packet::parse(LinkType::Raw, &ip)?);

    assert_eq!(view.stream(), "tcp ");
    Ok(())
}

#[test]
fn test_lock_ignores_bad_packets_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;
    key(&mut view, KeyCode::Char('f'));
    let err = YeyoError::Truncated {
        layer: Layer::Tcp,
        needed: 20,
        got: 3,
    };

    view.bad(23, &err);
    let text = screen(&view, 100, 20)?;

    assert!(!text.contains("bad packet"));
    assert!(text.contains("2 packets"));
    Ok(())
}

#[test]
fn test_lock_twice_unlocks_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"a")?;

    key(&mut view, KeyCode::Char('f'));
    key(&mut view, KeyCode::Char('f'));
    send(&mut view, OTHER, SERVER, b"b")?;
    let text = screen(&view, 80, 20)?;

    assert_eq!(view.stream(), "b");
    assert!(text.contains("none (f follows"));
    Ok(())
}

#[test]
fn test_lock_without_ports_does_nothing_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    let icmp = common::ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], &[8, 0, 0, 0]);
    view.packet(28, &Packet::parse(LinkType::Raw, &icmp)?);

    key(&mut view, KeyCode::Char('f'));
    send(&mut view, OTHER, SERVER, b"still shown")?;

    assert!(screen(&view, 80, 20)?.contains("still shown"));
    Ok(())
}

#[test]
fn test_lock_before_any_packet_does_nothing_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    key(&mut view, KeyCode::Char('f'));
    send(&mut view, OTHER, SERVER, b"shown")?;

    assert_eq!(view.stream(), "shown");
    Ok(())
}

#[test]
fn test_lock_starts_stream_fresh_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, OTHER, SERVER, b"old ")?;
    send(&mut view, CLIENT, SERVER, b"new")?;

    key(&mut view, KeyCode::Char('f'));

    assert_eq!(view.stream(), "new");
    Ok(())
}

#[test]
fn test_stream_bounded_many_small_chunks_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    for i in 0..20_000 {
        tcp_payload(&mut view, format!("{i:05} ").as_bytes())?;
    }

    assert!(view.stream().len() <= 64 * 1024);
    assert!(view.stream().ends_with("19999 "));
    Ok(())
}

#[test]
fn test_packet_row_coloured_by_protocol_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    udp_packet(&mut view, 1111)?;
    let udp = drawn(&view)?;
    send(&mut view, CLIENT, SERVER, b"x")?;
    let tcp = drawn(&view)?;

    assert_eq!(last_color_of(&udp, "UDP"), Some(Color::LightGreen));
    assert_eq!(last_color_of(&tcp, "TCP"), Some(Color::LightCyan));
    Ok(())
}

#[test]
fn test_packet_row_other_protocol_coloured_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    let icmp = common::ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], &[8, 0, 0, 0]);

    view.packet(28, &Packet::parse(LinkType::Raw, &icmp)?);
    let buffer = drawn(&view)?;

    assert_eq!(
        last_color_of(&buffer, "10.0.0.1"),
        Some(Color::LightMagenta)
    );
    Ok(())
}

#[test]
fn test_bad_packet_shown_red_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    let err = YeyoError::Truncated {
        layer: Layer::Udp,
        needed: 8,
        got: 3,
    };

    view.bad(31, &err);
    let buffer = drawn(&view)?;

    assert_eq!(last_color_of(&buffer, "bad packet"), Some(Color::Red));
    Ok(())
}

#[test]
fn test_footer_state_colours_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    let capturing = drawn(&view)?;
    key(&mut view, KeyCode::Char(' '));
    let paused = drawn(&view)?;
    view.end();
    let ended = drawn(&view)?;

    assert_eq!(last_color_of(&capturing, "capturing"), Some(Color::Green));
    assert_eq!(last_color_of(&paused, "paused"), Some(Color::Yellow));
    assert_eq!(last_color_of(&ended, "ended"), Some(Color::Red));
    Ok(())
}

#[test]
fn test_footer_keys_stand_out_ok() -> Result<(), Box<dyn Error>> {
    let buffer = drawn(&View::default())?;

    assert_eq!(last_color_of(&buffer, "space"), Some(Color::Black));
    assert_eq!(last_color_of(&buffer, "pause"), Some(Color::Gray));
    Ok(())
}

#[test]
fn test_lock_highlights_stream_border_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;
    let before = drawn(&view)?;

    key(&mut view, KeyCode::Char('f'));
    let after = drawn(&view)?;

    assert_eq!(last_color_of(&before, "╰"), Some(Color::DarkGray));
    assert_eq!(last_color_of(&after, "╰"), Some(Color::Yellow));
    Ok(())
}

#[test]
fn test_filter_bar_shows_capture_filter_ok() -> Result<(), Box<dyn Error>> {
    let view = View::new(Some("tcp port 80"));

    let text = screen(&view, 80, 20)?;

    assert!(text.contains("capture tcp port 80"));
    assert!(text.contains("none (f follows"));
    Ok(())
}

#[test]
fn test_filter_bar_without_capture_filter_ok() -> Result<(), Box<dyn Error>> {
    let text = screen(&View::new(None), 80, 20)?;

    assert!(text.contains("capture all packets"));
    Ok(())
}

#[test]
fn test_filter_bar_keeps_capture_filter_while_following_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::new(Some("tcp"));
    send(&mut view, CLIENT, SERVER, b"x")?;

    key(&mut view, KeyCode::Char('f'));
    let text = screen(&view, 100, 20)?;

    assert!(text.contains("capture tcp"));
    assert!(text.contains("following TCP 10.0.0.1:51000 <> 10.0.0.2:80"));
    Ok(())
}

#[test]
fn test_filter_bar_hostile_capture_filter_sanitized_ok() -> Result<(), Box<dyn Error>> {
    let view = View::new(Some("tcp\x1b[2J\nport 80"));

    let text = screen(&view, 80, 20)?;

    assert!(!text.contains('\x1b'));
    assert!(text.contains("capture tcp.[2J port 80"));
    Ok(())
}

#[test]
fn test_filter_bar_capture_filter_coloured_ok() -> Result<(), Box<dyn Error>> {
    let buffer = drawn(&View::new(Some("udp")))?;

    assert_eq!(last_color_of(&buffer, "udp"), Some(Color::White));
    assert_eq!(last_color_of(&buffer, "capture"), Some(Color::Gray));
    Ok(())
}
