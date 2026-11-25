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

fn follow(view: &mut View) {
    key(view, KeyCode::Char('f'));
    key(view, KeyCode::Enter);
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

    follow(&mut view);
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
    follow(&mut view);

    send(&mut view, SERVER, CLIENT, b"RESPONSE")?;
    let buffer = drawn(&view)?;

    assert_eq!(last_color_of(&buffer, "REQUEST"), Some(Color::Indexed(180)));
    assert_eq!(
        last_color_of(&buffer, "RESPONSE"),
        Some(Color::Indexed(110))
    );
    Ok(())
}

#[test]
fn test_lock_shown_in_filter_bar_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;

    follow(&mut view);
    let text = screen(&view, 80, 20)?;

    assert!(text.contains("following TCP 10.0.0.1:51000 <> 10.0.0.2:80"));
    Ok(())
}

#[test]
fn test_lock_ignores_other_traffic_on_screen_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;
    follow(&mut view);

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
    follow(&mut view);

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
    follow(&mut view);
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

    follow(&mut view);
    key(&mut view, KeyCode::Char('f'));
    send(&mut view, OTHER, SERVER, b"b")?;
    let text = screen(&view, 80, 20)?;

    assert_eq!(view.stream(), "ab");
    assert!(text.contains("none (f picks"));
    Ok(())
}

#[test]
fn test_lock_starts_stream_fresh_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, OTHER, SERVER, b"old ")?;
    send(&mut view, CLIENT, SERVER, b"new")?;

    follow(&mut view);

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

    follow(&mut view);
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
    assert!(text.contains("none (f picks"));
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

    follow(&mut view);
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

#[test]
fn test_follow_shows_history_before_f_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"GET ")?;
    send(&mut view, OTHER, SERVER, b"noise ")?;
    send(&mut view, SERVER, CLIENT, b"200 ")?;

    follow(&mut view);

    assert_eq!(view.stream(), "GET 200 ");
    Ok(())
}

#[test]
fn test_live_stream_coloured_by_side_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    send(&mut view, CLIENT, SERVER, b"REQUEST")?;
    send(&mut view, SERVER, CLIENT, b"RESPONSE")?;
    let buffer = drawn(&view)?;

    assert_eq!(last_color_of(&buffer, "REQUEST"), Some(Color::Indexed(180)));
    assert_eq!(
        last_color_of(&buffer, "RESPONSE"),
        Some(Color::Indexed(110))
    );
    Ok(())
}

#[test]
fn test_clear_while_following_clears_only_that_conversation_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"a")?;
    send(&mut view, OTHER, SERVER, b"b")?;
    send(&mut view, CLIENT, SERVER, b"c")?;
    follow(&mut view);

    key(&mut view, KeyCode::Char('c'));
    let followed = view.stream();
    key(&mut view, KeyCode::Char('f'));

    assert_eq!(followed, "");
    assert_eq!(view.stream(), "abc");
    Ok(())
}

#[test]
fn test_clear_live_keeps_conversation_history_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"a")?;

    key(&mut view, KeyCode::Char('c'));
    let live = view.stream();
    follow(&mut view);

    assert_eq!(live, "");
    assert_eq!(view.stream(), "a");
    Ok(())
}

#[test]
fn test_follow_survives_conversation_flood_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;
    follow(&mut view);

    for port in 1..=300 {
        send(&mut view, (OTHER.0, port), SERVER, b"scan")?;
    }
    send(&mut view, SERVER, CLIENT, b"y")?;
    let text = screen(&view, 100, 20)?;

    assert_eq!(view.stream(), "xy");
    assert!(text.contains("following TCP 10.0.0.1:51000 <> 10.0.0.2:80"));
    Ok(())
}

#[test]
fn test_paused_records_nothing_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"a")?;

    key(&mut view, KeyCode::Char(' '));
    send(&mut view, CLIENT, SERVER, b"b")?;
    key(&mut view, KeyCode::Char(' '));
    follow(&mut view);

    assert_eq!(view.stream(), "a");
    Ok(())
}

fn text_of(view: &View) -> Result<String, Box<dyn Error>> {
    screen(view, 100, 30)
}

#[test]
fn test_picker_empty_shows_message_and_stays_open_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    let icmp = common::ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], &[8, 0, 0, 0]);
    view.packet(28, &Packet::parse(LinkType::Raw, &icmp)?);

    follow(&mut view);
    let text = text_of(&view)?;

    assert!(text.contains("no conversations yet"));
    assert!(text.contains("esc  close"));
    Ok(())
}

#[test]
fn test_picker_lists_newest_first_with_counts_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"a")?;
    send(&mut view, OTHER, SERVER, b"b")?;

    key(&mut view, KeyCode::Char('f'));
    let text = text_of(&view)?;

    let other = text
        .find("TCP 10.0.0.9:4444 <> 10.0.0.2:80")
        .ok_or("other row missing")?;
    let client = text
        .find("TCP 10.0.0.1:51000 <> 10.0.0.2:80")
        .ok_or("client row missing")?;
    assert!(other < client);
    assert!(text.contains("1 pkts  64 B"));
    Ok(())
}

#[test]
fn test_picker_preselects_conversation_on_screen_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, OTHER, SERVER, b"other ")?;
    send(&mut view, CLIENT, SERVER, b"mine ")?;
    send(&mut view, OTHER, SERVER, b"other ")?;
    send(&mut view, CLIENT, SERVER, b"mine ")?;

    follow(&mut view);

    assert_eq!(view.stream(), "mine mine ");
    Ok(())
}

#[test]
fn test_picker_starts_at_top_without_ports_on_screen_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"old ")?;
    send(&mut view, OTHER, SERVER, b"new ")?;
    let icmp = common::ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], &[8, 0, 0, 0]);
    view.packet(28, &Packet::parse(LinkType::Raw, &icmp)?);

    follow(&mut view);

    assert_eq!(view.stream(), "new ");
    Ok(())
}

#[test]
fn test_picker_moves_and_follows_selected_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"client ")?;
    send(&mut view, OTHER, SERVER, b"other ")?;

    key(&mut view, KeyCode::Char('f'));
    key(&mut view, KeyCode::Down);
    key(&mut view, KeyCode::Enter);
    let text = text_of(&view)?;

    assert_eq!(view.stream(), "client ");
    assert!(text.contains("following TCP 10.0.0.1:51000 <> 10.0.0.2:80"));
    Ok(())
}

#[test]
fn test_picker_j_k_move_like_arrows_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"client ")?;
    send(&mut view, OTHER, SERVER, b"other ")?;

    key(&mut view, KeyCode::Char('f'));
    key(&mut view, KeyCode::Char('j'));
    key(&mut view, KeyCode::Char('k'));
    key(&mut view, KeyCode::Enter);

    assert_eq!(view.stream(), "other ");
    Ok(())
}

#[test]
fn test_picker_stops_at_both_ends_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"client ")?;
    send(&mut view, OTHER, SERVER, b"other ")?;

    key(&mut view, KeyCode::Char('f'));
    key(&mut view, KeyCode::Up);
    key(&mut view, KeyCode::Up);
    key(&mut view, KeyCode::Enter);
    let top = view.stream();
    key(&mut view, KeyCode::Char('f'));
    key(&mut view, KeyCode::Char('f'));
    for _ in 0..5 {
        key(&mut view, KeyCode::Down);
    }
    key(&mut view, KeyCode::Enter);

    assert_eq!(top, "other ");
    assert_eq!(view.stream(), "client ");
    Ok(())
}

#[test]
fn test_picker_esc_closes_without_quitting_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;
    key(&mut view, KeyCode::Char('f'));

    let flow = key(&mut view, KeyCode::Esc);
    let text = text_of(&view)?;

    assert_eq!(flow, Flow::Continue);
    assert!(!text.contains(" conversations "));
    assert!(text.contains("none (f picks"));
    Ok(())
}

#[test]
fn test_picker_f_closes_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;

    key(&mut view, KeyCode::Char('f'));
    key(&mut view, KeyCode::Char('f'));

    assert!(!text_of(&view)?.contains(" conversations "));
    Ok(())
}

#[test]
fn test_picker_q_and_ctrl_c_still_quit_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;

    key(&mut view, KeyCode::Char('f'));
    let q = key(&mut view, KeyCode::Char('q'));
    let ctrl_c = view.key(press(KeyCode::Char('c'), KeyModifiers::CONTROL));

    assert_eq!(q, Flow::Quit);
    assert_eq!(ctrl_c, Flow::Quit);
    Ok(())
}

#[test]
fn test_picker_snapshot_stable_while_packets_arrive_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"client ")?;
    send(&mut view, OTHER, SERVER, b"other ")?;
    key(&mut view, KeyCode::Char('f'));
    key(&mut view, KeyCode::Down);

    send(&mut view, CLIENT, SERVER, b"more ")?;
    send(&mut view, ([10, 0, 0, 7], 7777), SERVER, b"new ")?;
    key(&mut view, KeyCode::Enter);

    assert_eq!(view.stream(), "client more ");
    Ok(())
}

#[test]
fn test_picker_evicted_row_cannot_be_followed_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;
    key(&mut view, KeyCode::Char('f'));

    for port in 1..=200 {
        send(&mut view, (OTHER.0, port), SERVER, b"scan")?;
    }
    key(&mut view, KeyCode::Enter);
    let text = text_of(&view)?;

    assert!(text.contains("(gone)"));
    assert!(text.contains(" conversations "));
    assert!(!text.contains("following"));
    Ok(())
}

#[test]
fn test_picker_rows_coloured_and_selected_highlighted_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;
    send(&mut view, OTHER, SERVER, b"y")?;

    key(&mut view, KeyCode::Char('f'));
    let buffer = drawn(&view)?;

    assert_eq!(
        last_color_of(&buffer, "10.0.0.1:51000"),
        Some(Color::Indexed(180))
    );
    let marker = buffer
        .content
        .iter()
        .find(|cell| cell.symbol() == "▶")
        .ok_or("no selection marker")?;
    assert_eq!(marker.bg, Color::Cyan);
    assert_eq!(marker.fg, Color::Black);
    assert_eq!(last_color_of(&buffer, "10.0.0.9:4444"), Some(Color::Black));
    Ok(())
}

#[test]
fn test_picker_many_rows_keeps_selection_visible_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    for port in 1..=100 {
        send(&mut view, (OTHER.0, port), SERVER, b"x")?;
    }

    key(&mut view, KeyCode::Char('f'));
    for _ in 0..99 {
        key(&mut view, KeyCode::Down);
    }
    let text = text_of(&view)?;

    assert!(text.contains("▶ TCP 10.0.0.9:1 <> 10.0.0.2:80"));
    Ok(())
}

#[test]
fn test_picker_tiny_terminal_no_panic_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;
    key(&mut view, KeyCode::Char('f'));

    for (width, height) in [(1, 1), (10, 5), (3, 40), (200, 2)] {
        screen(&view, width, height)?;
    }
    Ok(())
}

#[test]
fn test_picker_footer_shows_picker_keys_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    key(&mut view, KeyCode::Char('f'));
    let text = text_of(&view)?;

    assert!(text.contains("enter  follow"));
    assert!(!text.contains("space  pause"));
    Ok(())
}

const LATER: ([u8; 4], u16) = ([10, 0, 0, 1], 51007);

fn follow_server(view: &mut View) {
    key(view, KeyCode::Char('f'));
    key(view, KeyCode::Char('s'));
}

#[test]
fn test_server_follow_merges_earlier_connections_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"GET1 ")?;
    send(&mut view, SERVER, CLIENT, b"OK1 ")?;
    send(&mut view, LATER, SERVER, b"GET2 ")?;
    send(&mut view, SERVER, LATER, b"OK2 ")?;

    follow_server(&mut view);

    assert_eq!(view.stream(), "GET1 OK1 GET2 OK2 ");
    Ok(())
}

#[test]
fn test_server_follow_includes_new_connections_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"GET1 ")?;
    follow_server(&mut view);

    send(&mut view, LATER, SERVER, b"GET2 ")?;
    send(&mut view, SERVER, LATER, b"OK2 ")?;
    let buffer = drawn(&view)?;

    assert_eq!(view.stream(), "GET1 GET2 OK2 ");
    assert_eq!(last_color_of(&buffer, "GET2"), Some(Color::Indexed(180)));
    assert_eq!(last_color_of(&buffer, "OK2"), Some(Color::Indexed(110)));
    Ok(())
}

#[test]
fn test_server_follow_excludes_other_port_and_client_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"mine ")?;
    follow_server(&mut view);

    send(&mut view, LATER, (SERVER.0, 443), b"tls ")?;
    send(&mut view, OTHER, SERVER, b"other ")?;
    let udp = common::udp(LATER.1, SERVER.1, b"udp ");
    view.packet(
        64,
        &Packet::parse(LinkType::Raw, &common::ipv4(17, LATER.0, SERVER.0, &udp))?,
    );

    assert_eq!(view.stream(), "mine ");
    Ok(())
}

#[test]
fn test_server_follow_shown_in_filter_bar_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"x")?;

    follow_server(&mut view);
    let text = text_of(&view)?;

    assert!(text.contains("following server TCP 10.0.0.1 > 10.0.0.2:80"));
    Ok(())
}

#[test]
fn test_enter_still_follows_one_connection_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"GET1 ")?;
    follow(&mut view);

    send(&mut view, LATER, SERVER, b"GET2 ")?;

    assert_eq!(view.stream(), "GET1 ");
    Ok(())
}

#[test]
fn test_server_follow_clear_then_continues_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    send(&mut view, CLIENT, SERVER, b"old ")?;
    follow_server(&mut view);

    key(&mut view, KeyCode::Char('c'));
    send(&mut view, LATER, SERVER, b"new ")?;

    assert_eq!(view.stream(), "new ");
    Ok(())
}

#[test]
fn test_server_follow_history_capped_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    let chunk = vec![b'x'; 1000];
    for port in 1..=100 {
        send(&mut view, ([10, 0, 0, 1], port), SERVER, &chunk)?;
    }

    follow_server(&mut view);

    assert_eq!(view.stream().len(), 64 * 1024);
    Ok(())
}

#[test]
fn test_picker_footer_shows_server_key_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    key(&mut view, KeyCode::Char('f'));

    assert!(text_of(&view)?.contains("s  server"));
    Ok(())
}

#[test]
fn test_server_follow_on_empty_picker_does_nothing_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    follow_server(&mut view);
    let text = text_of(&view)?;

    assert!(text.contains("no conversations yet"));
    assert!(!text.contains("following"));
    Ok(())
}

fn numbered(view: &mut View, from: usize, to: usize) -> Result<(), Box<dyn Error>> {
    let text: Vec<String> = (from..to).map(|n| format!("line {n:02}")).collect();
    tcp_payload(view, text.join("\n").as_bytes())
}

fn scrolled_screen(view: &mut View, keys: &[KeyCode]) -> Result<String, Box<dyn Error>> {
    screen(view, 80, 20)?;
    for &code in keys {
        key(view, code);
        screen(view, 80, 20)?;
    }
    screen(view, 80, 20)
}

#[test]
fn test_scroll_live_shows_newest_rows_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;

    let text = scrolled_screen(&mut view, &[])?;

    assert!(text.contains("line 29"));
    assert!(text.contains("line 24"));
    assert!(!text.contains("line 23"));
    assert!(!text.contains("scrolled"));
    Ok(())
}

#[test]
fn test_scroll_up_shows_older_row_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;

    let text = scrolled_screen(&mut view, &[KeyCode::Up])?;

    assert!(text.contains("line 23"));
    assert!(!text.contains("line 29"));
    assert!(text.contains("scrolled · End = live"));
    Ok(())
}

#[test]
fn test_scroll_k_j_like_arrows_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;

    let up = scrolled_screen(&mut view, &[KeyCode::Char('k'), KeyCode::Char('k')])?;
    let down = scrolled_screen(&mut view, &[KeyCode::Char('j')])?;

    assert!(up.contains("line 22") && !up.contains("line 28"));
    assert!(down.contains("line 23") && !down.contains("line 29"));
    Ok(())
}

#[test]
fn test_scroll_end_returns_to_live_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;

    let text = scrolled_screen(&mut view, &[KeyCode::PageUp, KeyCode::Up, KeyCode::End])?;

    assert!(text.contains("line 29"));
    assert!(!text.contains("scrolled"));
    Ok(())
}

#[test]
fn test_scroll_position_kept_when_new_data_arrives_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;
    scrolled_screen(&mut view, &[KeyCode::Up])?;

    tcp_payload(&mut view, b"\n")?;
    numbered(&mut view, 30, 40)?;
    let text = scrolled_screen(&mut view, &[])?;

    assert!(text.contains("line 23"));
    assert!(!text.contains("line 39"));
    assert!(text.contains("scrolled"));
    Ok(())
}

#[test]
fn test_scroll_live_follows_new_data_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;
    scrolled_screen(&mut view, &[])?;

    tcp_payload(&mut view, b"\n")?;
    numbered(&mut view, 30, 40)?;
    let text = scrolled_screen(&mut view, &[])?;

    assert!(text.contains("line 39"));
    Ok(())
}

#[test]
fn test_scroll_home_shows_oldest_and_up_clamps_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;

    let text = scrolled_screen(&mut view, &[KeyCode::Home, KeyCode::Up, KeyCode::Up])?;
    let g = scrolled_screen(&mut view, &[KeyCode::End, KeyCode::Char('g')])?;

    assert!(text.contains("line 00"));
    assert!(!text.contains("line 06"));
    assert!(g.contains("line 00"));
    Ok(())
}

#[test]
fn test_scroll_down_past_bottom_goes_live_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;

    let text = scrolled_screen(
        &mut view,
        &[KeyCode::Up, KeyCode::Up, KeyCode::Down, KeyCode::Down],
    )?;
    let more = scrolled_screen(&mut view, &[KeyCode::Down, KeyCode::Down])?;

    assert!(text.contains("line 29"));
    assert!(!text.contains("scrolled"));
    assert!(more.contains("line 29"));
    Ok(())
}

#[test]
fn test_scroll_page_up_and_down_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;

    let up = scrolled_screen(&mut view, &[KeyCode::PageUp])?;
    let down = scrolled_screen(&mut view, &[KeyCode::PageDown])?;

    assert!(up.contains("line 18") && up.contains("line 23"));
    assert!(!up.contains("line 24"));
    assert!(down.contains("line 29"));
    assert!(!down.contains("scrolled"));
    Ok(())
}

#[test]
fn test_scroll_reset_by_clear_and_follow_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;

    let cleared = scrolled_screen(&mut view, &[KeyCode::Up, KeyCode::Char('c')])?;
    numbered(&mut view, 0, 30)?;
    let followed = scrolled_screen(
        &mut view,
        &[KeyCode::Up, KeyCode::Char('f'), KeyCode::Enter],
    )?;
    let unfollowed = scrolled_screen(&mut view, &[KeyCode::Up, KeyCode::Char('f')])?;

    assert!(!cleared.contains("scrolled"));
    assert!(!followed.contains("scrolled"));
    assert!(followed.contains("line 29"));
    assert!(!unfollowed.contains("scrolled"));
    Ok(())
}

#[test]
fn test_scroll_picker_arrows_do_not_scroll_stream_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;

    let text = scrolled_screen(&mut view, &[KeyCode::Char('f'), KeyCode::Up, KeyCode::Esc])?;

    assert!(text.contains("line 29"));
    assert!(!text.contains("scrolled"));
    Ok(())
}

#[test]
fn test_scroll_short_or_empty_stream_stays_live_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();

    let empty = scrolled_screen(&mut view, &[KeyCode::Up, KeyCode::Home, KeyCode::PageUp])?;
    numbered(&mut view, 0, 3)?;
    let short = scrolled_screen(&mut view, &[KeyCode::Up, KeyCode::Home])?;

    assert!(!empty.contains("scrolled"));
    assert!(!short.contains("scrolled"));
    assert!(short.contains("line 00") && short.contains("line 02"));
    Ok(())
}

#[test]
fn test_scroll_tiny_terminal_no_panic_ok() -> Result<(), Box<dyn Error>> {
    let mut view = View::default();
    numbered(&mut view, 0, 30)?;

    for (width, height) in [(1, 1), (10, 5), (3, 40), (200, 2)] {
        screen(&view, width, height)?;
        for code in [
            KeyCode::PageUp,
            KeyCode::Up,
            KeyCode::Home,
            KeyCode::PageDown,
            KeyCode::End,
        ] {
            key(&mut view, code);
            screen(&view, width, height)?;
        }
    }
    Ok(())
}

#[test]
fn test_footer_status_visible_with_all_keys_ok() -> Result<(), Box<dyn Error>> {
    let text = screen(&View::default(), 60, 20)?;

    assert!(text.contains("0 packets | capturing"));
    Ok(())
}
