mod common;

use std::error::Error;
use yeyo::packet::link::LinkType;
use yeyo::packet::{Endpoints, Packet};
use yeyo::render::{Conversations, Key, Side};

const CLIENT: ([u8; 4], u16) = ([10, 0, 0, 1], 51000);
const SERVER: ([u8; 4], u16) = ([10, 0, 0, 2], 80);

fn tcp(src: ([u8; 4], u16), dst: ([u8; 4], u16), flags: u8, payload: &[u8]) -> Vec<u8> {
    common::ipv4(6, src.0, dst.0, &common::tcp(src.1, dst.1, flags, payload))
}

fn udp(src: ([u8; 4], u16), dst: ([u8; 4], u16), payload: &[u8]) -> Vec<u8> {
    common::ipv4(17, src.0, dst.0, &common::udp(src.1, dst.1, payload))
}

fn record(
    table: &mut Conversations,
    bytes: &[u8],
    text: &str,
) -> Result<Option<(Key, Side)>, Box<dyn Error>> {
    let packet = Packet::parse(LinkType::Raw, bytes)?;
    Ok(table.record(&packet, 100, text))
}

fn key_of(protocol: u8, src: ([u8; 4], u16), dst: ([u8; 4], u16)) -> Key {
    Key::new(Endpoints {
        protocol,
        src: (src.0, src.1).into(),
        dst: (dst.0, dst.1).into(),
    })
}

#[test]
fn test_key_same_for_both_directions_ok() {
    assert_eq!(key_of(6, CLIENT, SERVER), key_of(6, SERVER, CLIENT));
}

#[test]
fn test_key_differs_by_protocol_ok() {
    assert_ne!(key_of(6, CLIENT, SERVER), key_of(17, CLIENT, SERVER));
}

#[test]
fn test_record_both_directions_one_entry_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();

    let request = record(&mut table, &tcp(CLIENT, SERVER, 0x18, b"GET"), "GET")?;
    let reply = record(&mut table, &tcp(SERVER, CLIENT, 0x18, b"OK"), "OK")?;

    let key = key_of(6, CLIENT, SERVER);
    let conversation = table.get(&key).ok_or("missing conversation")?;
    assert_eq!(table.len(), 1);
    assert_eq!(request, Some((key, Side::Client)));
    assert_eq!(reply, Some((key, Side::Server)));
    assert_eq!(conversation.packets(), 2);
    assert_eq!(conversation.bytes(), 200);
    assert_eq!(
        conversation.stream().parts(),
        [(Some(Side::Client), "GET"), (Some(Side::Server), "OK")]
    );
    Ok(())
}

#[test]
fn test_record_tcp_and_udp_kept_apart_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();

    record(&mut table, &tcp(CLIENT, SERVER, 0x18, b""), "")?;
    record(&mut table, &udp(CLIENT, SERVER, b""), "")?;

    assert_eq!(table.len(), 2);
    Ok(())
}

#[test]
fn test_roles_syn_sender_is_client_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();

    record(&mut table, &tcp(CLIENT, SERVER, 0x02, b""), "")?;

    let conversation = table.get(&key_of(6, CLIENT, SERVER)).ok_or("missing")?;
    assert_eq!(conversation.client(), (CLIENT.0, CLIENT.1).into());
    assert_eq!(conversation.server(), (SERVER.0, SERVER.1).into());
    Ok(())
}

#[test]
fn test_roles_syn_ack_seen_first_sender_is_server_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();

    let first = record(&mut table, &tcp(SERVER, CLIENT, 0x12, b""), "")?;

    let conversation = table.get(&key_of(6, CLIENT, SERVER)).ok_or("missing")?;
    assert_eq!(conversation.client(), (CLIENT.0, CLIENT.1).into());
    assert_eq!(first.map(|(_, side)| side), Some(Side::Server));
    Ok(())
}

#[test]
fn test_roles_first_seen_is_client_without_syn_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();

    record(&mut table, &udp(SERVER, CLIENT, b""), "")?;

    let conversation = table.get(&key_of(17, CLIENT, SERVER)).ok_or("missing")?;
    assert_eq!(conversation.client(), (SERVER.0, SERVER.1).into());
    Ok(())
}

#[test]
fn test_roles_fixed_after_first_packet_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    record(&mut table, &tcp(CLIENT, SERVER, 0x02, b""), "")?;

    let later = record(&mut table, &tcp(SERVER, CLIENT, 0x02, b""), "")?;

    assert_eq!(later.map(|(_, side)| side), Some(Side::Server));
    Ok(())
}

#[test]
fn test_record_without_ports_none_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    let icmp = common::ipv4(1, CLIENT.0, SERVER.0, &[8, 0, 0, 0]);
    let arp = common::ethernet(0x0806, &[0; 28]);

    let from_icmp = record(&mut table, &icmp, "")?;
    let from_arp = table.record(&Packet::parse(LinkType::Ethernet, &arp)?, 42, "");

    assert_eq!(from_icmp, None);
    assert_eq!(from_arp, None);
    assert!(table.is_empty());
    Ok(())
}

#[test]
fn test_evicts_quietest_when_full_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    for port in 1..=128 {
        record(
            &mut table,
            &tcp(([10, 0, 0, 9], port), SERVER, 0x18, b""),
            "",
        )?;
    }
    record(&mut table, &tcp(([10, 0, 0, 9], 1), SERVER, 0x18, b""), "")?;

    record(&mut table, &tcp(CLIENT, SERVER, 0x18, b""), "")?;

    assert_eq!(table.len(), 128);
    assert!(table.get(&key_of(6, ([10, 0, 0, 9], 1), SERVER)).is_some());
    assert!(table.get(&key_of(6, ([10, 0, 0, 9], 2), SERVER)).is_none());
    assert!(table.get(&key_of(6, CLIENT, SERVER)).is_some());
    Ok(())
}

#[test]
fn test_pinned_survives_eviction_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    record(&mut table, &tcp(CLIENT, SERVER, 0x18, b""), "")?;
    table.pin(Some(key_of(6, CLIENT, SERVER)));

    for port in 1..=300 {
        record(
            &mut table,
            &tcp(([10, 0, 0, 9], port), SERVER, 0x18, b""),
            "",
        )?;
    }

    assert_eq!(table.len(), 128);
    assert!(table.get(&key_of(6, CLIENT, SERVER)).is_some());
    Ok(())
}

#[test]
fn test_unpinned_can_be_evicted_again_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    record(&mut table, &tcp(CLIENT, SERVER, 0x18, b""), "")?;
    table.pin(Some(key_of(6, CLIENT, SERVER)));
    table.pin(None);

    for port in 1..=128 {
        record(
            &mut table,
            &tcp(([10, 0, 0, 9], port), SERVER, 0x18, b""),
            "",
        )?;
    }

    assert!(table.get(&key_of(6, CLIENT, SERVER)).is_none());
    Ok(())
}

#[test]
fn test_flood_stays_bounded_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();

    for port in 0..10_000u16 {
        record(&mut table, &udp(([10, 0, 0, 9], port), SERVER, b"x"), "x")?;
    }

    assert_eq!(table.len(), 128);
    Ok(())
}

#[test]
fn test_huge_payload_capped_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    let text = "x".repeat(200_000);

    record(&mut table, &tcp(CLIENT, SERVER, 0x18, b""), &text)?;

    let conversation = table.get(&key_of(6, CLIENT, SERVER)).ok_or("missing")?;
    assert_eq!(conversation.stream().len(), 64 * 1024);
    Ok(())
}

#[test]
fn test_clear_empties_only_stream_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    record(&mut table, &tcp(CLIENT, SERVER, 0x18, b"a"), "a")?;
    let key = key_of(6, CLIENT, SERVER);

    table.get_mut(&key).ok_or("missing")?.clear();

    let conversation = table.get(&key).ok_or("missing")?;
    assert!(conversation.stream().is_empty());
    assert_eq!(conversation.packets(), 1);
    Ok(())
}
