mod common;

use std::error::Error;
use yeyo::packet::link::LinkType;
use yeyo::packet::{Endpoints, Packet};
use yeyo::render::{Conversations, Key, Side, Target};

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
fn test_recent_newest_first_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    let other = ([10, 0, 0, 9], 4444);
    record(&mut table, &tcp(CLIENT, SERVER, 0x18, b""), "")?;
    record(&mut table, &tcp(other, SERVER, 0x18, b""), "")?;

    record(&mut table, &tcp(SERVER, CLIENT, 0x18, b""), "")?;

    assert_eq!(
        table.recent(),
        [key_of(6, CLIENT, SERVER), key_of(6, other, SERVER)]
    );
    Ok(())
}

#[test]
fn test_recent_empty_ok() {
    assert!(Conversations::default().recent().is_empty());
}

#[test]
fn test_key_protocol_name_ok() {
    assert_eq!(key_of(6, CLIENT, SERVER).protocol_name(), "TCP");
    assert_eq!(key_of(17, CLIENT, SERVER).protocol_name(), "UDP");
}

fn target_for(
    table: &Conversations,
    key: Key,
    make: fn(Key, &yeyo::render::Conversation) -> Target,
) -> Result<Target, Box<dyn Error>> {
    Ok(make(key, table.get(&key).ok_or("missing conversation")?))
}

#[test]
fn test_target_connection_matches_only_its_key_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    let later = ([10, 0, 0, 1], 51007);
    record(&mut table, &tcp(CLIENT, SERVER, 0x02, b""), "")?;

    let target = target_for(&table, key_of(6, CLIENT, SERVER), Target::connection)?;

    assert!(target.matches(&key_of(6, SERVER, CLIENT)));
    assert!(!target.matches(&key_of(6, later, SERVER)));
    Ok(())
}

#[test]
fn test_target_server_matches_new_client_ports_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    record(&mut table, &tcp(CLIENT, SERVER, 0x02, b""), "")?;

    let target = target_for(&table, key_of(6, CLIENT, SERVER), Target::server)?;

    assert!(target.matches(&key_of(6, ([10, 0, 0, 1], 51007), SERVER)));
    assert!(target.matches(&key_of(6, SERVER, ([10, 0, 0, 1], 60000))));
    Ok(())
}

#[test]
fn test_target_server_rejects_other_port_client_or_protocol_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    record(&mut table, &tcp(CLIENT, SERVER, 0x02, b""), "")?;

    let target = target_for(&table, key_of(6, CLIENT, SERVER), Target::server)?;

    assert!(!target.matches(&key_of(6, CLIENT, ([10, 0, 0, 2], 443))));
    assert!(!target.matches(&key_of(6, ([10, 0, 0, 9], 51000), SERVER)));
    assert!(!target.matches(&key_of(17, CLIENT, SERVER)));
    Ok(())
}

#[test]
fn test_target_server_uses_roles_not_key_order_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    let client = ([10, 0, 0, 200], 51000);
    let server = ([10, 0, 0, 2], 80);
    record(&mut table, &tcp(client, server, 0x02, b""), "")?;

    let target = target_for(&table, key_of(6, client, server), Target::server)?;

    assert!(target.matches(&key_of(6, ([10, 0, 0, 200], 40000), server)));
    Ok(())
}

#[test]
fn test_target_side_on_localhost_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    let client = ([127, 0, 0, 1], 51000);
    let server = ([127, 0, 0, 1], 8080);
    record(&mut table, &tcp(client, server, 0x02, b""), "")?;
    let target = target_for(&table, key_of(6, client, server), Target::server)?;

    let reply = Endpoints {
        protocol: 6,
        src: (server.0, server.1).into(),
        dst: (client.0, client.1).into(),
    };
    let request = Endpoints {
        protocol: 6,
        src: (client.0, 52000).into(),
        dst: (server.0, server.1).into(),
    };

    assert_eq!(target.side(&reply), Side::Server);
    assert_eq!(target.side(&request), Side::Client);
    assert!(target.matches(&key_of(6, ([127, 0, 0, 1], 52000), server)));
    Ok(())
}

#[test]
fn test_matching_oldest_conversation_first_ok() -> Result<(), Box<dyn Error>> {
    let mut table = Conversations::default();
    let second = ([10, 0, 0, 1], 51007);
    record(&mut table, &tcp(CLIENT, SERVER, 0x02, b""), "first")?;
    record(&mut table, &tcp(second, SERVER, 0x02, b""), "second")?;
    record(&mut table, &tcp(CLIENT, SERVER, 0x18, b""), " again")?;

    let target = target_for(&table, key_of(6, CLIENT, SERVER), Target::server)?;
    let texts: Vec<String> = table
        .matching(&target)
        .iter()
        .map(|conversation| conversation.stream().text())
        .collect();

    assert_eq!(texts, ["first again", "second"]);
    Ok(())
}
