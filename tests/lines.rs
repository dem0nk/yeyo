mod common;

use std::error::Error;
use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::Packet;
use yeyo::packet::link::LinkType;
use yeyo::render::Lines;

fn at(micros: u64) -> Option<SystemTime> {
    Some(UNIX_EPOCH + Duration::from_secs(1_700_000_000) + Duration::from_micros(micros))
}

fn render(link_type: LinkType, bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    let packet = Packet::parse(link_type, bytes)?;
    let mut out = Vec::new();
    Lines::new(&mut out).packet(at(0), 99, &packet)?;
    Ok(String::from_utf8(out)?)
}

fn tcp_line(flags: u8) -> Result<String, Box<dyn Error>> {
    let tcp = common::tcp(51000, 80, flags, &[]);
    let ip = common::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &tcp);
    render(LinkType::Raw, &ip)
}

#[test]
fn test_line_ipv4_tcp_ok() -> Result<(), Box<dyn Error>> {
    let line = tcp_line(0x02)?;

    assert_eq!(line, "0.000000 10.0.0.1:51000 > 10.0.0.2:80 TCP [S] len 99\n");
    Ok(())
}

#[test]
fn test_line_ipv6_udp_brackets_ok() -> Result<(), Box<dyn Error>> {
    let udp = common::udp(5353, 53, b"q");
    let ip = common::ipv6(17, Ipv6Addr::LOCALHOST, "2001:db8::1".parse()?, &udp);

    let line = render(LinkType::Raw, &ip)?;

    assert_eq!(line, "0.000000 [::1]:5353 > [2001:db8::1]:53 UDP len 99\n");
    Ok(())
}

#[test]
fn test_line_tcp_flags_order_ok() -> Result<(), Box<dyn Error>> {
    assert!(tcp_line(0x12)?.contains("TCP [SA]"));
    assert!(tcp_line(0x18)?.contains("TCP [PA]"));
    assert!(tcp_line(0x11)?.contains("TCP [FA]"));
    assert!(tcp_line(0x04)?.contains("TCP [R]"));
    assert!(tcp_line(0xff)?.contains("TCP [FSRPAUEW]"));
    Ok(())
}

#[test]
fn test_line_tcp_no_flags_ok() -> Result<(), Box<dyn Error>> {
    assert!(tcp_line(0x00)?.contains("TCP [none]"));
    Ok(())
}

#[test]
fn test_line_unknown_protocol_ok() -> Result<(), Box<dyn Error>> {
    let ip = common::ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], &[8, 0, 0, 0]);

    let line = render(LinkType::Raw, &ip)?;

    assert_eq!(line, "0.000000 10.0.0.1 > 10.0.0.2 proto 1 len 99\n");
    Ok(())
}

#[test]
fn test_line_later_fragment_ok() -> Result<(), Box<dyn Error>> {
    let mut ip = common::ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], &[0; 8]);
    ip[6..8].copy_from_slice(&0x00b9u16.to_be_bytes());

    let line = render(LinkType::Raw, &ip)?;

    assert_eq!(line, "0.000000 10.0.0.1 > 10.0.0.2 fragment proto 17 len 99\n");
    Ok(())
}

#[test]
fn test_line_non_ip_ethertype_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::ethernet(0x0806, &[0; 28]);

    let line = render(LinkType::Ethernet, &bytes)?;

    assert_eq!(line, "0.000000 ethertype 0x0806 len 99\n");
    Ok(())
}

#[test]
fn test_line_time_relative_to_first_ok() -> Result<(), Box<dyn Error>> {
    let ip = common::ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    let packet = Packet::parse(LinkType::Raw, &ip)?;
    let mut out = Vec::new();
    let mut lines = Lines::new(&mut out);

    lines.packet(at(5_000_000), 1, &packet)?;
    lines.packet(at(6_500_001), 1, &packet)?;
    lines.packet(at(4_999_999), 1, &packet)?;
    lines.packet(None, 1, &packet)?;

    let text = String::from_utf8(out)?;
    let times: Vec<&str> = text.lines().filter_map(|l| l.split(' ').next()).collect();
    assert_eq!(times, ["0.000000", "1.500001", "-0.000001", "?"]);
    Ok(())
}

#[test]
fn test_line_untimed_first_does_not_set_start_ok() -> Result<(), Box<dyn Error>> {
    let ip = common::ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    let packet = Packet::parse(LinkType::Raw, &ip)?;
    let mut out = Vec::new();
    let mut lines = Lines::new(&mut out);

    lines.packet(None, 1, &packet)?;
    lines.packet(at(7), 1, &packet)?;

    let text = String::from_utf8(out)?;
    let times: Vec<&str> = text.lines().filter_map(|l| l.split(' ').next()).collect();
    assert_eq!(times, ["?", "0.000000"]);
    Ok(())
}

#[test]
fn test_line_bad_packet_ok() -> Result<(), Box<dyn Error>> {
    let err = YeyoError::Truncated {
        layer: Layer::Tcp,
        needed: 20,
        got: 4,
    };
    let mut out = Vec::new();

    Lines::new(&mut out).bad(at(0), 58, &err)?;

    assert_eq!(
        String::from_utf8(out)?,
        "0.000000 bad packet: truncated TCP header: needed 20 bytes, got 4, len 58\n"
    );
    Ok(())
}

#[test]
fn test_line_write_failure_err() -> Result<(), Box<dyn Error>> {
    let ip = common::ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    let packet = Packet::parse(LinkType::Raw, &ip)?;
    let mut full = [0u8; 4];

    let result = Lines::new(&mut full[..]).packet(at(0), 1, &packet);

    assert_eq!(result.map_err(|e| e.kind()), Err(std::io::ErrorKind::WriteZero));
    Ok(())
}
