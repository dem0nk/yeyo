use crate::common;
use std::error::Error;
use std::net::Ipv6Addr;
use yeyo::filter::Filter;
use yeyo::packet::Packet;
use yeyo::packet::link::LinkType;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const CLIENT: [u8; 4] = [10, 0, 0, 1];
const SERVER: [u8; 4] = [192, 168, 1, 2];
const LOGIN: &[u8] = b"POST /login HTTP/1.1\r\nHost: Example.COM\r\n\r\nuser=bob";

fn tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    common::ipv4(
        PROTO_TCP,
        CLIENT,
        SERVER,
        &common::tcp(src_port, dst_port, 0x18, payload),
    )
}

fn udp(src_port: u16, dst_port: u16) -> Vec<u8> {
    common::ipv4(
        PROTO_UDP,
        CLIENT,
        SERVER,
        &common::udp(src_port, dst_port, &[]),
    )
}

fn icmp() -> Vec<u8> {
    common::ipv4(PROTO_ICMP, CLIENT, SERVER, &[8, 0, 0, 0])
}

fn v6_tcp() -> Result<Vec<u8>, Box<dyn Error>> {
    let src: Ipv6Addr = "2001:db8::1".parse()?;
    let dst: Ipv6Addr = "fe80::2".parse()?;
    Ok(common::ipv6(
        PROTO_TCP,
        src,
        dst,
        &common::tcp(5000, 443, 0x02, &[]),
    ))
}

fn matches(expr: &str, bytes: &[u8]) -> Result<bool, Box<dyn Error>> {
    let filter = Filter::parse(expr)?;
    let packet = Packet::parse(LinkType::Raw, bytes)?;
    Ok(filter.matches(&packet))
}

fn check(expr: &str, bytes: &[u8], want: bool) -> Result<(), Box<dyn Error>> {
    assert_eq!(matches(expr, bytes)?, want, "filter {expr:?}");
    Ok(())
}

#[test]
fn test_eval_presence_fields_ok() -> Result<(), Box<dyn Error>> {
    check("ip", &icmp(), true)?;
    check("tcp", &tcp(1, 2, &[]), true)?;
    check("tcp", &udp(1, 2), false)?;
    check("udp", &udp(1, 2), true)?;
    check("udp", &icmp(), false)?;
    check("http", &tcp(51000, 80, LOGIN), true)?;
    check("http", &tcp(51000, 80, b"hello"), false)
}

#[test]
fn test_eval_ip_fields_ok() -> Result<(), Box<dyn Error>> {
    let packet = tcp(1, 2, &[]);

    check("ip.src == 10.0.0.1", &packet, true)?;
    check("ip.src == 192.168.1.2", &packet, false)?;
    check("ip.dst == 192.168.1.2", &packet, true)?;
    check("ip.addr == 10.0.0.1", &packet, true)?;
    check("ip.addr == 192.168.1.2", &packet, true)?;
    check("ip.addr == 8.8.8.8", &packet, false)
}

#[test]
fn test_eval_cidr_ok() -> Result<(), Box<dyn Error>> {
    let packet = tcp(1, 2, &[]);

    check("ip.src == 10.0.0.0/8", &packet, true)?;
    check("ip.src == 11.0.0.0/8", &packet, false)?;
    check("ip.src == 0.0.0.0/0", &packet, true)?;
    check("ip.src == 10.0.0.1/32", &packet, true)?;
    check("ip.src == 10.0.0.0/32", &packet, false)?;
    check("ip.src == 10.0.0.0/31", &packet, true)?;
    check("ip.dst == 192.168.0.0/16", &packet, true)
}

#[test]
fn test_eval_ipv6_ok() -> Result<(), Box<dyn Error>> {
    let packet = v6_tcp()?;

    check("ip.src == 2001:db8::1", &packet, true)?;
    check("ip.src == 2001:db8::/32", &packet, true)?;
    check("ip.src == 2001:db9::/32", &packet, false)?;
    check("ip.src == ::/0", &packet, true)?;
    check("ip.src == 2001:db8::1/128", &packet, true)?;
    check("ip.src == 2001:db8::/128", &packet, false)?;
    check("ip.dst == fe80::/10", &packet, true)?;
    check("tcp.dstport == 443", &packet, true)
}

#[test]
fn test_eval_families_never_mix_ok() -> Result<(), Box<dyn Error>> {
    check("ip.addr == ::/0", &tcp(1, 2, &[]), false)?;
    check("ip.addr == 0.0.0.0/0", &v6_tcp()?, false)
}

#[test]
fn test_eval_protocol_ok() -> Result<(), Box<dyn Error>> {
    check("ip.proto == tcp", &tcp(1, 2, &[]), true)?;
    check("ip.proto == 17", &udp(1, 2), true)?;
    check("ip.proto == icmp", &icmp(), true)?;
    check("ip.proto != tcp", &icmp(), true)?;
    check("ip.proto < 6", &icmp(), true)
}

#[test]
fn test_eval_port_fields_ok() -> Result<(), Box<dyn Error>> {
    let packet = tcp(51000, 80, &[]);

    check("tcp.port == 80", &packet, true)?;
    check("tcp.port == 51000", &packet, true)?;
    check("tcp.port == 443", &packet, false)?;
    check("tcp.srcport == 51000", &packet, true)?;
    check("tcp.srcport == 80", &packet, false)?;
    check("tcp.dstport == 80", &packet, true)?;
    check("udp.port == 53", &udp(53, 40000), true)?;
    check("udp.srcport == 53", &udp(53, 40000), true)?;
    check("udp.dstport == 53", &udp(53, 40000), false)
}

#[test]
fn test_eval_port_ordering_ok() -> Result<(), Box<dyn Error>> {
    let packet = tcp(51000, 80, &[]);

    check("tcp.dstport < 1024", &packet, true)?;
    check("tcp.dstport <= 80", &packet, true)?;
    check("tcp.dstport < 80", &packet, false)?;
    check("tcp.dstport >= 80", &packet, true)?;
    check("tcp.dstport > 80", &packet, false)?;
    check("tcp.port > 50000", &packet, true)?;
    check("tcp.port > 60000", &packet, false)
}

#[test]
fn test_eval_not_equal_means_neither_side_ok() -> Result<(), Box<dyn Error>> {
    let packet = tcp(51000, 80, &[]);

    check("tcp.port != 80", &packet, false)?;
    check("tcp.port != 443", &packet, true)?;
    check("ip.addr != 10.0.0.1", &packet, false)?;
    check("ip.addr != 8.8.8.8", &packet, true)
}

#[test]
fn test_eval_absent_field_is_false_ok() -> Result<(), Box<dyn Error>> {
    let packet = udp(1, 2);

    check("tcp.port == 1", &packet, false)?;
    check("tcp.port != 80", &packet, false)?;
    check("!(tcp.port == 80)", &packet, true)?;
    check("tcp.port", &packet, false)?;
    check("udp.port", &packet, true)?;
    check("udp.port == 1", &tcp(1, 2, &[]), false)
}

#[test]
fn test_eval_non_ip_packet_ok() -> Result<(), Box<dyn Error>> {
    let frame = common::ethernet(0x0806, &[0; 28]);
    let filter = Filter::parse("ip || ip.addr != 1.2.3.4 || tcp")?;
    let packet = Packet::parse(LinkType::Ethernet, &frame)?;

    assert!(!filter.matches(&packet));
    assert!(Filter::parse("!ip")?.matches(&packet));
    Ok(())
}

#[test]
fn test_eval_http_fields_ok() -> Result<(), Box<dyn Error>> {
    let packet = tcp(51000, 80, LOGIN);

    check("http.request.method == POST", &packet, true)?;
    check("http.request.method == \"POST\"", &packet, true)?;
    check("http.request.method == post", &packet, false)?;
    check("http.request.method != GET", &packet, true)?;
    check("http.host == example.com", &packet, true)?;
    check("http.host == \"EXAMPLE.com\"", &packet, true)?;
    check("http.host == other.com", &packet, false)?;
    check("http.host", &packet, true)
}

#[test]
fn test_eval_http_fields_absent_ok() -> Result<(), Box<dyn Error>> {
    let response = tcp(80, 51000, b"HTTP/1.1 200 OK\r\n\r\n");
    let plain = tcp(51000, 80, b"hello");
    let no_host = tcp(51000, 80, b"GET / HTTP/1.1\r\n\r\n");

    check("http.request.method == GET", &response, false)?;
    check("http.request.method != GET", &response, false)?;
    check("http.request.method", &response, false)?;
    check("http", &response, true)?;
    check("http.host == a.com", &plain, false)?;
    check("http.host", &no_host, false)?;
    check("http.request.method == GET", &no_host, true)
}

#[test]
fn test_eval_http_over_udp_payload_ok() -> Result<(), Box<dyn Error>> {
    let packet = common::ipv4(PROTO_UDP, CLIENT, SERVER, &common::udp(1, 2, LOGIN));

    check("http.request.method == POST", &packet, true)
}

#[test]
fn test_eval_logic_ok() -> Result<(), Box<dyn Error>> {
    let packet = tcp(51000, 80, LOGIN);

    check("tcp && tcp.port == 80", &packet, true)?;
    check("tcp && udp", &packet, false)?;
    check("udp || tcp.port == 80", &packet, true)?;
    check("!udp", &packet, true)?;
    check("!!tcp", &packet, true)?;
    check(
        "ip.src == 10.0.0.0/8 && (tcp.port == 443 || http.request.method == POST)",
        &packet,
        true,
    )?;
    check("not (tcp and tcp.port == 80) or udp", &packet, false)
}

#[test]
fn test_eval_later_fragment_has_no_ports_ok() -> Result<(), Box<dyn Error>> {
    let mut packet = tcp(51000, 80, &[]);
    packet[6] = 0x00;
    packet[7] = 0x10;

    check("tcp.port == 80", &packet, false)?;
    check("tcp", &packet, false)?;
    check("ip.proto == tcp", &packet, true)
}
