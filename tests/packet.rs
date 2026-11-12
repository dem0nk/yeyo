mod common;

use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::Link;
use yeyo::packet::link::LinkType;
use yeyo::packet::{IpHeader, Packet, Transport, tcp::TcpFlags};

#[test]
fn test_parse_ipv4_udp_ok() -> Result<(), Box<dyn Error>> {
    let udp_bytes = common::udp(12345, 53, &[]);
    let ip_bytes = common::ipv4(17, [192, 168, 1, 2], [8, 8, 8, 8], &udp_bytes);
    let bytes = common::ethernet(0x0800, &ip_bytes);

    let pkt = Packet::parse(LinkType::Ethernet, &bytes)?;

    match pkt.ip {
        Some(IpHeader::V4(ip)) => {
            assert_eq!(ip.src, Ipv4Addr::new(192, 168, 1, 2));
            assert_eq!(ip.dst, Ipv4Addr::new(8, 8, 8, 8));
            assert_eq!(ip.protocol, 17);
        }
        _ => panic!("expected IPv4"),
    }

    match pkt.transport {
        Some(Transport::Udp(udp)) => {
            assert_eq!(udp.src_port, 12345);
            assert_eq!(udp.dst_port, 53);
        }
        _ => panic!("expected UDP"),
    }

    Ok(())
}

#[test]
fn test_parse_ipv4_first_fragment_has_transport_ok() -> Result<(), Box<dyn Error>> {
    let udp_bytes = common::udp(12345, 53, &[]);
    let mut ip_bytes = common::ipv4(17, [192, 168, 1, 2], [8, 8, 8, 8], &udp_bytes);
    ip_bytes[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
    let bytes = common::ethernet(0x0800, &ip_bytes);

    let pkt = Packet::parse(LinkType::Ethernet, &bytes)?;

    assert!(matches!(pkt.transport, Some(Transport::Udp(_))));
    Ok(())
}

#[test]
fn test_parse_ipv4_later_fragment_has_no_transport_ok() -> Result<(), Box<dyn Error>> {
    let data = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00];
    let mut ip_bytes = common::ipv4(17, [192, 168, 1, 2], [8, 8, 8, 8], &data);
    ip_bytes[6..8].copy_from_slice(&0x00b9u16.to_be_bytes());
    let bytes = common::ethernet(0x0800, &ip_bytes);

    let pkt = Packet::parse(LinkType::Ethernet, &bytes)?;

    assert!(matches!(pkt.ip, Some(IpHeader::V4(_))));
    assert!(pkt.transport.is_none());
    Ok(())
}

#[test]
fn test_parse_ipv6_udp_ok() -> Result<(), Box<dyn Error>> {
    let src = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111);
    let udp_bytes = common::udp(54321, 53, &[]);
    let bytes = common::ethernet(0x86dd, &common::ipv6(17, src, dst, &udp_bytes));

    let pkt = Packet::parse(LinkType::Ethernet, &bytes)?;

    match pkt.ip {
        Some(IpHeader::V6(ip)) => {
            assert_eq!(ip.src, src);
            assert_eq!(ip.dst, dst);
        }
        _ => panic!("expected IPv6"),
    }
    assert!(matches!(pkt.transport, Some(Transport::Udp(_))));
    Ok(())
}

#[test]
fn test_parse_ipv6_hop_by_hop_udp_ok() -> Result<(), Box<dyn Error>> {
    let src = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111);
    let hbh = common::ipv6_ext(17, &common::udp(54321, 53, &[]));
    let bytes = common::ethernet(0x86dd, &common::ipv6(0, src, dst, &hbh));

    let pkt = Packet::parse(LinkType::Ethernet, &bytes)?;

    assert!(matches!(pkt.transport, Some(Transport::Udp(_))));
    Ok(())
}

#[test]
fn test_parse_ipv6_later_fragment_has_no_transport_ok() -> Result<(), Box<dyn Error>> {
    let src = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111);
    let frag = common::ipv6_fragment(17, 1448, false, 7, &[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]);
    let bytes = common::ethernet(0x86dd, &common::ipv6(44, src, dst, &frag));

    let pkt = Packet::parse(LinkType::Ethernet, &bytes)?;

    assert!(matches!(pkt.ip, Some(IpHeader::V6(_))));
    assert!(pkt.transport.is_none());
    Ok(())
}

#[test]
fn test_parse_truncated_ipv6_propagates_err() {
    let bytes = common::ethernet(0x86dd, &[0x60; 20]);

    assert_eq!(
        Packet::parse(LinkType::Ethernet, &bytes).err(),
        Some(YeyoError::Truncated {
            layer: Layer::Ipv6,
            needed: 40,
            got: 20
        })
    );
}

#[test]
fn test_parse_ipv4_tcp_ok() -> Result<(), Box<dyn Error>> {
    let tcp_bytes = common::tcp(52814, 443, 0x02, &[]);
    let ip_bytes = common::ipv4(6, [192, 168, 1, 2], [93, 184, 216, 34], &tcp_bytes);
    let bytes = common::ethernet(0x0800, &ip_bytes);

    let pkt = Packet::parse(LinkType::Ethernet, &bytes)?;

    match pkt.transport {
        Some(Transport::Tcp(tcp)) => {
            assert_eq!(tcp.dst_port, 443);
            assert!(tcp.flags.contains(TcpFlags::SYN));
        }
        _ => panic!("expected TCP"),
    }
    Ok(())
}

#[test]
fn test_parse_truncated_tcp_propagates_err() {
    let ip_bytes = common::ipv4(6, [192, 168, 1, 2], [93, 184, 216, 34], &[0; 10]);
    let bytes = common::ethernet(0x0800, &ip_bytes);

    assert_eq!(
        Packet::parse(LinkType::Ethernet, &bytes).err(),
        Some(YeyoError::Truncated {
            layer: Layer::Tcp,
            needed: 20,
            got: 10
        })
    );
}

#[test]
fn test_parse_truncated_udp_propagates_err() {
    let ip_bytes = common::ipv4(17, [192, 168, 1, 2], [8, 8, 8, 8], &[0; 4]);
    let bytes = common::ethernet(0x0800, &ip_bytes);

    assert_eq!(
        Packet::parse(LinkType::Ethernet, &bytes).err(),
        Some(YeyoError::Truncated {
            layer: Layer::Udp,
            needed: 8,
            got: 4
        })
    );
}

#[test]
fn test_parse_loopback_ipv4_udp_ok() -> Result<(), Box<dyn Error>> {
    let udp_bytes = common::udp(54321, 53, &[]);
    let ip_bytes = common::ipv4(17, [127, 0, 0, 1], [127, 0, 0, 1], &udp_bytes);
    let bytes = common::loopback(2, &ip_bytes);

    let pkt = Packet::parse(LinkType::Loopback, &bytes)?;

    assert!(matches!(pkt.link, Link::Loopback));
    assert!(matches!(pkt.ip, Some(IpHeader::V4(_))));
    assert!(matches!(pkt.transport, Some(Transport::Udp(_))));
    Ok(())
}

#[test]
fn test_parse_loopback_ipv6_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::loopback(
        30,
        &common::ipv6(
            17,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            &common::udp(1, 2, &[]),
        ),
    );

    let pkt = Packet::parse(LinkType::Loopback, &bytes)?;

    assert!(matches!(pkt.ip, Some(IpHeader::V6(_))));
    Ok(())
}

#[test]
fn test_parse_loopback_truncated_err() {
    assert_eq!(
        Packet::parse(LinkType::Loopback, &[2, 0]).err(),
        Some(YeyoError::Truncated {
            layer: Layer::Loopback,
            needed: 4,
            got: 2
        })
    );
}

#[test]
fn test_parse_raw_ipv6_tcp_ok() -> Result<(), Box<dyn Error>> {
    let src = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
    let bytes = common::ipv6(6, src, dst, &common::tcp(52814, 443, 0x02, &[]));

    let pkt = Packet::parse(LinkType::Raw, &bytes)?;

    assert!(matches!(pkt.link, Link::Raw));
    assert!(matches!(pkt.transport, Some(Transport::Tcp(_))));
    Ok(())
}

#[test]
fn test_parse_raw_ipv4_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], &common::udp(1, 2, &[]));

    let pkt = Packet::parse(LinkType::Raw, &bytes)?;

    assert!(matches!(pkt.ip, Some(IpHeader::V4(_))));
    Ok(())
}

#[test]
fn test_parse_raw_empty_err() {
    assert_eq!(
        Packet::parse(LinkType::Raw, &[]).err(),
        Some(YeyoError::Truncated {
            layer: Layer::Ipv4,
            needed: 20,
            got: 0
        })
    );
}

#[test]
fn test_parse_raw_bad_version_err() {
    let mut bytes = common::ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], &[]);
    bytes[0] = 0x55;

    assert_eq!(
        Packet::parse(LinkType::Raw, &bytes).err(),
        Some(YeyoError::Malformed {
            layer: Layer::Ipv4,
            reason: "version 5, expected 4".to_string(),
        })
    );
}

#[test]
fn test_parse_ethernet_non_ip_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::ethernet(0x0806, &[0; 28]);

    let pkt = Packet::parse(LinkType::Ethernet, &bytes)?;

    assert!(matches!(pkt.link, Link::Ethernet(_)));
    assert!(pkt.ip.is_none());
    Ok(())
}
