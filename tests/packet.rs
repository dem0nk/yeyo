mod common;

use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::{IpHeader, Packet, Transport};

#[test]
fn test_parse_ipv4_udp_ok() -> Result<(), Box<dyn Error>> {
    let udp_bytes = common::udp(12345, 53, &[]);
    let ip_bytes = common::ipv4(17, [192, 168, 1, 2], [8, 8, 8, 8], &udp_bytes);
    let bytes = common::ethernet(0x0800, &ip_bytes);

    let pkt = Packet::parse(&bytes)?;

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

    let pkt = Packet::parse(&bytes)?;

    assert!(matches!(pkt.transport, Some(Transport::Udp(_))));
    Ok(())
}

#[test]
fn test_parse_ipv4_later_fragment_has_no_transport_ok() -> Result<(), Box<dyn Error>> {
    let data = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x00, 0x00, 0x00];
    let mut ip_bytes = common::ipv4(17, [192, 168, 1, 2], [8, 8, 8, 8], &data);
    ip_bytes[6..8].copy_from_slice(&0x00b9u16.to_be_bytes());
    let bytes = common::ethernet(0x0800, &ip_bytes);

    let pkt = Packet::parse(&bytes)?;

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

    let pkt = Packet::parse(&bytes)?;

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

    let pkt = Packet::parse(&bytes)?;

    assert!(matches!(pkt.transport, Some(Transport::Udp(_))));
    Ok(())
}

#[test]
fn test_parse_ipv6_later_fragment_has_no_transport_ok() -> Result<(), Box<dyn Error>> {
    let src = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let dst = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111);
    let frag = common::ipv6_fragment(17, 1448, false, 7, &[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]);
    let bytes = common::ethernet(0x86dd, &common::ipv6(44, src, dst, &frag));

    let pkt = Packet::parse(&bytes)?;

    assert!(matches!(pkt.ip, Some(IpHeader::V6(_))));
    assert!(pkt.transport.is_none());
    Ok(())
}

#[test]
fn test_parse_truncated_ipv6_propagates_err() {
    let bytes = common::ethernet(0x86dd, &[0x60; 20]);

    assert_eq!(
        Packet::parse(&bytes).err(),
        Some(YeyoError::Truncated {
            layer: Layer::Ipv6,
            needed: 40,
            got: 20
        })
    );
}
