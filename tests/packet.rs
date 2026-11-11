mod common;

use std::error::Error;
use std::net::Ipv4Addr;
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
