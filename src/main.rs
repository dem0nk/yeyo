mod error;
mod packet;

use packet::{IpHeader, Packet, Transport};
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() -> Result<(), pcap::Error> {
    let mut cap = pcap::Capture::from_device("en0")?
        .immediate_mode(true)
        .open()?;

    loop {
        let raw = cap.next_packet()?;

        let pkt = match Packet::parse(raw.data) {
            Ok(pkt) => pkt,
            Err(e) => {
                println!("bad packet: {:?}", e);
                continue;
            }
        };

        match &pkt.ip {
            Some(IpHeader::V6(ip)) => {
                println!("{} -> {}", Ipv6Addr::from(ip.src), Ipv6Addr::from(ip.dst))
            }
            Some(IpHeader::V4(ip)) => {
                println!("{} -> {}", Ipv4Addr::from(ip.src), Ipv4Addr::from(ip.dst))
            }
            None => {}
        }

        match &pkt.transport {
            Some(Transport::Tcp(tcp)) => println!(
                "    tcp {} -> {} flags={:08b}",
                tcp.src_port, tcp.dst_port, tcp.flags
            ),
            Some(Transport::Udp(udp)) => {
                println!("    udp {} -> {}", udp.src_port, udp.dst_port)
            }
            None => {}
        }
    }
}
