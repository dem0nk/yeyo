mod error;
mod packet;

use packet::ethernet::EthernetHeader;
use packet::ipv6::Ipv6Header;
use packet::tcp::TcpHeader;
use packet::udp::UdpHeader;

use std::net::Ipv6Addr;

fn main() -> Result<(), pcap::Error> {
    let mut cap = pcap::Capture::from_device("en0")?
        .immediate_mode(true)
        .open()?;

    loop {
        let packet = cap.next_packet()?;

        let eth = match EthernetHeader::parse(packet.data) {
            Ok(eth) => eth,
            Err(e) => {
                println!("bad packet: {:?}", e);
                continue;
            }
        };

        if eth.ethertype == 0x86dd {
            match Ipv6Header::parse(&packet.data[14..]) {
                Ok(ip) => {
                    println!(
                        "{} -> {} next={} hops={}",
                        Ipv6Addr::from(ip.src),
                        Ipv6Addr::from(ip.dst),
                        ip.next_header,
                        ip.hop_limit
                    );
                    match ip.next_header {
                        17 => match UdpHeader::parse(&packet.data[54..]) {
                            Ok(udp) => println!("    udp {} -> {}", udp.src_port, udp.dst_port),
                            Err(e) => println!("bad udp: {:?}", e),
                        },
                        6 => match TcpHeader::parse(&packet.data[54..]) {
                            Ok(tcp) => println!(
                                "    tcp {} -> {} flags={:08b} seq={} len={}",
                                tcp.src_port, tcp.dst_port, tcp.flags, tcp.seq, tcp.header_len
                            ),
                            Err(e) => println!("bad tcp: {:?}", e),
                        },
                        _ => {}
                    }
                }
                Err(e) => println!("bad ipv6: {:?}", e),
            }
        }
    }
}
