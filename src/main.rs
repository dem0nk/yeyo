mod error;
mod packet;

use packet::ethernet::EthernetHeader;
use packet::ipv6::Ipv6Header;
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
                Ok(ip) => println!(
                    "{} -> {} next={} hops={}",
                    Ipv6Addr::from(ip.src),
                    Ipv6Addr::from(ip.dst),
                    ip.next_header,
                    ip.hop_limit
                ),
                Err(e) => println!("bad ipv6: {:?}", e),
            }
        }
    }
}
