use std::process::ExitCode;
use yeyo::error::YeyoError;
use yeyo::packet::link::LinkType;
use yeyo::packet::{IpHeader, Packet, Transport};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("yeyo: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), YeyoError> {
    let mut cap = pcap::Capture::from_device("en0")?
        .immediate_mode(true)
        .open()?;

    let link_type = LinkType::try_from(cap.get_datalink().0)?;

    loop {
        let raw = cap.next_packet()?;

        let pkt = match Packet::parse(link_type, raw.data) {
            Ok(pkt) => pkt,
            Err(e) => {
                println!("bad packet: {e}");
                continue;
            }
        };

        match &pkt.ip {
            Some(IpHeader::V6(ip)) => println!("{} -> {}", ip.src, ip.dst),
            Some(IpHeader::V4(ip)) => println!("{} -> {}", ip.src, ip.dst),
            None => {}
        }

        match &pkt.transport {
            Some(Transport::Tcp(tcp)) => println!(
                "    tcp {} -> {} flags={:08b}",
                tcp.src_port,
                tcp.dst_port,
                tcp.flags.bits()
            ),
            Some(Transport::Udp(udp)) => {
                println!("    udp {} -> {}", udp.src_port, udp.dst_port)
            }
            None => {}
        }
    }
}
