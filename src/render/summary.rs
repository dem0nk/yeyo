use crate::packet::tcp::TcpFlags;
use crate::packet::{Link, Packet, Transport};
use std::net::SocketAddr;

const FLAG_LETTERS: [(TcpFlags, char); 8] = [
    (TcpFlags::FIN, 'F'),
    (TcpFlags::SYN, 'S'),
    (TcpFlags::RST, 'R'),
    (TcpFlags::PSH, 'P'),
    (TcpFlags::ACK, 'A'),
    (TcpFlags::URG, 'U'),
    (TcpFlags::ECE, 'E'),
    (TcpFlags::CWR, 'W'),
];

pub(super) fn summary(packet: &Packet<'_>) -> String {
    let ip = match &packet.ip {
        Some(ip) => ip,
        None => {
            return match &packet.link {
                Link::Ethernet(eth) => format!("ethertype 0x{:04x}", eth.ethertype),
                Link::Loopback | Link::Raw => "non-IP".to_string(),
            };
        }
    };
    let (src, dst) = (ip.src(), ip.dst());
    match &packet.transport {
        Some(Transport::Tcp(tcp)) => format!(
            "{} > {} TCP [{}]",
            SocketAddr::new(src, tcp.src_port),
            SocketAddr::new(dst, tcp.dst_port),
            flags(tcp.flags)
        ),
        Some(Transport::Udp(udp)) => format!(
            "{} > {} UDP",
            SocketAddr::new(src, udp.src_port),
            SocketAddr::new(dst, udp.dst_port)
        ),
        None if ip.is_later_fragment() => {
            format!("{src} > {dst} fragment proto {}", ip.protocol())
        }
        None => format!("{src} > {dst} proto {}", ip.protocol()),
    }
}

fn flags(flags: TcpFlags) -> String {
    let letters: String = FLAG_LETTERS
        .iter()
        .filter(|(flag, _)| flags.contains(*flag))
        .map(|(_, letter)| letter)
        .collect();
    if letters.is_empty() {
        "none".to_string()
    } else {
        letters
    }
}
