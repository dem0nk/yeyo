use crate::packet::arp::{Arp, Operation};
use crate::packet::icmp::Icmp;
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
    if let Some(arp) = packet.arp() {
        return arp_line(arp);
    }
    let ip = match packet.ip() {
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
        Some(Transport::Icmp(icmp)) => format!("{src} > {dst} ICMP {}", icmp_text(icmp)),
        Some(Transport::Icmpv6(icmp)) => format!("{src} > {dst} ICMPv6 {}", icmp_text(icmp)),
        Some(Transport::Other(protocol)) => format!("{src} > {dst} proto {protocol}"),
        None if ip.is_later_fragment() => {
            format!("{src} > {dst} fragment proto {}", ip.protocol())
        }
        None => format!("{src} > {dst} proto {}", ip.protocol()),
    }
}

fn icmp_text(icmp: &Icmp) -> String {
    let mut text = match icmp.name() {
        Some(name) => name.to_string(),
        None => format!("type {}", icmp.kind),
    };
    if let Some(echo) = icmp.echo {
        text.push_str(&format!(" id {} seq {}", echo.id, echo.seq));
    }
    text
}

fn arp_line(arp: &Arp) -> String {
    match arp.operation {
        Operation::Request => format!("ARP who-has {} tell {}", arp.target_ip, arp.sender_ip),
        Operation::Reply => format!("ARP {} is-at {}", arp.sender_ip, mac(arp.sender_mac)),
        Operation::Other(code) => {
            format!("ARP operation {code} {} > {}", arp.sender_ip, arp.target_ip)
        }
    }
}

fn mac(bytes: [u8; 6]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
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
