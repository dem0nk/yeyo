use crate::error::YeyoError;
use crate::packet::tcp::TcpFlags;
use crate::packet::{Link, Packet, Transport};
use std::io::{self, Write};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

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

pub struct Lines<W> {
    out: W,
    start: Option<SystemTime>,
}

impl<W: Write> Lines<W> {
    pub fn new(out: W) -> Self {
        Lines { out, start: None }
    }

    pub fn packet(
        &mut self,
        time: Option<SystemTime>,
        len: u32,
        packet: &Packet<'_>,
    ) -> io::Result<()> {
        let time = self.elapsed(time);
        writeln!(self.out, "{time} {} len {len}", summary(packet))
    }

    pub fn bad(&mut self, time: Option<SystemTime>, len: u32, err: &YeyoError) -> io::Result<()> {
        let time = self.elapsed(time);
        writeln!(self.out, "{time} bad packet: {err}, len {len}")
    }

    fn elapsed(&mut self, time: Option<SystemTime>) -> String {
        let time = match time {
            Some(time) => time,
            None => return "?".to_string(),
        };
        let start = *self.start.get_or_insert(time);
        match time.duration_since(start) {
            Ok(ahead) => seconds(ahead),
            Err(behind) => format!("-{}", seconds(behind.duration())),
        }
    }
}

fn seconds(d: Duration) -> String {
    format!("{}.{:06}", d.as_secs(), d.subsec_micros())
}

fn summary(packet: &Packet<'_>) -> String {
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
