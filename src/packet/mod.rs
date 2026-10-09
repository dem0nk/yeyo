use crate::error::YeyoError;
use ethernet::EthernetHeader;
use ipv4::Ipv4Header;
use ipv6::Ipv6Header;
use tcp::TcpHeader;
use udp::UdpHeader;

pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod tcp;
pub mod udp;

pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

pub enum Transport {
    Tcp(TcpHeader),
    Udp(UdpHeader),
}

pub struct Packet {
    pub eth: EthernetHeader,
    pub ip: Option<IpHeader>,
    pub transport: Option<Transport>,
}

impl Packet {
    pub fn parse(bytes: &[u8]) -> Result<Packet, YeyoError> {
        let eth = EthernetHeader::parse(bytes)?;
        let after_eth = &bytes[14..];

        let (ip, protocol, ip_len) = match eth.ethertype {
            0x86dd => {
                let h = Ipv6Header::parse(after_eth)?;
                let proto = h.next_header;
                (IpHeader::V6(h), proto, 40)
            }
            0x0800 => {
                let h = Ipv4Header::parse(after_eth)?;
                let proto = h.protocol;
                let len = h.header_len;
                (IpHeader::V4(h), proto, len)
            }
            _ => {
                return Ok(Packet {
                    eth,
                    ip: None,
                    transport: None,
                });
            }
        };

        let rest = &after_eth[ip_len..];
        let transport = match protocol {
            6 => Some(Transport::Tcp(TcpHeader::parse(rest)?)),
            17 => Some(Transport::Udp(UdpHeader::parse(rest)?)),
            _ => None,
        };

        Ok(Packet {
            eth,
            ip: Some(ip),
            transport,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_udp() {
        let bytes: [u8; 42] = [
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x02, 0x08, 0x08, 0x08, 0x08, 0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00,
        ];

        let pkt = Packet::parse(&bytes).unwrap();

        match pkt.ip {
            Some(IpHeader::V4(ip)) => {
                assert_eq!(ip.src, [192, 168, 1, 2]);
                assert_eq!(ip.dst, [8, 8, 8, 8]);
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
    }
}
