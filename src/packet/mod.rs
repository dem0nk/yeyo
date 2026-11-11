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
        let after_eth = &bytes[eth.header_len..];

        let (ip, protocol, ip_len) = match eth.ethertype {
            0x86dd => {
                let h = Ipv6Header::parse(after_eth)?;
                if let Some(frag) = h.fragment {
                    if frag.offset > 0 {
                        return Ok(Packet {
                            eth,
                            ip: Some(IpHeader::V6(h)),
                            transport: None,
                        });
                    }
                }
                let proto = h.protocol;
                let len = h.header_len;
                (IpHeader::V6(h), proto, len)
            }
            0x0800 => {
                let h = Ipv4Header::parse(after_eth)?;
                if h.fragment_offset > 0 {
                    return Ok(Packet {
                        eth,
                        ip: Some(IpHeader::V4(h)),
                        transport: None,
                    });
                }
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
