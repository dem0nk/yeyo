use crate::error::{Layer, YeyoError};
use ethernet::EthernetHeader;
use ipv4::Ipv4Header;
use ipv6::Ipv6Header;
use link::LinkType;
use tcp::TcpHeader;
use udp::UdpHeader;

pub mod ethernet;
pub mod ipv4;
pub mod ipv6;
pub mod link;
pub mod tcp;
pub mod udp;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const LOOPBACK_HEADER_LEN: usize = 4;
const IP_VERSION_6: u8 = 6;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

pub enum Link {
    Ethernet(EthernetHeader),
    Loopback,
    Raw,
}

pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

pub enum Transport {
    Tcp(TcpHeader),
    Udp(UdpHeader),
}

pub struct Packet {
    pub link: Link,
    pub ip: Option<IpHeader>,
    pub transport: Option<Transport>,
}

enum Network {
    Ipv4,
    Ipv6,
    Other,
}

impl Packet {
    pub fn parse(link_type: LinkType, bytes: &[u8]) -> Result<Packet, YeyoError> {
        let (link, network, link_len) = match link_type {
            LinkType::Ethernet => {
                let eth = EthernetHeader::parse(bytes)?;
                let network = match eth.ethertype {
                    ETHERTYPE_IPV4 => Network::Ipv4,
                    ETHERTYPE_IPV6 => Network::Ipv6,
                    _ => Network::Other,
                };
                let len = eth.header_len;
                (Link::Ethernet(eth), network, len)
            }
            LinkType::Loopback => {
                if bytes.len() < LOOPBACK_HEADER_LEN {
                    return Err(YeyoError::Truncated {
                        layer: Layer::Loopback,
                        needed: LOOPBACK_HEADER_LEN,
                        got: bytes.len(),
                    });
                }
                let network = ip_by_version(&bytes[LOOPBACK_HEADER_LEN..]);
                (Link::Loopback, network, LOOPBACK_HEADER_LEN)
            }
            LinkType::Raw => (Link::Raw, ip_by_version(bytes), 0),
        };

        let after_link = &bytes[link_len..];

        let (ip, protocol, ip_len) = match network {
            Network::Ipv6 => {
                let h = Ipv6Header::parse(after_link)?;
                if let Some(frag) = h.fragment {
                    if frag.offset > 0 {
                        return Ok(Packet {
                            link,
                            ip: Some(IpHeader::V6(h)),
                            transport: None,
                        });
                    }
                }
                let proto = h.protocol;
                let len = h.header_len;
                (IpHeader::V6(h), proto, len)
            }
            Network::Ipv4 => {
                let h = Ipv4Header::parse(after_link)?;
                if h.fragment_offset > 0 {
                    return Ok(Packet {
                        link,
                        ip: Some(IpHeader::V4(h)),
                        transport: None,
                    });
                }
                let proto = h.protocol;
                let len = h.header_len;
                (IpHeader::V4(h), proto, len)
            }
            Network::Other => {
                return Ok(Packet {
                    link,
                    ip: None,
                    transport: None,
                });
            }
        };

        let rest = &after_link[ip_len..];
        let transport = match protocol {
            PROTO_TCP => Some(Transport::Tcp(TcpHeader::parse(rest)?)),
            PROTO_UDP => Some(Transport::Udp(UdpHeader::parse(rest)?)),
            _ => None,
        };

        Ok(Packet {
            link,
            ip: Some(ip),
            transport,
        })
    }
}

fn ip_by_version(bytes: &[u8]) -> Network {
    if !bytes.is_empty() && bytes[0] >> 4 == IP_VERSION_6 {
        Network::Ipv6
    } else {
        Network::Ipv4
    }
}
