use crate::error::{Layer, YeyoError};
use arp::Arp;
use ethernet::EthernetHeader;
use icmp::{Icmp, Version};
use ipv4::Ipv4Header;
use ipv6::Ipv6Header;
use link::LinkType;
use std::net::{IpAddr, SocketAddr};
use tcp::TcpHeader;
use udp::UdpHeader;

pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod link;
pub mod tcp;
pub mod udp;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_ARP: u16 = 0x0806;
const LOOPBACK_HEADER_LEN: usize = 4;
const IP_VERSION_6: u8 = 6;
const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

pub enum Link {
    Ethernet(EthernetHeader),
    Loopback,
    Raw,
}

pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

pub enum Network {
    Ip(IpHeader),
    Arp(Arp),
}

pub enum Transport {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(Icmp),
    Icmpv6(Icmp),
    Other(u8),
}

pub struct Packet<'a> {
    pub link: Link,
    pub network: Option<Network>,
    pub transport: Option<Transport>,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoints {
    pub protocol: u8,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

enum Next {
    Ipv4,
    Ipv6,
    Arp,
    Other,
}

impl<'a> Packet<'a> {
    pub fn parse(link_type: LinkType, bytes: &'a [u8]) -> Result<Packet<'a>, YeyoError> {
        let (link, network, link_len) = match link_type {
            LinkType::Ethernet => {
                let eth = EthernetHeader::parse(bytes)?;
                let network = match eth.ethertype {
                    ETHERTYPE_IPV4 => Next::Ipv4,
                    ETHERTYPE_IPV6 => Next::Ipv6,
                    ETHERTYPE_ARP => Next::Arp,
                    _ => Next::Other,
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

        let ip = match network {
            Next::Ipv4 => IpHeader::V4(Ipv4Header::parse(after_link)?),
            Next::Ipv6 => IpHeader::V6(Ipv6Header::parse(after_link)?),
            Next::Arp => {
                let arp = Arp::parse(after_link)?;
                return Ok(Packet {
                    link,
                    network: Some(Network::Arp(arp)),
                    transport: None,
                    payload: &[],
                });
            }
            Next::Other => {
                return Ok(Packet {
                    link,
                    network: None,
                    transport: None,
                    payload: after_link,
                });
            }
        };

        let datagram = &after_link[..ip.datagram_len(after_link.len())];
        let ip_payload = &datagram[ip.header_len()..];

        if ip.is_later_fragment() {
            return Ok(Packet {
                link,
                network: Some(Network::Ip(ip)),
                transport: None,
                payload: ip_payload,
            });
        }

        let (transport, payload) = match ip.protocol() {
            PROTO_TCP => {
                let tcp = TcpHeader::parse(ip_payload)?;
                let payload = &ip_payload[tcp.header_len..];
                (Some(Transport::Tcp(tcp)), payload)
            }
            PROTO_UDP => {
                let udp = UdpHeader::parse(ip_payload)?;
                let end = usize::from(udp.length).min(ip_payload.len());
                let payload = &ip_payload[udp::HEADER_LEN..end];
                (Some(Transport::Udp(udp)), payload)
            }
            PROTO_ICMP => {
                let icmp = Icmp::parse(Version::V4, ip_payload)?;
                let payload = &ip_payload[icmp.header_len..];
                (Some(Transport::Icmp(icmp)), payload)
            }
            PROTO_ICMPV6 => {
                let icmp = Icmp::parse(Version::V6, ip_payload)?;
                let payload = &ip_payload[icmp.header_len..];
                (Some(Transport::Icmpv6(icmp)), payload)
            }
            other => (Some(Transport::Other(other)), ip_payload),
        };

        Ok(Packet {
            link,
            network: Some(Network::Ip(ip)),
            transport,
            payload,
        })
    }
}

impl Packet<'_> {
    pub fn ip(&self) -> Option<&IpHeader> {
        match &self.network {
            Some(Network::Ip(ip)) => Some(ip),
            _ => None,
        }
    }

    pub fn arp(&self) -> Option<&Arp> {
        match &self.network {
            Some(Network::Arp(arp)) => Some(arp),
            _ => None,
        }
    }

    pub fn endpoints(&self) -> Option<Endpoints> {
        let ip = self.ip()?;
        let (src_port, dst_port) = match self.transport.as_ref()? {
            Transport::Tcp(tcp) => (tcp.src_port, tcp.dst_port),
            Transport::Udp(udp) => (udp.src_port, udp.dst_port),
            Transport::Icmp(_) | Transport::Icmpv6(_) | Transport::Other(_) => return None,
        };
        Some(Endpoints {
            protocol: ip.protocol(),
            src: SocketAddr::new(ip.src(), src_port),
            dst: SocketAddr::new(ip.dst(), dst_port),
        })
    }
}

impl IpHeader {
    pub fn src(&self) -> IpAddr {
        match self {
            IpHeader::V4(h) => IpAddr::V4(h.src),
            IpHeader::V6(h) => IpAddr::V6(h.src),
        }
    }

    pub fn dst(&self) -> IpAddr {
        match self {
            IpHeader::V4(h) => IpAddr::V4(h.dst),
            IpHeader::V6(h) => IpAddr::V6(h.dst),
        }
    }

    pub fn protocol(&self) -> u8 {
        match self {
            IpHeader::V4(h) => h.protocol,
            IpHeader::V6(h) => h.protocol,
        }
    }

    pub fn is_later_fragment(&self) -> bool {
        match self {
            IpHeader::V4(h) => h.fragment_offset > 0,
            IpHeader::V6(h) => h.fragment.is_some_and(|f| f.offset > 0),
        }
    }

    fn header_len(&self) -> usize {
        match self {
            IpHeader::V4(h) => h.header_len,
            IpHeader::V6(h) => h.header_len,
        }
    }

    fn datagram_len(&self, captured: usize) -> usize {
        let declared = match self {
            IpHeader::V4(h) => usize::from(h.total_length),
            IpHeader::V6(h) if h.payload_length == 0 => captured,
            IpHeader::V6(h) => ipv6::HEADER_LEN + usize::from(h.payload_length),
        };
        declared.min(captured)
    }
}

fn ip_by_version(bytes: &[u8]) -> Next {
    if !bytes.is_empty() && bytes[0] >> 4 == IP_VERSION_6 {
        Next::Ipv6
    } else {
        Next::Ipv4
    }
}
