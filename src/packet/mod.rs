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

pub struct Packet<'a> {
    pub link: Link,
    pub ip: Option<IpHeader>,
    pub transport: Option<Transport>,
    pub payload: &'a [u8],
}

enum Network {
    Ipv4,
    Ipv6,
    Other,
}

impl<'a> Packet<'a> {
    pub fn parse(link_type: LinkType, bytes: &'a [u8]) -> Result<Packet<'a>, YeyoError> {
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

        let ip = match network {
            Network::Ipv4 => IpHeader::V4(Ipv4Header::parse(after_link)?),
            Network::Ipv6 => IpHeader::V6(Ipv6Header::parse(after_link)?),
            Network::Other => {
                return Ok(Packet {
                    link,
                    ip: None,
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
                ip: Some(ip),
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
            _ => (None, ip_payload),
        };

        Ok(Packet {
            link,
            ip: Some(ip),
            transport,
            payload,
        })
    }
}

impl IpHeader {
    fn header_len(&self) -> usize {
        match self {
            IpHeader::V4(h) => h.header_len,
            IpHeader::V6(h) => h.header_len,
        }
    }

    fn protocol(&self) -> u8 {
        match self {
            IpHeader::V4(h) => h.protocol,
            IpHeader::V6(h) => h.protocol,
        }
    }

    fn is_later_fragment(&self) -> bool {
        match self {
            IpHeader::V4(h) => h.fragment_offset > 0,
            IpHeader::V6(h) => h.fragment.is_some_and(|f| f.offset > 0),
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

fn ip_by_version(bytes: &[u8]) -> Network {
    if !bytes.is_empty() && bytes[0] >> 4 == IP_VERSION_6 {
        Network::Ipv6
    } else {
        Network::Ipv4
    }
}
