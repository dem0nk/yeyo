use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Ethernet,
    Vlan,
    Loopback,
    Arp,
    Ipv4,
    Ipv6,
    Ipv6Extension,
    Tcp,
    Udp,
    Icmp,
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Layer::Ethernet => "Ethernet",
            Layer::Vlan => "VLAN",
            Layer::Loopback => "loopback",
            Layer::Arp => "ARP",
            Layer::Ipv4 => "IPv4",
            Layer::Ipv6 => "IPv6",
            Layer::Ipv6Extension => "IPv6 extension",
            Layer::Tcp => "TCP",
            Layer::Udp => "UDP",
            Layer::Icmp => "ICMP",
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum YeyoError {
    Capture(pcap::Error),
    UnsupportedLinkType(i32),
    Truncated {
        layer: Layer,
        needed: usize,
        got: usize,
    },
    Malformed {
        layer: Layer,
        reason: String,
    },
    PacketTooShort {
        needed: usize,
        got: usize,
    },
    BadIpVersion {
        expected: u8,
        got: u8,
    },
}

impl fmt::Display for YeyoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            YeyoError::Capture(e) => write!(f, "capture failed: {e}"),
            YeyoError::UnsupportedLinkType(link) => {
                write!(f, "unsupported link type {link}")
            }
            YeyoError::Truncated { layer, needed, got } => {
                write!(
                    f,
                    "truncated {layer} header: needed {needed} bytes, got {got}"
                )
            }
            YeyoError::Malformed { layer, reason } => {
                write!(f, "malformed {layer} header: {reason}")
            }
            YeyoError::PacketTooShort { needed, got } => {
                write!(f, "packet too short: needed {needed} bytes, got {got}")
            }
            YeyoError::BadIpVersion { expected, got } => {
                write!(f, "bad IP version: expected {expected}, got {got}")
            }
        }
    }
}

impl std::error::Error for YeyoError {}

impl From<pcap::Error> for YeyoError {
    fn from(e: pcap::Error) -> Self {
        YeyoError::Capture(e)
    }
}
