use crate::error::{Layer, YeyoError};

pub const V4_MIN_LEN: usize = 8;
pub const V6_MIN_LEN: usize = 4;
const ECHO_LEN: usize = 8;

const V4_ECHO_REPLY: u8 = 0;
const V4_ECHO_REQUEST: u8 = 8;
const V6_ECHO_REQUEST: u8 = 128;
const V6_ECHO_REPLY: u8 = 129;

const V4_NAMES: [(u8, &str); 6] = [
    (0, "echo reply"),
    (3, "destination unreachable"),
    (5, "redirect"),
    (8, "echo request"),
    (11, "time exceeded"),
    (12, "parameter problem"),
];
const V6_NAMES: [(u8, &str); 11] = [
    (1, "destination unreachable"),
    (2, "packet too big"),
    (3, "time exceeded"),
    (4, "parameter problem"),
    (128, "echo request"),
    (129, "echo reply"),
    (133, "router solicitation"),
    (134, "router advertisement"),
    (135, "neighbor solicitation"),
    (136, "neighbor advertisement"),
    (137, "redirect"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echo {
    pub id: u16,
    pub seq: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp {
    pub version: Version,
    pub kind: u8,
    pub code: u8,
    pub checksum: u16,
    pub echo: Option<Echo>,
    pub header_len: usize,
}

impl Icmp {
    pub fn parse(version: Version, bytes: &[u8]) -> Result<Icmp, YeyoError> {
        let (layer, min) = match version {
            Version::V4 => (Layer::Icmp, V4_MIN_LEN),
            Version::V6 => (Layer::Icmpv6, V6_MIN_LEN),
        };
        if bytes.len() < min {
            return Err(YeyoError::Truncated {
                layer,
                needed: min,
                got: bytes.len(),
            });
        }

        let kind = bytes[0];
        let is_echo = match version {
            Version::V4 => matches!(kind, V4_ECHO_REQUEST | V4_ECHO_REPLY),
            Version::V6 => matches!(kind, V6_ECHO_REQUEST | V6_ECHO_REPLY),
        };
        let echo = if is_echo {
            if bytes.len() < ECHO_LEN {
                return Err(YeyoError::Truncated {
                    layer,
                    needed: ECHO_LEN,
                    got: bytes.len(),
                });
            }
            Some(Echo {
                id: u16::from_be_bytes([bytes[4], bytes[5]]),
                seq: u16::from_be_bytes([bytes[6], bytes[7]]),
            })
        } else {
            None
        };

        Ok(Icmp {
            version,
            kind,
            code: bytes[1],
            checksum: u16::from_be_bytes([bytes[2], bytes[3]]),
            echo,
            header_len: if echo.is_some() { ECHO_LEN } else { min },
        })
    }

    pub fn name(&self) -> Option<&'static str> {
        let names: &[(u8, &str)] = match self.version {
            Version::V4 => &V4_NAMES,
            Version::V6 => &V6_NAMES,
        };
        names
            .iter()
            .find(|(kind, _)| *kind == self.kind)
            .map(|&(_, name)| name)
    }
}
