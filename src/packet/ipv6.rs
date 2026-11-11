use std::net::Ipv6Addr;

use crate::error::{Layer, YeyoError};

pub(crate) const HEADER_LEN: usize = 40;
const VERSION: u8 = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Header {
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

impl Ipv6Header {
    pub fn parse(bytes: &[u8]) -> Result<Ipv6Header, YeyoError> {
        if bytes.len() < HEADER_LEN {
            return Err(YeyoError::Truncated {
                layer: Layer::Ipv6,
                needed: HEADER_LEN,
                got: bytes.len(),
            });
        }

        let version = bytes[0] >> 4;
        if version != VERSION {
            return Err(YeyoError::Malformed {
                layer: Layer::Ipv6,
                reason: format!("version {version}, expected {VERSION}"),
            });
        }

        let mut src = [0u8; 16];
        src.copy_from_slice(&bytes[8..24]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&bytes[24..40]);

        Ok(Ipv6Header {
            payload_length: u16::from_be_bytes([bytes[4], bytes[5]]),
            next_header: bytes[6],
            hop_limit: bytes[7],
            src: Ipv6Addr::from(src),
            dst: Ipv6Addr::from(dst),
        })
    }
}
