use std::net::Ipv4Addr;

use crate::error::{Layer, YeyoError};

const MIN_HEADER_LEN: usize = 20;
const VERSION: u8 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub header_len: usize,
    pub total_length: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Ipv4Header {
    pub fn parse(bytes: &[u8]) -> Result<Ipv4Header, YeyoError> {
        if bytes.len() < MIN_HEADER_LEN {
            return Err(YeyoError::Truncated {
                layer: Layer::Ipv4,
                needed: MIN_HEADER_LEN,
                got: bytes.len(),
            });
        }

        let version = bytes[0] >> 4;
        if version != VERSION {
            return Err(YeyoError::Malformed {
                layer: Layer::Ipv4,
                reason: format!("version {version}, expected {VERSION}"),
            });
        }

        let header_len = (bytes[0] & 0x0f) as usize * 4;
        if header_len < MIN_HEADER_LEN {
            return Err(YeyoError::Malformed {
                layer: Layer::Ipv4,
                reason: format!("header length {header_len}, minimum {MIN_HEADER_LEN}"),
            });
        }
        if bytes.len() < header_len {
            return Err(YeyoError::Truncated {
                layer: Layer::Ipv4,
                needed: header_len,
                got: bytes.len(),
            });
        }

        let total_length = u16::from_be_bytes([bytes[2], bytes[3]]);
        if (total_length as usize) < header_len {
            return Err(YeyoError::Malformed {
                layer: Layer::Ipv4,
                reason: format!(
                    "total length {total_length}, smaller than header length {header_len}"
                ),
            });
        }

        Ok(Ipv4Header {
            header_len,
            total_length,
            ttl: bytes[8],
            protocol: bytes[9],
            src: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
            dst: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        })
    }
}
