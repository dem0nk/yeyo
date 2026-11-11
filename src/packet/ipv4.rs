use std::net::Ipv4Addr;

use crate::error::{Layer, YeyoError};

const MIN_HEADER_LEN: usize = 20;
const VERSION: u8 = 4;
const DONT_FRAGMENT: u16 = 0x4000;
const MORE_FRAGMENTS: u16 = 0x2000;
const OFFSET_MASK: u16 = 0x1fff;
const OFFSET_UNIT: u16 = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    pub header_len: usize,
    pub total_length: u16,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    pub fragment_offset: u16,
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

        let flags_and_offset = u16::from_be_bytes([bytes[6], bytes[7]]);

        Ok(Ipv4Header {
            header_len,
            total_length,
            identification: u16::from_be_bytes([bytes[4], bytes[5]]),
            dont_fragment: flags_and_offset & DONT_FRAGMENT != 0,
            more_fragments: flags_and_offset & MORE_FRAGMENTS != 0,
            fragment_offset: (flags_and_offset & OFFSET_MASK) * OFFSET_UNIT,
            ttl: bytes[8],
            protocol: bytes[9],
            src: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
            dst: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        })
    }
}
