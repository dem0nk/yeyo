use std::net::Ipv6Addr;

use crate::error::{Layer, YeyoError};

const HEADER_LEN: usize = 40;
const VERSION: u8 = 6;

const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const AUTHENTICATION: u8 = 51;
const DESTINATION_OPTIONS: u8 = 60;

const EXTENSION_MIN_LEN: usize = 8;
const FRAGMENT_OFFSET_MASK: u16 = 0xfff8;
const MORE_FRAGMENTS: u16 = 0x0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Fragment {
    pub offset: u16,
    pub more_fragments: bool,
    pub identification: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Header {
    pub payload_length: u16,
    pub protocol: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub header_len: usize,
    pub fragment: Option<Ipv6Fragment>,
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

        let mut protocol = bytes[6];
        let mut offset = HEADER_LEN;
        let mut fragment = None;

        while matches!(
            protocol,
            HOP_BY_HOP | ROUTING | FRAGMENT | AUTHENTICATION | DESTINATION_OPTIONS
        ) {
            if protocol == HOP_BY_HOP && offset != HEADER_LEN {
                return Err(YeyoError::Malformed {
                    layer: Layer::Ipv6Extension,
                    reason: format!(
                        "hop-by-hop header at offset {offset}, must directly follow the IPv6 header"
                    ),
                });
            }
            if bytes.len() < offset + EXTENSION_MIN_LEN {
                return Err(truncated(offset + EXTENSION_MIN_LEN, bytes.len()));
            }

            let ext_len = match protocol {
                FRAGMENT => EXTENSION_MIN_LEN,
                AUTHENTICATION => (bytes[offset + 1] as usize + 2) * 4,
                _ => (bytes[offset + 1] as usize + 1) * 8,
            };
            if bytes.len() < offset + ext_len {
                return Err(truncated(offset + ext_len, bytes.len()));
            }

            let mut later_fragment = false;
            if protocol == FRAGMENT {
                let field = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
                let frag = Ipv6Fragment {
                    offset: field & FRAGMENT_OFFSET_MASK,
                    more_fragments: field & MORE_FRAGMENTS != 0,
                    identification: u32::from_be_bytes([
                        bytes[offset + 4],
                        bytes[offset + 5],
                        bytes[offset + 6],
                        bytes[offset + 7],
                    ]),
                };
                later_fragment = frag.offset > 0;
                fragment = Some(frag);
            }

            protocol = bytes[offset];
            offset += ext_len;

            if later_fragment {
                break;
            }
        }

        let mut src = [0u8; 16];
        src.copy_from_slice(&bytes[8..24]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&bytes[24..40]);

        Ok(Ipv6Header {
            payload_length: u16::from_be_bytes([bytes[4], bytes[5]]),
            protocol,
            hop_limit: bytes[7],
            src: Ipv6Addr::from(src),
            dst: Ipv6Addr::from(dst),
            header_len: offset,
            fragment,
        })
    }
}

fn truncated(needed: usize, got: usize) -> YeyoError {
    YeyoError::Truncated {
        layer: Layer::Ipv6Extension,
        needed,
        got,
    }
}
