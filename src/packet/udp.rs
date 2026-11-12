use crate::error::{Layer, YeyoError};

const HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn parse(bytes: &[u8]) -> Result<UdpHeader, YeyoError> {
        if bytes.len() < HEADER_LEN {
            return Err(YeyoError::Truncated {
                layer: Layer::Udp,
                needed: HEADER_LEN,
                got: bytes.len(),
            });
        }

        let length = u16::from_be_bytes([bytes[4], bytes[5]]);
        if (length as usize) < HEADER_LEN {
            return Err(YeyoError::Malformed {
                layer: Layer::Udp,
                reason: format!("length {length}, minimum {HEADER_LEN}"),
            });
        }

        Ok(UdpHeader {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            length,
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }
}
