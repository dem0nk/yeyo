use crate::error::{Layer, YeyoError};

pub(crate) const HEADER_LEN: usize = 14;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

impl EthernetHeader {
    pub fn parse(bytes: &[u8]) -> Result<EthernetHeader, YeyoError> {
        if bytes.len() < HEADER_LEN {
            return Err(YeyoError::Truncated {
                layer: Layer::Ethernet,
                needed: HEADER_LEN,
                got: bytes.len(),
            });
        }

        Ok(EthernetHeader {
            dst_mac: [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]],
            src_mac: [bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11]],
            ethertype: u16::from_be_bytes([bytes[12], bytes[13]]),
        })
    }
}
