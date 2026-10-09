use crate::error::YeyoError;

pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
}

impl EthernetHeader {
    pub fn parse(bytes: &[u8]) -> Result<EthernetHeader, YeyoError> {
        if bytes.len() < 14 {
            return Err(YeyoError::PacketTooShort {
                needed: 14,
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
