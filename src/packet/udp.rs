use crate::error::YeyoError;

pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    pub fn parse(bytes: &[u8]) -> Result<UdpHeader, YeyoError> {
        if bytes.len() < 8 {
            return Err(YeyoError::PacketTooShort {
                needed: 8,
                got: bytes.len(),
            });
        }

        Ok(UdpHeader {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            length: u16::from_be_bytes([bytes[4], bytes[5]]),
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }
}
