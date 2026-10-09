use crate::error::YeyoError;

pub struct Ipv4Header {
    pub header_len: usize,
    pub total_length: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

impl Ipv4Header {
    pub fn parse(bytes: &[u8]) -> Result<Ipv4Header, YeyoError> {
        if bytes.len() < 20 {
            return Err(YeyoError::PacketTooShort {
                needed: 20,
                got: bytes.len(),
            });
        }

        let version = bytes[0] >> 4;
        if version != 4 {
            return Err(YeyoError::BadIpVersion {
                expected: 4,
                got: version,
            });
        }

        let header_len = (bytes[0] & 0x0f) as usize * 4;
        if header_len < 20 || bytes.len() < header_len {
            return Err(YeyoError::PacketTooShort {
                needed: header_len.max(20),
                got: bytes.len(),
            });
        }

        Ok(Ipv4Header {
            header_len,
            total_length: u16::from_be_bytes([bytes[2], bytes[3]]),
            ttl: bytes[8],
            protocol: bytes[9],
            src: [bytes[12], bytes[13], bytes[14], bytes[15]],
            dst: [bytes[16], bytes[17], bytes[18], bytes[19]],
        })
    }
}
