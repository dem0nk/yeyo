use crate::error::YeyoError;

pub struct Ipv6Header {
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: [u8; 16],
    pub dst: [u8; 16],
}

impl Ipv6Header {
    pub fn parse(bytes: &[u8]) -> Result<Ipv6Header, YeyoError> {
        if bytes.len() < 40 {
            return Err(YeyoError::PacketTooShort {
                needed: 40,
                got: bytes.len(),
            });
        }

        let version = bytes[0] >> 4;
        if version != 6 {
            return Err(YeyoError::BadIpVersion {
                expected: 6,
                got: version,
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
            src,
            dst,
        })
    }
}
