use crate::error::YeyoError;

pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub header_len: usize,
    pub flags: u8,
    pub window: u16,
}

impl TcpHeader {
    pub fn parse(bytes: &[u8]) -> Result<TcpHeader, YeyoError> {
        if bytes.len() < 20 {
            return Err(YeyoError::PacketTooShort {
                needed: 20,
                got: bytes.len(),
            });
        }

        let header_len = (bytes[12] >> 4) as usize * 4;
        if header_len < 20 || bytes.len() < header_len {
            return Err(YeyoError::PacketTooShort {
                needed: header_len.max(20),
                got: bytes.len(),
            });
        }

        Ok(TcpHeader {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            header_len,
            flags: bytes[13],
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
        })
    }
}
