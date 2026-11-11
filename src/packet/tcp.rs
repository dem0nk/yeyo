use crate::error::{Layer, YeyoError};

const MIN_HEADER_LEN: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const FIN: TcpFlags = TcpFlags(0x01);
    pub const SYN: TcpFlags = TcpFlags(0x02);
    pub const RST: TcpFlags = TcpFlags(0x04);
    pub const PSH: TcpFlags = TcpFlags(0x08);
    pub const ACK: TcpFlags = TcpFlags(0x10);
    pub const URG: TcpFlags = TcpFlags(0x20);
    pub const ECE: TcpFlags = TcpFlags(0x40);
    pub const CWR: TcpFlags = TcpFlags(0x80);

    pub fn contains(self, flag: TcpFlags) -> bool {
        self.0 & flag.0 == flag.0
    }

    pub fn bits(self) -> u8 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub header_len: usize,
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
}

impl TcpHeader {
    pub fn parse(bytes: &[u8]) -> Result<TcpHeader, YeyoError> {
        if bytes.len() < MIN_HEADER_LEN {
            return Err(YeyoError::Truncated {
                layer: Layer::Tcp,
                needed: MIN_HEADER_LEN,
                got: bytes.len(),
            });
        }

        let header_len = (bytes[12] >> 4) as usize * 4;
        if header_len < MIN_HEADER_LEN {
            return Err(YeyoError::Malformed {
                layer: Layer::Tcp,
                reason: format!("header length {header_len}, minimum {MIN_HEADER_LEN}"),
            });
        }
        if bytes.len() < header_len {
            return Err(YeyoError::Truncated {
                layer: Layer::Tcp,
                needed: header_len,
                got: bytes.len(),
            });
        }

        Ok(TcpHeader {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ack: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            header_len,
            flags: TcpFlags(bytes[13]),
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            checksum: u16::from_be_bytes([bytes[16], bytes[17]]),
            urgent_pointer: u16::from_be_bytes([bytes[18], bytes[19]]),
        })
    }
}
