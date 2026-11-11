use crate::error::{Layer, YeyoError};

const HEADER_LEN: usize = 14;
const TAG_LEN: usize = 4;
const TPID_8021Q: u16 = 0x8100;
const TPID_8021AD: u16 = 0x88a8;
const TPID_QINQ_LEGACY: u16 = 0x9100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VlanTag {
    pub priority: u8,
    pub drop_eligible: bool,
    pub id: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub vlans: Vec<VlanTag>,
    pub ethertype: u16,
    pub header_len: usize,
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

        let mut ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
        let mut offset = HEADER_LEN;
        let mut vlans = Vec::new();

        while matches!(ethertype, TPID_8021Q | TPID_8021AD | TPID_QINQ_LEGACY) {
            if bytes.len() < offset + TAG_LEN {
                return Err(YeyoError::Truncated {
                    layer: Layer::Vlan,
                    needed: offset + TAG_LEN,
                    got: bytes.len(),
                });
            }

            let tci = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            vlans.push(VlanTag {
                priority: (tci >> 13) as u8,
                drop_eligible: tci & 0x1000 != 0,
                id: tci & 0x0fff,
            });
            ethertype = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]);
            offset += TAG_LEN;
        }

        Ok(EthernetHeader {
            dst_mac: [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]],
            src_mac: [bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11]],
            vlans,
            ethertype,
            header_len: offset,
        })
    }
}
