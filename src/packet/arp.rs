use crate::error::{Layer, YeyoError};
use std::net::Ipv4Addr;

pub const LEN: usize = 28;
const HARDWARE_ETHERNET: u16 = 1;
const PROTOCOL_IPV4: u16 = 0x0800;
const MAC_LEN: u8 = 6;
const IPV4_LEN: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Request,
    Reply,
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arp {
    pub operation: Operation,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

impl Arp {
    pub fn parse(bytes: &[u8]) -> Result<Arp, YeyoError> {
        if bytes.len() < LEN {
            return Err(YeyoError::Truncated {
                layer: Layer::Arp,
                needed: LEN,
                got: bytes.len(),
            });
        }

        let hardware = u16::from_be_bytes([bytes[0], bytes[1]]);
        let protocol = u16::from_be_bytes([bytes[2], bytes[3]]);
        let (mac_len, ip_len) = (bytes[4], bytes[5]);
        // The fixed 28-byte layout only holds for Ethernet/IPv4 ARP.
        if hardware != HARDWARE_ETHERNET
            || protocol != PROTOCOL_IPV4
            || mac_len != MAC_LEN
            || ip_len != IPV4_LEN
        {
            return Err(YeyoError::Malformed {
                layer: Layer::Arp,
                reason: format!(
                    "hardware {hardware} protocol 0x{protocol:04x} lengths {mac_len}/{ip_len}, \
                     only Ethernet/IPv4 is supported"
                ),
            });
        }

        let operation = match u16::from_be_bytes([bytes[6], bytes[7]]) {
            1 => Operation::Request,
            2 => Operation::Reply,
            other => Operation::Other(other),
        };
        Ok(Arp {
            operation,
            sender_mac: mac(&bytes[8..14]),
            sender_ip: Ipv4Addr::new(bytes[14], bytes[15], bytes[16], bytes[17]),
            target_mac: mac(&bytes[18..24]),
            target_ip: Ipv4Addr::new(bytes[24], bytes[25], bytes[26], bytes[27]),
        })
    }
}

fn mac(bytes: &[u8]) -> [u8; 6] {
    [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]
}
