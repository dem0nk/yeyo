#![allow(dead_code)]

use std::net::Ipv6Addr;
pub fn ipv6(next_header: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let payload_length = payload.len() as u16;
    let mut bytes = vec![0x60, 0x00, 0x00, 0x00];
    bytes.extend_from_slice(&payload_length.to_be_bytes());
    bytes.push(next_header);
    bytes.push(64);
    bytes.extend_from_slice(&src.octets());
    bytes.extend_from_slice(&dst.octets());
    bytes.extend_from_slice(payload);
    bytes
}

pub fn ipv6_ext(next_header: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![next_header, 0, 0, 0, 0, 0, 0, 0];
    bytes.extend_from_slice(payload);
    bytes
}

pub fn ipv6_fragment(next_header: u8, offset: u16, more: bool, id: u32, payload: &[u8]) -> Vec<u8> {
    let field = offset | u16::from(more);
    let mut bytes = vec![next_header, 0];
    bytes.extend_from_slice(&field.to_be_bytes());
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

pub fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    ];
    bytes.extend_from_slice(&ethertype.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

pub fn ipv4(protocol: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total_length = (20 + payload.len()) as u16;
    let mut bytes = vec![0x45, 0x00];
    bytes.extend_from_slice(&total_length.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0, 64, protocol, 0, 0]);
    bytes.extend_from_slice(&src);
    bytes.extend_from_slice(&dst);
    bytes.extend_from_slice(payload);
    bytes
}

pub fn tcp(src_port: u16, dst_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&src_port.to_be_bytes());
    bytes.extend_from_slice(&dst_port.to_be_bytes());
    bytes.extend_from_slice(&1000u32.to_be_bytes());
    bytes.extend_from_slice(&2000u32.to_be_bytes());
    bytes.push(0x50);
    bytes.push(flags);
    bytes.extend_from_slice(&65535u16.to_be_bytes());
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes.extend_from_slice(payload);
    bytes
}

pub fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let length = (8 + payload.len()) as u16;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&src_port.to_be_bytes());
    bytes.extend_from_slice(&dst_port.to_be_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(payload);
    bytes
}

pub fn vlan_tag(id: u16, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = id.to_be_bytes().to_vec();
    bytes.extend_from_slice(&ethertype.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
