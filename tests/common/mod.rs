#![allow(dead_code)]

use std::net::Ipv6Addr;
use std::path::Path;
use std::path::PathBuf;
use yeyo::capture::{Capture, Frame};
use yeyo::error::YeyoError;

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

pub fn loopback(family: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = family.to_le_bytes().to_vec();
    bytes.extend_from_slice(payload);
    bytes
}

pub fn pcap_header(link_type: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    b.extend_from_slice(&2u16.to_le_bytes());
    b.extend_from_slice(&4u16.to_le_bytes());
    b.extend_from_slice(&0i32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&262_144u32.to_le_bytes());
    b.extend_from_slice(&link_type.to_le_bytes());
    b
}

pub fn pcap_record(data: &[u8], orig_len: u32) -> Vec<u8> {
    pcap_record_at(1, 0, data, orig_len)
}

pub fn pcap_record_at(sec: u32, usec: u32, data: &[u8], orig_len: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&sec.to_le_bytes());
    b.extend_from_slice(&usec.to_le_bytes());
    b.extend_from_slice(&(data.len() as u32).to_le_bytes());
    b.extend_from_slice(&orig_len.to_le_bytes());
    b.extend_from_slice(data);
    b
}

pub fn temp_file(name: &str, bytes: &[u8]) -> std::io::Result<PathBuf> {
    let path = std::env::temp_dir().join(format!("yeyo-test-{name}.pcap"));
    std::fs::write(&path, bytes)?;
    Ok(path)
}

pub fn two_frames() -> Vec<u8> {
    let mut bytes = pcap_header(1);
    bytes.extend(pcap_record(&[1, 2, 3], 3));
    bytes.extend(pcap_record(&[4, 5], 2));
    bytes
}

pub fn read_all(path: &Path) -> Result<Vec<Frame>, YeyoError> {
    let mut cap = Capture::file(path)?;
    let mut frames = Vec::new();
    while let Some(frame) = cap.next_frame()? {
        frames.push(frame);
    }
    Ok(frames)
}

pub fn icmp(kind: u8, code: u8, rest: [u8; 4]) -> Vec<u8> {
    let mut bytes = vec![kind, code, 0, 0];
    bytes.extend_from_slice(&rest);
    bytes
}

pub fn arp(operation: u16, sender: [u8; 4], target: [u8; 4]) -> Vec<u8> {
    let mut bytes = vec![0, 1, 0x08, 0x00, 6, 4];
    bytes.extend_from_slice(&operation.to_be_bytes());
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    bytes.extend_from_slice(&sender);
    bytes.extend_from_slice(&[0; 6]);
    bytes.extend_from_slice(&target);
    bytes
}
