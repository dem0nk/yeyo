mod common;

use std::error::Error;
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::udp::UdpHeader;

fn malformed(reason: &str) -> Result<UdpHeader, YeyoError> {
    Err(YeyoError::Malformed {
        layer: Layer::Udp,
        reason: reason.to_string(),
    })
}

#[test]
fn test_parse_header_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::udp(54321, 53, &[1, 2, 3, 4]);

    let udp = UdpHeader::parse(&bytes)?;

    assert_eq!(
        udp,
        UdpHeader {
            src_port: 54321,
            dst_port: 53,
            length: 12,
            checksum: 0
        }
    );
    Ok(())
}

#[test]
fn test_parse_empty_payload_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::udp(54321, 53, &[]);

    let udp = UdpHeader::parse(&bytes)?;

    assert_eq!(udp.length, 8);
    Ok(())
}

#[test]
fn test_parse_length_beyond_capture_ok() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::udp(54321, 53, &[]);
    bytes[4..6].copy_from_slice(&1000u16.to_be_bytes());

    let udp = UdpHeader::parse(&bytes)?;

    assert_eq!(udp.length, 1000);
    assert_eq!(udp.dst_port, 53);
    Ok(())
}

#[test]
fn test_parse_one_byte_short_err() {
    let bytes = common::udp(54321, 53, &[]);

    assert_eq!(
        UdpHeader::parse(&bytes[..7]),
        Err(YeyoError::Truncated {
            layer: Layer::Udp,
            needed: 8,
            got: 7
        })
    );
}

#[test]
fn test_parse_empty_err() {
    assert_eq!(
        UdpHeader::parse(&[]),
        Err(YeyoError::Truncated {
            layer: Layer::Udp,
            needed: 8,
            got: 0
        })
    );
}

#[test]
fn test_parse_length_below_header_err() {
    let mut bytes = common::udp(54321, 53, &[]);
    bytes[4..6].copy_from_slice(&7u16.to_be_bytes());

    assert_eq!(UdpHeader::parse(&bytes), malformed("length 7, minimum 8"));
}

#[test]
fn test_parse_length_zero_err() {
    let mut bytes = common::udp(54321, 53, &[]);
    bytes[4..6].copy_from_slice(&0u16.to_be_bytes());

    assert_eq!(UdpHeader::parse(&bytes), malformed("length 0, minimum 8"));
}
