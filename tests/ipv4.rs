mod common;

use std::error::Error;
use std::net::Ipv4Addr;
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::ipv4::Ipv4Header;

const SRC: [u8; 4] = [192, 168, 1, 2];
const DST: [u8; 4] = [8, 8, 8, 8];

fn malformed(reason: &str) -> Result<Ipv4Header, YeyoError> {
    Err(YeyoError::Malformed {
        layer: Layer::Ipv4,
        reason: reason.to_string(),
    })
}

#[test]
fn test_parse_minimal_header_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::ipv4(17, SRC, DST, &[1, 2, 3, 4]);

    let ip = Ipv4Header::parse(&bytes)?;

    assert_eq!(
        ip,
        Ipv4Header {
            header_len: 20,
            total_length: 24,
            ttl: 64,
            protocol: 17,
            src: Ipv4Addr::new(192, 168, 1, 2),
            dst: Ipv4Addr::new(8, 8, 8, 8),
        }
    );
    Ok(())
}

#[test]
fn test_parse_with_options_ok() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::ipv4(6, SRC, DST, &[0; 4]);
    bytes[0] = 0x46;

    let ip = Ipv4Header::parse(&bytes)?;

    assert_eq!(ip.header_len, 24);
    Ok(())
}

#[test]
fn test_parse_one_byte_short_err() {
    let bytes = common::ipv4(17, SRC, DST, &[]);

    let result = Ipv4Header::parse(&bytes[..19]);

    assert_eq!(
        result,
        Err(YeyoError::Truncated {
            layer: Layer::Ipv4,
            needed: 20,
            got: 19
        })
    );
}

#[test]
fn test_parse_options_truncated_err() {
    let mut bytes = common::ipv4(17, SRC, DST, &[]);
    bytes[0] = 0x46;

    let result = Ipv4Header::parse(&bytes);

    assert_eq!(
        result,
        Err(YeyoError::Truncated {
            layer: Layer::Ipv4,
            needed: 24,
            got: 20
        })
    );
}

#[test]
fn test_parse_wrong_version_err() {
    let mut bytes = common::ipv4(17, SRC, DST, &[]);
    bytes[0] = 0x65;

    assert_eq!(
        Ipv4Header::parse(&bytes),
        malformed("version 6, expected 4")
    );
}

#[test]
fn test_parse_header_length_too_small_err() {
    let mut bytes = common::ipv4(17, SRC, DST, &[]);
    bytes[0] = 0x44;

    assert_eq!(
        Ipv4Header::parse(&bytes),
        malformed("header length 16, minimum 20")
    );
}

#[test]
fn test_parse_total_length_too_small_err() {
    let mut bytes = common::ipv4(17, SRC, DST, &[]);
    bytes[2..4].copy_from_slice(&16u16.to_be_bytes());

    assert_eq!(
        Ipv4Header::parse(&bytes),
        malformed("total length 16, smaller than header length 20")
    );
}
