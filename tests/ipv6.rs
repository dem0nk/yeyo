mod common;

use std::error::Error;
use std::net::Ipv6Addr;
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::ipv6::Ipv6Header;

const SRC: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
const DST: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111);

#[test]
fn test_parse_header_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::ipv6(6, SRC, DST, &[1, 2, 3, 4]);

    let ip = Ipv6Header::parse(&bytes)?;

    assert_eq!(
        ip,
        Ipv6Header {
            payload_length: 4,
            next_header: 6,
            hop_limit: 64,
            src: SRC,
            dst: DST,
        }
    );
    Ok(())
}

#[test]
fn test_parse_traffic_class_and_flow_label_ignored_ok() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::ipv6(17, SRC, DST, &[]);
    bytes[0..4].copy_from_slice(&[0x6f, 0xff, 0xff, 0xff]);

    let ip = Ipv6Header::parse(&bytes)?;

    assert_eq!(ip.next_header, 17);
    Ok(())
}

#[test]
fn test_parse_one_byte_short_err() {
    let bytes = common::ipv6(6, SRC, DST, &[]);

    let result = Ipv6Header::parse(&bytes[..39]);

    assert_eq!(
        result,
        Err(YeyoError::Truncated {
            layer: Layer::Ipv6,
            needed: 40,
            got: 39
        })
    );
}

#[test]
fn test_parse_wrong_version_err() {
    let mut bytes = common::ipv6(6, SRC, DST, &[]);
    bytes[0] = 0x40;

    assert_eq!(
        Ipv6Header::parse(&bytes),
        Err(YeyoError::Malformed {
            layer: Layer::Ipv6,
            reason: "version 4, expected 6".to_string(),
        })
    );
}
