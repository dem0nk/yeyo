mod common;

use std::error::Error;
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::ethernet::EthernetHeader;

#[test]
fn test_parse_exact_header_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::ethernet(0x86dd, &[]);

    let eth = EthernetHeader::parse(&bytes)?;

    assert_eq!(eth.dst_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(eth.src_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    assert_eq!(eth.ethertype, 0x86dd);
    Ok(())
}

#[test]
fn test_parse_with_payload_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::ethernet(0x0800, &[1, 2, 3]);

    let eth = EthernetHeader::parse(&bytes)?;

    assert_eq!(eth.ethertype, 0x0800);
    Ok(())
}

#[test]
fn test_parse_one_byte_short_err() {
    let bytes = common::ethernet(0x0800, &[]);

    let result = EthernetHeader::parse(&bytes[..13]);

    assert_eq!(
        result,
        Err(YeyoError::Truncated {
            layer: Layer::Ethernet,
            needed: 14,
            got: 13,
        })
    );
}

#[test]
fn test_parse_empty_err() {
    let result = EthernetHeader::parse(&[]);

    assert_eq!(
        result,
        Err(YeyoError::Truncated {
            layer: Layer::Ethernet,
            needed: 14,
            got: 0,
        })
    );
}
