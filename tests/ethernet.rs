mod common;

use std::error::Error;
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::ethernet::{EthernetHeader, VlanTag};

#[test]
fn test_parse_exact_header_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::ethernet(0x86dd, &[]);

    let eth = EthernetHeader::parse(&bytes)?;

    assert_eq!(eth.dst_mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    assert_eq!(eth.src_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    assert_eq!(eth.ethertype, 0x86dd);
    assert!(eth.vlans.is_empty());
    assert_eq!(eth.header_len, 14);

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

#[test]
fn test_parse_single_vlan_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::ethernet(0x8100, &common::vlan_tag(100, 0x0800, &[]));

    let eth = EthernetHeader::parse(&bytes)?;

    assert_eq!(
        eth.vlans,
        vec![VlanTag {
            priority: 0,
            drop_eligible: false,
            id: 100
        }]
    );
    assert_eq!(eth.ethertype, 0x0800);
    assert_eq!(eth.header_len, 18);
    Ok(())
}

#[test]
fn test_parse_qinq_ok() -> Result<(), Box<dyn Error>> {
    let inner = common::vlan_tag(100, 0x86dd, &[]);
    let bytes = common::ethernet(0x88a8, &common::vlan_tag(200, 0x8100, &inner));

    let eth = EthernetHeader::parse(&bytes)?;

    assert_eq!(eth.vlans.len(), 2);
    assert_eq!(eth.vlans[0].id, 200);
    assert_eq!(eth.vlans[1].id, 100);
    assert_eq!(eth.ethertype, 0x86dd);
    assert_eq!(eth.header_len, 22);
    Ok(())
}

#[test]
fn test_parse_vlan_tci_fields_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::ethernet(0x8100, &[0xf0, 0x64, 0x08, 0x00]);

    let eth = EthernetHeader::parse(&bytes)?;

    assert_eq!(
        eth.vlans,
        vec![VlanTag {
            priority: 7,
            drop_eligible: true,
            id: 100
        }]
    );
    Ok(())
}

#[test]
fn test_parse_vlan_truncated_err() {
    let bytes = common::ethernet(0x8100, &[0x00, 0x64]);

    let result = EthernetHeader::parse(&bytes);

    assert_eq!(
        result,
        Err(YeyoError::Truncated {
            layer: Layer::Vlan,
            needed: 18,
            got: 16,
        })
    );
}
