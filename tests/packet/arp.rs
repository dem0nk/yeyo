use crate::common;
use std::error::Error;
use std::net::Ipv4Addr;
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::arp::{Arp, Operation};

const SENDER: [u8; 4] = [10, 0, 0, 1];
const TARGET: [u8; 4] = [10, 0, 0, 2];

fn malformed(bytes: &[u8]) {
    match Arp::parse(bytes) {
        Err(YeyoError::Malformed {
            layer: Layer::Arp,
            reason,
        }) => assert!(reason.contains("only Ethernet/IPv4"), "reason: {reason}"),
        other => panic!("expected malformed ARP, got {other:?}"),
    }
}

#[test]
fn test_arp_request_ok() -> Result<(), Box<dyn Error>> {
    let arp = Arp::parse(&common::arp(1, SENDER, TARGET))?;

    assert_eq!(
        arp,
        Arp {
            operation: Operation::Request,
            sender_mac: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            sender_ip: Ipv4Addr::from(SENDER),
            target_mac: [0; 6],
            target_ip: Ipv4Addr::from(TARGET),
        }
    );
    Ok(())
}

#[test]
fn test_arp_reply_and_other_operations_ok() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        Arp::parse(&common::arp(2, SENDER, TARGET))?.operation,
        Operation::Reply
    );
    assert_eq!(
        Arp::parse(&common::arp(0, SENDER, TARGET))?.operation,
        Operation::Other(0)
    );
    assert_eq!(
        Arp::parse(&common::arp(0xffff, SENDER, TARGET))?.operation,
        Operation::Other(0xffff)
    );
    Ok(())
}

#[test]
fn test_arp_trailing_bytes_ignored_ok() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::arp(1, SENDER, TARGET);
    bytes.extend_from_slice(&[0xee; 18]);

    assert_eq!(Arp::parse(&bytes)?.target_ip, Ipv4Addr::from(TARGET));
    Ok(())
}

#[test]
fn test_arp_exactly_28_bytes_ok() -> Result<(), Box<dyn Error>> {
    assert!(Arp::parse(&common::arp(1, SENDER, TARGET)[..28]).is_ok());
    Ok(())
}

#[test]
fn test_arp_truncated_err() {
    let bytes = common::arp(1, SENDER, TARGET);

    for len in [0, 1, 8, 27] {
        assert_eq!(
            Arp::parse(&bytes[..len]),
            Err(YeyoError::Truncated {
                layer: Layer::Arp,
                needed: 28,
                got: len,
            })
        );
    }
}

#[test]
fn test_arp_wrong_hardware_type_err() {
    let mut bytes = common::arp(1, SENDER, TARGET);
    bytes[1] = 6;

    malformed(&bytes);
}

#[test]
fn test_arp_wrong_protocol_type_err() {
    let mut bytes = common::arp(1, SENDER, TARGET);
    bytes[2..4].copy_from_slice(&0x86ddu16.to_be_bytes());

    malformed(&bytes);
}

#[test]
fn test_arp_wrong_address_lengths_err() {
    let mut bytes = common::arp(1, SENDER, TARGET);
    bytes[4] = 8;
    malformed(&bytes);

    let mut bytes = common::arp(1, SENDER, TARGET);
    bytes[5] = 16;
    malformed(&bytes);
}

#[test]
fn test_arp_all_zero_err() {
    malformed(&[0; 28]);
}
