use crate::common;
use std::error::Error;
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::icmp::{Echo, Icmp, Version};

#[test]
fn test_icmp_echo_request_ok() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::icmp(8, 0, [0x12, 0x34, 0x00, 0x05]);
    bytes[2..4].copy_from_slice(&0xbeefu16.to_be_bytes());

    let icmp = Icmp::parse(Version::V4, &bytes)?;

    assert_eq!(
        icmp,
        Icmp {
            version: Version::V4,
            kind: 8,
            code: 0,
            checksum: 0xbeef,
            echo: Some(Echo { id: 0x1234, seq: 5 }),
            header_len: 8,
        }
    );
    assert_eq!(icmp.name(), Some("echo request"));
    Ok(())
}

#[test]
fn test_icmp_echo_reply_ok() -> Result<(), Box<dyn Error>> {
    let icmp = Icmp::parse(Version::V4, &common::icmp(0, 0, [0, 7, 0xff, 0xff]))?;

    assert_eq!(icmp.echo, Some(Echo { id: 7, seq: 0xffff }));
    assert_eq!(icmp.name(), Some("echo reply"));
    Ok(())
}

#[test]
fn test_icmp_non_echo_has_no_id_ok() -> Result<(), Box<dyn Error>> {
    let icmp = Icmp::parse(Version::V4, &common::icmp(3, 1, [0; 4]))?;

    assert_eq!(icmp.echo, None);
    assert_eq!(icmp.code, 1);
    assert_eq!(icmp.name(), Some("destination unreachable"));
    assert_eq!(icmp.header_len, 8);
    Ok(())
}

#[test]
fn test_icmp_named_types_ok() -> Result<(), Box<dyn Error>> {
    for (kind, name) in [
        (5, "redirect"),
        (11, "time exceeded"),
        (12, "parameter problem"),
    ] {
        let icmp = Icmp::parse(Version::V4, &common::icmp(kind, 0, [0; 4]))?;
        assert_eq!(icmp.name(), Some(name), "type {kind}");
    }
    Ok(())
}

#[test]
fn test_icmp_unknown_type_has_no_name_ok() -> Result<(), Box<dyn Error>> {
    for kind in [1, 42, 128, 255] {
        let icmp = Icmp::parse(Version::V4, &common::icmp(kind, 0, [0; 4]))?;
        assert_eq!(icmp.name(), None, "type {kind}");
        assert_eq!(icmp.kind, kind);
    }
    Ok(())
}

#[test]
fn test_icmp_truncated_err() {
    let bytes = common::icmp(3, 0, [0; 4]);

    for len in [0, 1, 4, 7] {
        assert_eq!(
            Icmp::parse(Version::V4, &bytes[..len]),
            Err(YeyoError::Truncated {
                layer: Layer::Icmp,
                needed: 8,
                got: len,
            })
        );
    }
}

#[test]
fn test_icmpv6_neighbor_solicitation_ok() -> Result<(), Box<dyn Error>> {
    let icmp = Icmp::parse(Version::V6, &common::icmp(135, 0, [0; 4]))?;

    assert_eq!(icmp.version, Version::V6);
    assert_eq!(icmp.name(), Some("neighbor solicitation"));
    assert_eq!(icmp.echo, None);
    assert_eq!(icmp.header_len, 4);
    Ok(())
}

#[test]
fn test_icmpv6_named_types_ok() -> Result<(), Box<dyn Error>> {
    for (kind, name) in [
        (1, "destination unreachable"),
        (2, "packet too big"),
        (3, "time exceeded"),
        (4, "parameter problem"),
        (133, "router solicitation"),
        (134, "router advertisement"),
        (136, "neighbor advertisement"),
        (137, "redirect"),
    ] {
        let icmp = Icmp::parse(Version::V6, &common::icmp(kind, 0, [0; 4]))?;
        assert_eq!(icmp.name(), Some(name), "type {kind}");
    }
    Ok(())
}

#[test]
fn test_icmpv6_echo_ok() -> Result<(), Box<dyn Error>> {
    let request = Icmp::parse(Version::V6, &common::icmp(128, 0, [0, 1, 0, 2]))?;
    let reply = Icmp::parse(Version::V6, &common::icmp(129, 0, [0, 1, 0, 2]))?;

    assert_eq!(request.echo, Some(Echo { id: 1, seq: 2 }));
    assert_eq!(request.name(), Some("echo request"));
    assert_eq!(reply.name(), Some("echo reply"));
    assert_eq!(request.header_len, 8);
    Ok(())
}

#[test]
fn test_icmpv6_v4_numbers_are_not_echo_ok() -> Result<(), Box<dyn Error>> {
    let icmp = Icmp::parse(Version::V6, &common::icmp(8, 0, [0, 1, 0, 2]))?;

    assert_eq!(icmp.echo, None);
    assert_eq!(icmp.name(), None);
    Ok(())
}

#[test]
fn test_icmpv6_four_bytes_ok() -> Result<(), Box<dyn Error>> {
    let icmp = Icmp::parse(Version::V6, &[200, 0, 0, 0])?;

    assert_eq!(icmp.kind, 200);
    Ok(())
}

#[test]
fn test_icmpv6_truncated_err() {
    assert_eq!(
        Icmp::parse(Version::V6, &[135, 0, 0]),
        Err(YeyoError::Truncated {
            layer: Layer::Icmpv6,
            needed: 4,
            got: 3,
        })
    );
}

#[test]
fn test_icmpv6_echo_truncated_err() {
    assert_eq!(
        Icmp::parse(Version::V6, &[128, 0, 0, 0, 0, 1]),
        Err(YeyoError::Truncated {
            layer: Layer::Icmpv6,
            needed: 8,
            got: 6,
        })
    );
}
