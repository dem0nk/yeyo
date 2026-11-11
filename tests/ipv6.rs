mod common;

use std::error::Error;
use std::net::Ipv6Addr;
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::ipv6::{Ipv6Fragment, Ipv6Header};

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
            protocol: 6,
            hop_limit: 64,
            src: SRC,
            dst: DST,
            header_len: 40,
            fragment: None
        }
    );
    Ok(())
}

#[test]
fn test_parse_traffic_class_and_flow_label_ignored_ok() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::ipv6(17, SRC, DST, &[]);
    bytes[0..4].copy_from_slice(&[0x6f, 0xff, 0xff, 0xff]);

    let ip = Ipv6Header::parse(&bytes)?;

    assert_eq!(ip.protocol, 17);
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

#[test]
fn test_parse_hop_by_hop_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::ipv6(0, SRC, DST, &common::ipv6_ext(6, &[]));

    let ip = Ipv6Header::parse(&bytes)?;

    assert_eq!(ip.protocol, 6);
    assert_eq!(ip.header_len, 48);
    Ok(())
}

#[test]
fn test_parse_extension_chain_ok() -> Result<(), Box<dyn Error>> {
    let routing = common::ipv6_ext(17, &[]);
    let dest_opts = common::ipv6_ext(43, &routing);
    let bytes = common::ipv6(0, SRC, DST, &common::ipv6_ext(60, &dest_opts));

    let ip = Ipv6Header::parse(&bytes)?;

    assert_eq!(ip.protocol, 17);
    assert_eq!(ip.header_len, 64);
    Ok(())
}

#[test]
fn test_parse_extension_length_field_ok() -> Result<(), Box<dyn Error>> {
    let mut ext = common::ipv6_ext(17, &[0; 8]);
    ext[1] = 1;
    let bytes = common::ipv6(0, SRC, DST, &ext);

    let ip = Ipv6Header::parse(&bytes)?;

    assert_eq!(ip.header_len, 56);
    assert_eq!(ip.protocol, 17);
    Ok(())
}

#[test]
fn test_parse_authentication_header_ok() -> Result<(), Box<dyn Error>> {
    let ah = [6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let bytes = common::ipv6(51, SRC, DST, &ah);

    let ip = Ipv6Header::parse(&bytes)?;

    assert_eq!(ip.header_len, 52);
    assert_eq!(ip.protocol, 6);
    Ok(())
}

#[test]
fn test_parse_first_fragment_ok() -> Result<(), Box<dyn Error>> {
    let frag = common::ipv6_fragment(17, 0, true, 0xdeadbeef, &[]);
    let bytes = common::ipv6(44, SRC, DST, &frag);

    let ip = Ipv6Header::parse(&bytes)?;

    assert_eq!(
        ip.fragment,
        Some(Ipv6Fragment {
            offset: 0,
            more_fragments: true,
            identification: 0xdeadbeef
        })
    );
    assert_eq!(ip.protocol, 17);
    assert_eq!(ip.header_len, 48);
    Ok(())
}

#[test]
fn test_parse_later_fragment_stops_walk_ok() -> Result<(), Box<dyn Error>> {
    let frag = common::ipv6_fragment(43, 1448, false, 7, &[0xff; 8]);
    let bytes = common::ipv6(44, SRC, DST, &frag);

    let ip = Ipv6Header::parse(&bytes)?;

    assert_eq!(ip.protocol, 43);
    assert_eq!(ip.header_len, 48);
    assert_eq!(ip.fragment.map(|f| f.offset), Some(1448));
    Ok(())
}

#[test]
fn test_parse_extension_header_truncated_err() {
    let bytes = common::ipv6(0, SRC, DST, &[6, 0, 0, 0]);

    assert_eq!(
        Ipv6Header::parse(&bytes),
        Err(YeyoError::Truncated {
            layer: Layer::Ipv6Extension,
            needed: 48,
            got: 44
        })
    );
}

#[test]
fn test_parse_extension_length_exceeds_data_err() {
    let mut ext = common::ipv6_ext(6, &[]);
    ext[1] = 1;
    let bytes = common::ipv6(0, SRC, DST, &ext);

    assert_eq!(
        Ipv6Header::parse(&bytes),
        Err(YeyoError::Truncated {
            layer: Layer::Ipv6Extension,
            needed: 56,
            got: 48
        })
    );
}

#[test]
fn test_parse_hop_by_hop_not_first_err() {
    let inner = common::ipv6_ext(0, &common::ipv6_ext(6, &[]));
    let bytes = common::ipv6(60, SRC, DST, &inner);

    assert_eq!(
        Ipv6Header::parse(&bytes),
        Err(YeyoError::Malformed {
            layer: Layer::Ipv6Extension,
            reason: "hop-by-hop header at offset 48, must directly follow the IPv6 header"
                .to_string(),
        })
    );
}
