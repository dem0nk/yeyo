mod common;

use std::error::Error;
use yeyo::error::{Layer, YeyoError};
use yeyo::packet::tcp::{TcpFlags, TcpHeader};

fn flags(bits: u8) -> TcpFlags {
    TcpHeader::parse(&common::tcp(1, 2, bits, &[]))
        .expect("builder produces a valid header")
        .flags
}

#[test]
fn test_parse_minimal_header_ok() -> Result<(), Box<dyn Error>> {
    let bytes = common::tcp(52814, 443, 0x02, &[]);

    let tcp = TcpHeader::parse(&bytes)?;

    assert_eq!(tcp.src_port, 52814);
    assert_eq!(tcp.dst_port, 443);
    assert_eq!(tcp.seq, 1000);
    assert_eq!(tcp.ack, 2000);
    assert_eq!(tcp.header_len, 20);
    assert_eq!(tcp.window, 65535);
    assert_eq!(tcp.checksum, 0);
    assert_eq!(tcp.urgent_pointer, 0);
    assert_eq!(tcp.flags.bits(), 0x02);
    Ok(())
}

#[test]
fn test_flags_each_bit_ok() {
    assert!(flags(0x01).contains(TcpFlags::FIN));
    assert!(flags(0x02).contains(TcpFlags::SYN));
    assert!(flags(0x04).contains(TcpFlags::RST));
    assert!(flags(0x08).contains(TcpFlags::PSH));
    assert!(flags(0x10).contains(TcpFlags::ACK));
    assert!(flags(0x20).contains(TcpFlags::URG));
    assert!(flags(0x40).contains(TcpFlags::ECE));
    assert!(flags(0x80).contains(TcpFlags::CWR));
}

#[test]
fn test_flags_syn_ack_ok() {
    let f = flags(0x12);

    assert!(f.contains(TcpFlags::SYN));
    assert!(f.contains(TcpFlags::ACK));
    assert!(!f.contains(TcpFlags::FIN));
    assert!(!f.contains(TcpFlags::RST));
}

#[test]
fn test_parse_with_options_ok() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::tcp(1, 2, 0x10, &[0; 4]);
    bytes[12] = 0x60;

    let tcp = TcpHeader::parse(&bytes)?;

    assert_eq!(tcp.header_len, 24);
    Ok(())
}

#[test]
fn test_parse_max_header_ok() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::tcp(1, 2, 0x10, &[0; 40]);
    bytes[12] = 0xf0;

    let tcp = TcpHeader::parse(&bytes)?;

    assert_eq!(tcp.header_len, 60);
    Ok(())
}

#[test]
fn test_parse_max_header_one_byte_short_err() {
    let mut bytes = common::tcp(1, 2, 0x10, &[0; 39]);
    bytes[12] = 0xf0;

    assert_eq!(
        TcpHeader::parse(&bytes),
        Err(YeyoError::Truncated {
            layer: Layer::Tcp,
            needed: 60,
            got: 59
        })
    );
}

#[test]
fn test_parse_one_byte_short_err() {
    let bytes = common::tcp(1, 2, 0x02, &[]);

    assert_eq!(
        TcpHeader::parse(&bytes[..19]),
        Err(YeyoError::Truncated {
            layer: Layer::Tcp,
            needed: 20,
            got: 19
        })
    );
}

#[test]
fn test_parse_header_length_too_small_err() {
    let mut bytes = common::tcp(1, 2, 0x02, &[]);
    bytes[12] = 0x40;

    assert_eq!(
        TcpHeader::parse(&bytes),
        Err(YeyoError::Malformed {
            layer: Layer::Tcp,
            reason: "header length 16, minimum 20".to_string(),
        })
    );
}

#[test]
fn test_parse_header_length_zero_err() {
    let mut bytes = common::tcp(1, 2, 0x02, &[]);
    bytes[12] = 0x00;

    assert_eq!(
        TcpHeader::parse(&bytes),
        Err(YeyoError::Malformed {
            layer: Layer::Tcp,
            reason: "header length 0, minimum 20".to_string(),
        })
    );
}
