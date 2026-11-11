use yeyo::error::{Layer, YeyoError};

#[test]
fn test_display_truncated_ok() {
    let err = YeyoError::Truncated {
        layer: Layer::Ipv4,
        needed: 20,
        got: 12,
    };
    assert_eq!(
        err.to_string(),
        "truncated IPv4 header: needed 20 bytes, got 12"
    );
}

#[test]
fn test_display_malformed_ok() {
    let err = YeyoError::Malformed {
        layer: Layer::Tcp,
        reason: String::from("data offset 3, minimum 5"),
    };
    assert_eq!(
        err.to_string(),
        "malformed TCP header: data offset 3, minimum 5"
    );
}

#[test]
fn test_from_pcap_error_ok() {
    let err = YeyoError::from(pcap::Error::NoMorePackets);
    assert_eq!(err, YeyoError::Capture(pcap::Error::NoMorePackets));
}

#[test]
fn test_display_capture_ok() {
    let err = YeyoError::from(pcap::Error::NoMorePackets);
    assert_eq!(
        err.to_string(),
        "capture failed: no more packets to read from the file"
    );
}

#[test]
fn test_display_truncated_multiword_layer_ok() {
    let err = YeyoError::Truncated {
        layer: Layer::Ipv6Extension,
        needed: 8,
        got: 2,
    };
    assert_eq!(
        err.to_string(),
        "truncated IPv6 extension header: needed 8 bytes, got 2"
    );
}

#[test]
fn test_display_unsupported_link_type_ok() {
    let err = YeyoError::UnsupportedLinkType(999);
    assert_eq!(err.to_string(), "unsupported link type 999");
}
