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

#[test]
fn test_display_no_device_ok() {
    assert_eq!(YeyoError::NoDevice.to_string(), "no capture device found");
}

#[test]
fn test_display_invalid_path_ok() {
    let err = YeyoError::InvalidPath(std::path::PathBuf::from("/tmp/x.pcap"));
    assert_eq!(err.to_string(), "path is not valid UTF-8: /tmp/x.pcap");
}

#[test]
fn test_display_same_file_ok() {
    let err = YeyoError::SameFile(std::path::PathBuf::from("a.pcap"));
    assert_eq!(
        err.to_string(),
        "refusing to overwrite the input file a.pcap"
    );
}

#[test]
fn test_display_signal_ok() {
    let err = YeyoError::Signal(String::from("already set"));
    assert_eq!(
        err.to_string(),
        "could not install Ctrl+C handler: already set"
    );
}

#[test]
fn test_display_capture_filter_ok() {
    let err = YeyoError::CaptureFilter {
        expr: String::from("tcp prot 80"),
        reason: String::from("syntax error"),
    };
    assert_eq!(
        err.to_string(),
        "invalid capture filter 'tcp prot 80': syntax error"
    );
}

#[test]
fn test_display_open_ok() {
    let err = YeyoError::Open {
        device: String::from("nope"),
        reason: String::from("No such device exists"),
    };
    assert_eq!(err.to_string(), "cannot open nope: No such device exists");
}

#[test]
fn test_display_permission_denied_ok() {
    let err = YeyoError::PermissionDenied {
        device: String::from("en0"),
        reason: String::from("/dev/bpf0: Permission denied"),
    };
    assert_eq!(
        err.to_string(),
        "cannot open en0: /dev/bpf0: Permission denied\n\
         hint: capturing needs extra privileges; try running with sudo"
    );
}

#[test]
fn test_display_output_ok() {
    let err = YeyoError::Output(String::from("disk full"));
    assert_eq!(err.to_string(), "cannot write output: disk full");
}

#[test]
fn test_display_display_filter_ok() {
    let err = YeyoError::DisplayFilter {
        expr: String::from("tcp.port =="),
        column: 12,
        reason: String::from("expected a value"),
    };
    assert_eq!(
        err.to_string(),
        "invalid display filter 'tcp.port ==': column 12: expected a value"
    );
}

#[test]
fn test_display_display_filter_hides_control_chars_ok() {
    let err = YeyoError::DisplayFilter {
        expr: String::from("tcp\u{1b}[2J"),
        column: 4,
        reason: String::from("unexpected character"),
    };
    assert_eq!(
        err.to_string(),
        "invalid display filter 'tcp.[2J': column 4: unexpected character"
    );
}
