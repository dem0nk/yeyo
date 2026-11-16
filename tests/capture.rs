mod common;

use pcap::{ConnectionStatus, Device, DeviceFlags, IfFlags};
use std::error::Error;
use std::path::Path;
use yeyo::capture;
use yeyo::capture::Capture;
use yeyo::error::YeyoError;
use yeyo::packet::link::LinkType;
use yeyo::packet::{IpHeader, Packet, Transport};

fn dev(name: &str, if_flags: IfFlags, status: ConnectionStatus) -> Device {
    Device {
        name: name.to_string(),
        desc: None,
        addresses: Vec::new(),
        flags: DeviceFlags {
            if_flags,
            connection_status: status,
        },
    }
}

fn up() -> IfFlags {
    IfFlags::UP | IfFlags::RUNNING
}

fn pick(devices: Vec<Device>) -> Result<String, YeyoError> {
    capture::first_connected(devices).map(|d| d.name)
}

#[test]
fn test_first_connected_skips_disconnected_ok() {
    let devices = vec![
        dev("ap1", up(), ConnectionStatus::Disconnected),
        dev("en0", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en0".to_string()));
}

#[test]
fn test_first_connected_keeps_list_order_ok() {
    let devices = vec![
        dev("en0", up(), ConnectionStatus::Connected),
        dev("en1", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en0".to_string()));
}

#[test]
fn test_first_connected_skips_loopback_ok() {
    let devices = vec![
        dev("lo0", up() | IfFlags::LOOPBACK, ConnectionStatus::Connected),
        dev("en0", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en0".to_string()));
}

#[test]
fn test_first_connected_skips_down_ok() {
    let devices = vec![
        dev("en0", IfFlags::RUNNING, ConnectionStatus::Connected),
        dev("en1", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en1".to_string()));
}

#[test]
fn test_first_connected_skips_not_running_ok() {
    let devices = vec![
        dev("en0", IfFlags::UP, ConnectionStatus::Connected),
        dev("en1", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en1".to_string()));
}

#[test]
fn test_first_connected_skips_unknown_status_ok() {
    let devices = vec![
        dev("utun0", up(), ConnectionStatus::Unknown),
        dev("en0", up(), ConnectionStatus::Connected),
    ];
    assert_eq!(pick(devices), Ok("en0".to_string()));
}

#[test]
fn test_first_connected_empty_list_err() {
    assert_eq!(pick(Vec::new()), Err(YeyoError::NoDevice));
}

#[test]
fn test_first_connected_none_usable_err() {
    let devices = vec![
        dev("ap1", up(), ConnectionStatus::Disconnected),
        dev(
            "lo0",
            up() | IfFlags::LOOPBACK,
            ConnectionStatus::NotApplicable,
        ),
    ];
    assert_eq!(pick(devices), Err(YeyoError::NoDevice));
}

#[test]
fn test_device_explicit_name_ok() -> Result<(), YeyoError> {
    let device = capture::device(Some("nope"))?;
    assert_eq!(device.name, "nope");
    Ok(())
}

#[test]
fn test_file_reads_frames_in_order_ok() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::pcap_header(1);
    bytes.extend(common::pcap_record(&[1, 2, 3], 3));
    bytes.extend(common::pcap_record(&[4, 5], 2));
    let path = common::temp_file("in_order", &bytes)?;

    let mut cap = Capture::file(&path)?;
    let first = cap.next_frame()?.ok_or("missing frame 1")?;
    let second = cap.next_frame()?.ok_or("missing frame 2")?;
    let end = cap.next_frame()?;
    std::fs::remove_file(&path)?;

    assert_eq!(first.data, vec![1, 2, 3]);
    assert_eq!(second.data, vec![4, 5]);
    assert!(end.is_none());
    Ok(())
}

#[test]
fn test_file_header_only_is_empty_ok() -> Result<(), Box<dyn Error>> {
    let path = common::temp_file("header_only", &common::pcap_header(1))?;

    let mut cap = Capture::file(&path)?;
    let end = cap.next_frame()?;
    std::fs::remove_file(&path)?;

    assert!(end.is_none());
    Ok(())
}

#[test]
fn test_file_link_type_ok() -> Result<(), Box<dyn Error>> {
    let path = common::temp_file("link_type", &common::pcap_header(0))?;

    let cap = Capture::file(&path)?;
    std::fs::remove_file(&path)?;

    assert_eq!(cap.link_type(), 0);
    Ok(())
}

#[test]
fn test_file_snapped_frame_keeps_original_len_ok() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::pcap_header(1);
    bytes.extend(common::pcap_record(&[0; 64], 1500));
    let path = common::temp_file("snapped", &bytes)?;

    let mut cap = Capture::file(&path)?;
    let frame = cap.next_frame()?.ok_or("missing frame")?;
    std::fs::remove_file(&path)?;

    assert_eq!(frame.data.len(), 64);
    assert_eq!(frame.len, 1500);
    Ok(())
}

#[test]
fn test_file_frame_parses_end_to_end_ok() -> Result<(), Box<dyn Error>> {
    let udp = common::udp(5353, 53, &[]);
    let ip = common::ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], &udp);
    let eth = common::ethernet(0x0800, &ip);
    let mut bytes = common::pcap_header(1);
    bytes.extend(common::pcap_record(&eth, eth.len() as u32));
    let path = common::temp_file("end_to_end", &bytes)?;

    let mut cap = Capture::file(&path)?;
    let link = LinkType::try_from(cap.link_type())?;
    let frame = cap.next_frame()?.ok_or("missing frame")?;
    std::fs::remove_file(&path)?;
    let pkt = Packet::parse(link, &frame.data)?;

    assert!(matches!(pkt.ip, Some(IpHeader::V4(_))));
    assert!(matches!(pkt.transport, Some(Transport::Udp(_))));
    Ok(())
}

#[test]
fn test_file_missing_err() {
    let result = Capture::file(Path::new("/nonexistent/yeyo.pcap"));
    assert!(matches!(result, Err(YeyoError::Capture(_))));
}

#[test]
fn test_file_not_a_pcap_err() -> Result<(), Box<dyn Error>> {
    let path = common::temp_file("garbage", b"this is not a capture file at all")?;

    let result = Capture::file(&path);
    std::fs::remove_file(&path)?;

    assert!(matches!(result, Err(YeyoError::Capture(_))));
    Ok(())
}

#[test]
fn test_file_truncated_record_err() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::pcap_header(1);
    let record = common::pcap_record(&[0; 100], 100);
    bytes.extend(&record[..16 + 10]);
    let path = common::temp_file("truncated", &bytes)?;

    let mut cap = Capture::file(&path)?;
    let result = cap.next_frame();
    std::fs::remove_file(&path)?;

    assert!(result.is_err());
    Ok(())
}
