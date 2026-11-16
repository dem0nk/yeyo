mod common;

use pcap::{ConnectionStatus, Device, DeviceFlags, IfFlags};
use std::error::Error;
use std::path::Path;
use yeyo::capture;
use yeyo::capture::{Capture, Frame};
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

#[cfg(unix)]
#[test]
fn test_file_non_utf8_path_err() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let path = Path::new(OsStr::from_bytes(b"/tmp/\xff.pcap"));
    let result = Capture::file(path);
    assert!(matches!(result, Err(YeyoError::InvalidPath(_))));
}

fn read_all(path: &Path) -> Result<Vec<Frame>, YeyoError> {
    let mut cap = Capture::file(path)?;
    let mut frames = Vec::new();
    while let Some(frame) = cap.next_frame()? {
        frames.push(frame);
    }
    Ok(frames)
}

#[test]
fn test_save_round_trip_ok() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::pcap_header(1);
    bytes.extend(common::pcap_record(&[1, 2, 3], 3));
    bytes.extend(common::pcap_record(&[0; 64], 1500));
    let input = common::temp_file("save_in", &bytes)?;
    let output = std::env::temp_dir().join("yeyo-test-save_out.pcap");

    let mut cap = Capture::file(&input)?;
    cap.save_to(&output)?;
    let mut seen = Vec::new();
    while let Some(frame) = cap.next_frame()? {
        seen.push(frame);
    }
    cap.finish()?;
    let saved = read_all(&output)?;
    let link = Capture::file(&output)?.link_type();
    std::fs::remove_file(&input)?;
    std::fs::remove_file(&output)?;

    assert_eq!(saved.len(), 2);
    assert_eq!(saved, seen);
    assert_eq!(saved[1].len, 1500);
    assert_eq!(link, 1);
    Ok(())
}

#[test]
fn test_save_empty_capture_is_valid_file_ok() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("save_empty_in", &common::pcap_header(1))?;
    let output = std::env::temp_dir().join("yeyo-test-save_empty_out.pcap");

    let mut cap = Capture::file(&input)?;
    cap.save_to(&output)?;
    while cap.next_frame()?.is_some() {}
    cap.finish()?;
    let saved = read_all(&output)?;
    std::fs::remove_file(&input)?;
    std::fs::remove_file(&output)?;

    assert!(saved.is_empty());
    Ok(())
}

#[test]
fn test_save_to_missing_dir_err() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("save_bad_dir", &common::pcap_header(1))?;

    let mut cap = Capture::file(&input)?;
    let result = cap.save_to(Path::new("/nonexistent/dir/out.pcap"));
    std::fs::remove_file(&input)?;

    assert!(matches!(result, Err(YeyoError::Capture(_))));
    Ok(())
}

#[cfg(unix)]
#[test]
fn test_save_to_non_utf8_path_err() -> Result<(), Box<dyn Error>> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let input = common::temp_file("save_non_utf8", &common::pcap_header(1))?;

    let mut cap = Capture::file(&input)?;
    let result = cap.save_to(Path::new(OsStr::from_bytes(b"/tmp/\xff.pcap")));
    std::fs::remove_file(&input)?;

    assert!(matches!(result, Err(YeyoError::InvalidPath(_))));
    Ok(())
}

fn two_frames() -> Vec<u8> {
    let mut bytes = common::pcap_header(1);
    bytes.extend(common::pcap_record(&[1, 2, 3], 3));
    bytes.extend(common::pcap_record(&[4, 5], 2));
    bytes
}

#[test]
fn test_save_to_same_path_err() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("same_path", &two_frames())?;

    let mut cap = Capture::file(&input)?;
    let result = cap.save_to(&input);
    let still_there = read_all(&input)?;
    std::fs::remove_file(&input)?;

    assert!(matches!(result, Err(YeyoError::SameFile(_))));
    assert_eq!(still_there.len(), 2);
    Ok(())
}

#[test]
fn test_save_to_hard_link_err() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("hard_link", &two_frames())?;
    let link = std::env::temp_dir().join("yeyo-test-hard_link-alias.pcap");
    let _ = std::fs::remove_file(&link);
    std::fs::hard_link(&input, &link)?;

    let mut cap = Capture::file(&input)?;
    let result = cap.save_to(&link);
    let still_there = read_all(&input)?;
    std::fs::remove_file(&input)?;
    std::fs::remove_file(&link)?;

    assert!(matches!(result, Err(YeyoError::SameFile(_))));
    assert_eq!(still_there.len(), 2);
    Ok(())
}

#[cfg(unix)]
#[test]
fn test_save_to_symlink_err() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("symlink", &two_frames())?;
    let link = std::env::temp_dir().join("yeyo-test-symlink-alias.pcap");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&input, &link)?;

    let mut cap = Capture::file(&input)?;
    let result = cap.save_to(&link);
    let still_there = read_all(&input)?;
    std::fs::remove_file(&input)?;
    std::fs::remove_file(&link)?;

    assert!(matches!(result, Err(YeyoError::SameFile(_))));
    assert_eq!(still_there.len(), 2);
    Ok(())
}
