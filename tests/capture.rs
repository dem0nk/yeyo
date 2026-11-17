mod common;

use pcap::{ConnectionStatus, Device, DeviceFlags, IfFlags};
use std::error::Error;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};
use yeyo::capture::{self, Capture, Frame, Interface};
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

#[test]
fn test_stop_before_read_ends_capture_ok() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("stop_before", &two_frames())?;

    let mut cap = Capture::file(&input)?;
    cap.stopper().stop();
    let result = cap.next_frame()?;
    std::fs::remove_file(&input)?;

    assert!(result.is_none());
    Ok(())
}

#[test]
fn test_stop_mid_capture_saves_frames_so_far_ok() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("stop_mid_in", &two_frames())?;
    let output = std::env::temp_dir().join("yeyo-test-stop_mid_out.pcap");

    let mut cap = Capture::file(&input)?;
    cap.save_to(&output)?;
    let first = cap.next_frame()?.ok_or("missing frame")?;
    cap.stopper().stop();
    let after_stop = cap.next_frame()?;
    cap.finish()?;
    let saved = read_all(&output)?;
    std::fs::remove_file(&input)?;
    std::fs::remove_file(&output)?;

    assert!(after_stop.is_none());
    assert_eq!(saved, vec![first]);
    Ok(())
}

#[test]
fn test_stop_from_another_thread_ok() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("stop_thread", &two_frames())?;

    let mut cap = Capture::file(&input)?;
    let stop = cap.stopper();
    std::thread::spawn(move || stop.stop())
        .join()
        .map_err(|_| "stop thread panicked")?;
    let result = cap.next_frame()?;
    std::fs::remove_file(&input)?;

    assert!(result.is_none());
    Ok(())
}

fn udp_then_tcp() -> Vec<u8> {
    let udp = common::udp(5353, 53, &[]);
    let udp = common::ethernet(
        0x0800,
        &common::ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], &udp),
    );
    let tcp = common::tcp(51000, 80, 0x02, &[]);
    let tcp = common::ethernet(0x0800, &common::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &tcp));
    let mut bytes = common::pcap_header(1);
    bytes.extend(common::pcap_record(&udp, udp.len() as u32));
    bytes.extend(common::pcap_record(&tcp, tcp.len() as u32));
    bytes
}

fn filtered(name: &str, expr: &str) -> Result<Vec<Frame>, Box<dyn Error>> {
    let input = common::temp_file(name, &udp_then_tcp())?;
    let result = Capture::file(&input).and_then(|mut cap| {
        cap.filter(expr)?;
        let mut frames = Vec::new();
        while let Some(frame) = cap.next_frame()? {
            frames.push(frame);
        }
        Ok(frames)
    });
    std::fs::remove_file(&input)?;
    Ok(result?)
}

#[test]
fn test_filter_keeps_matching_only_ok() -> Result<(), Box<dyn Error>> {
    let all = filtered("filter_all", "")?;
    let tcp = filtered("filter_tcp", "tcp port 80")?;

    assert_eq!(all.len(), 2);
    assert_eq!(tcp, vec![all[1].clone()]);
    Ok(())
}

#[test]
fn test_filter_matches_nothing_ok() -> Result<(), Box<dyn Error>> {
    let none = filtered("filter_none", "tcp port 443")?;
    assert!(none.is_empty());
    Ok(())
}

#[test]
fn test_filter_syntax_error_err() {
    let result = filtered("filter_syntax", "tcp prot 80");
    let err = result.err().and_then(|e| e.downcast::<YeyoError>().ok());
    assert!(matches!(
        err.as_deref(),
        Some(YeyoError::CaptureFilter { expr, .. }) if expr == "tcp prot 80"
    ));
}

#[test]
fn test_filter_nul_byte_err() {
    let result = filtered("filter_nul", "tcp\0port 80");
    let err = result.err().and_then(|e| e.downcast::<YeyoError>().ok());
    assert!(matches!(
        err.as_deref(),
        Some(YeyoError::CaptureFilter { .. })
    ));
}

#[test]
fn test_filter_wrong_link_type_err() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("filter_link", &common::pcap_header(0))?;

    let mut cap = Capture::file(&input)?;
    let result = cap.filter("ether host aa:bb:cc:dd:ee:ff");
    std::fs::remove_file(&input)?;

    assert!(matches!(result, Err(YeyoError::CaptureFilter { .. })));
    Ok(())
}

fn time_of(name: &str, sec: u32, usec: u32) -> Result<Frame, Box<dyn Error>> {
    let mut bytes = common::pcap_header(1);
    bytes.extend(common::pcap_record_at(sec, usec, &[1, 2, 3], 3));
    let input = common::temp_file(name, &bytes)?;
    let frame = Capture::file(&input).and_then(|mut cap| cap.next_frame());
    std::fs::remove_file(&input)?;
    Ok(frame?.ok_or("missing frame")?)
}

#[test]
fn test_time_read_ok() -> Result<(), Box<dyn Error>> {
    let frame = time_of("time_read", 1_700_000_000, 123_456)?;
    let expected = UNIX_EPOCH + Duration::new(1_700_000_000, 123_456_000);
    assert_eq!(frame.time, Some(expected));
    Ok(())
}

#[test]
fn test_time_epoch_ok() -> Result<(), Box<dyn Error>> {
    let frame = time_of("time_epoch", 0, 0)?;
    assert_eq!(frame.time, Some(UNIX_EPOCH));
    Ok(())
}

#[test]
fn test_time_max_valid_usec_ok() -> Result<(), Box<dyn Error>> {
    let frame = time_of("time_max_usec", 5, 999_999)?;
    assert_eq!(frame.time, Some(UNIX_EPOCH + Duration::new(5, 999_999_000)));
    Ok(())
}

#[test]
fn test_time_usec_overflow_is_unknown_ok() -> Result<(), Box<dyn Error>> {
    let frame = time_of("time_bad_usec", 5, 1_000_000)?;
    assert_eq!(frame.time, None);
    assert_eq!(frame.data, vec![1, 2, 3]);
    Ok(())
}

#[test]
fn test_time_max_seconds_ok() -> Result<(), Box<dyn Error>> {
    let frame = time_of("time_max_sec", 2_147_483_647, 0)?;
    assert_eq!(
        frame.time,
        Some(UNIX_EPOCH + Duration::from_secs(2_147_483_647))
    );
    Ok(())
}

#[test]
fn test_time_negative_seconds_is_unknown_ok() -> Result<(), Box<dyn Error>> {
    let frame = time_of("time_neg_sec", u32::MAX, 0)?;
    assert_eq!(frame.time, None);
    assert_eq!(frame.data, vec![1, 2, 3]);
    Ok(())
}

#[cfg(unix)]
#[test]
fn test_live_without_privileges_is_permission_denied_err() {
    let loopback = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };

    match Capture::live(Device::from(loopback)) {
        Ok(_) => {}
        Err(e) => assert!(matches!(
            e,
            YeyoError::PermissionDenied { ref device, .. } if device == loopback
        )),
    }
}

#[test]
fn test_live_failure_names_the_device_err() {
    let result = Capture::live(Device::from("yeyo-no-such-device"));
    assert!(matches!(
        result,
        Err(YeyoError::Open { ref device, .. } | YeyoError::PermissionDenied { ref device, .. })
            if device == "yeyo-no-such-device"
    ));
}

fn names_and_defaults(list: &[Interface]) -> Vec<(&str, bool)> {
    list.iter().map(|i| (i.name.as_str(), i.default)).collect()
}

#[test]
fn test_describe_marks_first_usable_as_default_ok() {
    let list = capture::describe(vec![
        dev(
            "ap1",
            up() | IfFlags::WIRELESS,
            ConnectionStatus::Disconnected,
        ),
        dev("en0", up() | IfFlags::WIRELESS, ConnectionStatus::Connected),
        dev("en1", up(), ConnectionStatus::Connected),
    ]);
    assert_eq!(
        names_and_defaults(&list),
        vec![("ap1", false), ("en0", true), ("en1", false)]
    );
}

#[test]
fn test_describe_no_usable_has_no_default_ok() {
    let list = capture::describe(vec![
        dev("ap1", up(), ConnectionStatus::Disconnected),
        dev(
            "lo0",
            up() | IfFlags::LOOPBACK,
            ConnectionStatus::NotApplicable,
        ),
    ]);
    assert!(list.iter().all(|i| !i.default));
}

#[test]
fn test_describe_empty_ok() {
    assert!(capture::describe(Vec::new()).is_empty());
}

#[test]
fn test_labels_wireless_ok() {
    let list = capture::describe(vec![
        dev("en0", up() | IfFlags::WIRELESS, ConnectionStatus::Connected),
        dev(
            "ap1",
            up() | IfFlags::WIRELESS,
            ConnectionStatus::Disconnected,
        ),
    ]);
    assert_eq!(
        list[0].labels,
        vec!["Up", "Running", "Wireless", "Associated"]
    );
    assert_eq!(
        list[1].labels,
        vec!["Up", "Running", "Wireless", "Not associated"]
    );
}

#[test]
fn test_labels_wired_and_loopback_ok() {
    let list = capture::describe(vec![
        dev("eth0", up(), ConnectionStatus::Connected),
        dev("eth1", up(), ConnectionStatus::Disconnected),
        dev(
            "lo0",
            up() | IfFlags::LOOPBACK,
            ConnectionStatus::NotApplicable,
        ),
        dev("utun0", up(), ConnectionStatus::Unknown),
        dev("down0", IfFlags::empty(), ConnectionStatus::Unknown),
    ]);
    assert_eq!(list[0].labels, vec!["Up", "Running", "Connected"]);
    assert_eq!(list[1].labels, vec!["Up", "Running", "Disconnected"]);
    assert_eq!(list[2].labels, vec!["Up", "Running", "Loopback"]);
    assert_eq!(list[3].labels, vec!["Up", "Running"]);
    assert!(list[4].labels.is_empty());
}

#[test]
fn test_interface_display_full_ok() {
    let mut d = dev("any", up(), ConnectionStatus::Connected);
    d.desc = Some(String::from(
        "Pseudo-device that captures on all interfaces",
    ));
    let list = capture::describe(vec![d]);
    assert_eq!(
        list[0].to_string(),
        "any (Pseudo-device that captures on all interfaces) [Up, Running, Connected] (default)"
    );
}

#[test]
fn test_interface_display_bare_ok() {
    let list = capture::describe(vec![dev(
        "down0",
        IfFlags::empty(),
        ConnectionStatus::Unknown,
    )]);
    assert_eq!(list[0].to_string(), "down0");
}
