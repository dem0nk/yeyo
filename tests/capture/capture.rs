use crate::common;

use pcap::Device;
use std::error::Error;
use std::path::Path;
use yeyo::capture::{Capture, Frame, Options};
use yeyo::error::YeyoError;
use yeyo::packet::link::LinkType;
use yeyo::packet::{IpHeader, Packet, Transport};

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

    assert!(matches!(pkt.ip(), Some(IpHeader::V4(_))));
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
    let saved = common::read_all(&output)?;
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
    let saved = common::read_all(&output)?;
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

#[test]
fn test_save_to_same_path_err() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("same_path", &common::two_frames())?;

    let mut cap = Capture::file(&input)?;
    let result = cap.save_to(&input);
    let still_there = common::read_all(&input)?;
    std::fs::remove_file(&input)?;

    assert!(matches!(result, Err(YeyoError::SameFile(_))));
    assert_eq!(still_there.len(), 2);
    Ok(())
}

#[test]
fn test_save_to_hard_link_err() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("hard_link", &common::two_frames())?;
    let link = std::env::temp_dir().join("yeyo-test-hard_link-alias.pcap");
    let _ = std::fs::remove_file(&link);
    std::fs::hard_link(&input, &link)?;

    let mut cap = Capture::file(&input)?;
    let result = cap.save_to(&link);
    let still_there = common::read_all(&input)?;
    std::fs::remove_file(&input)?;
    std::fs::remove_file(&link)?;

    assert!(matches!(result, Err(YeyoError::SameFile(_))));
    assert_eq!(still_there.len(), 2);
    Ok(())
}

#[cfg(unix)]
#[test]
fn test_save_to_symlink_err() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("symlink", &common::two_frames())?;
    let link = std::env::temp_dir().join("yeyo-test-symlink-alias.pcap");
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&input, &link)?;

    let mut cap = Capture::file(&input)?;
    let result = cap.save_to(&link);
    let still_there = common::read_all(&input)?;
    std::fs::remove_file(&input)?;
    std::fs::remove_file(&link)?;

    assert!(matches!(result, Err(YeyoError::SameFile(_))));
    assert_eq!(still_there.len(), 2);
    Ok(())
}

#[test]
fn test_stop_before_read_ends_capture_ok() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("stop_before", &common::two_frames())?;

    let mut cap = Capture::file(&input)?;
    cap.stopper().stop();
    let result = cap.next_frame()?;
    std::fs::remove_file(&input)?;

    assert!(result.is_none());
    Ok(())
}

#[test]
fn test_stop_mid_capture_saves_frames_so_far_ok() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("stop_mid_in", &common::two_frames())?;
    let output = std::env::temp_dir().join("yeyo-test-stop_mid_out.pcap");

    let mut cap = Capture::file(&input)?;
    cap.save_to(&output)?;
    let first = cap.next_frame()?.ok_or("missing frame")?;
    cap.stopper().stop();
    let after_stop = cap.next_frame()?;
    cap.finish()?;
    let saved = common::read_all(&output)?;
    std::fs::remove_file(&input)?;
    std::fs::remove_file(&output)?;

    assert!(after_stop.is_none());
    assert_eq!(saved, vec![first]);
    Ok(())
}

#[test]
fn test_stop_from_another_thread_ok() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("stop_thread", &common::two_frames())?;

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

#[cfg(unix)]
#[test]
fn test_live_without_privileges_is_permission_denied_err() {
    let loopback = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };

    match Capture::live(Device::from(loopback), &Options::default()) {
        Ok(_) => {}
        Err(e) => assert!(matches!(
            e,
            YeyoError::PermissionDenied { ref device, .. } if device == loopback
        )),
    }
}

#[test]
fn test_live_failure_names_the_device_err() {
    let result = Capture::live(Device::from("yeyo-no-such-device"), &Options::default());
    assert!(matches!(
        result,
        Err(YeyoError::Open { ref device, .. } | YeyoError::PermissionDenied { ref device, .. })
            if device == "yeyo-no-such-device"
    ));
}
