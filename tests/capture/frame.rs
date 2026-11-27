use crate::common;

use std::error::Error;
use std::time::{Duration, UNIX_EPOCH};
use yeyo::capture::{Capture, Frame};

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
