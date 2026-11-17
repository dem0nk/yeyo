mod common;

use std::error::Error;
use yeyo::capture::{Capture, KernelStats, Stats};

#[test]
fn test_stats_file_counts_frames_ok() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("stats_file", &common::two_frames())?;

    let mut cap = Capture::file(&input)?;
    while cap.next_frame()?.is_some() {}
    let stats = cap.stats()?;
    std::fs::remove_file(&input)?;

    assert_eq!(
        stats,
        Stats {
            captured: 2,
            kernel: None
        }
    );
    Ok(())
}

#[test]
fn test_stats_before_reading_is_zero_ok() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("stats_zero", &common::two_frames())?;

    let mut cap = Capture::file(&input)?;
    let stats = cap.stats()?;
    std::fs::remove_file(&input)?;

    assert_eq!(stats.captured, 0);
    Ok(())
}

#[test]
fn test_stats_count_stops_at_stop_ok() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("stats_stop", &common::two_frames())?;

    let mut cap = Capture::file(&input)?;
    cap.next_frame()?;
    cap.stopper().stop();
    cap.next_frame()?;
    let stats = cap.stats()?;
    std::fs::remove_file(&input)?;

    assert_eq!(stats.captured, 1);
    Ok(())
}

#[test]
fn test_stats_display_file_ok() {
    let stats = Stats {
        captured: 1,
        kernel: None,
    };
    assert_eq!(stats.to_string(), "1 packet captured");
}

#[test]
fn test_stats_display_live_ok() {
    let stats = Stats {
        captured: 1204,
        kernel: Some(KernelStats {
            received: 1210,
            dropped: 6,
            if_dropped: 0,
        }),
    };
    assert_eq!(
        stats.to_string(),
        "1204 packets captured\n1210 packets received by filter\n6 packets dropped by kernel"
    );
}

#[test]
fn test_stats_display_interface_drops_ok() {
    let stats = Stats {
        captured: 0,
        kernel: Some(KernelStats {
            received: 1,
            dropped: 0,
            if_dropped: 1,
        }),
    };
    assert_eq!(
        stats.to_string(),
        "0 packets captured\n1 packet received by filter\n0 packets dropped by kernel\n1 packet dropped by interface"
    );
}
