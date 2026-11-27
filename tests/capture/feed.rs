use crate::common;

use std::error::Error;
use yeyo::capture::Capture;
use yeyo::error::YeyoError;

fn many_frames(count: u32) -> Vec<u8> {
    let mut bytes = common::pcap_header(1);
    for i in 0..count {
        bytes.extend(common::pcap_record(&i.to_be_bytes(), 4));
    }
    bytes
}

#[test]
fn test_feed_delivers_frames_in_order_ok() -> Result<(), Box<dyn Error>> {
    let path = common::temp_file("feed_order", &common::two_frames())?;

    let feed = Capture::file(&path)?.spawn();
    let mut seen = Vec::new();
    while let Some(frame) = feed.recv() {
        seen.push(frame.data);
    }
    let stats = feed.finish()?;
    std::fs::remove_file(&path)?;

    assert_eq!(seen, [vec![1, 2, 3], vec![4, 5]]);
    assert_eq!(stats.captured, 2);
    assert!(stats.kernel.is_none());
    Ok(())
}

#[test]
fn test_feed_empty_file_ok() -> Result<(), Box<dyn Error>> {
    let path = common::temp_file("feed_empty", &common::pcap_header(1))?;

    let feed = Capture::file(&path)?.spawn();
    let first = feed.recv();
    let stats = feed.finish()?;
    std::fs::remove_file(&path)?;

    assert!(first.is_none());
    assert_eq!(stats.captured, 0);
    Ok(())
}

#[test]
fn test_feed_more_frames_than_queue_ok() -> Result<(), Box<dyn Error>> {
    let path = common::temp_file("feed_many", &many_frames(20_000))?;

    let feed = Capture::file(&path)?.spawn();
    let mut count: u32 = 0;
    while let Some(frame) = feed.recv() {
        assert_eq!(frame.data, count.to_be_bytes());
        count += 1;
    }
    let stats = feed.finish()?;
    std::fs::remove_file(&path)?;

    assert_eq!(count, 20_000);
    assert_eq!(stats.captured, 20_000);
    Ok(())
}

#[test]
fn test_feed_finish_early_does_not_hang_ok() -> Result<(), Box<dyn Error>> {
    let path = common::temp_file("feed_early", &many_frames(100_000))?;

    let feed = Capture::file(&path)?.spawn();
    let first = feed.recv();
    let stats = feed.finish()?;
    std::fs::remove_file(&path)?;

    assert!(first.is_some());
    assert!(stats.captured < 100_000, "captured {}", stats.captured);
    Ok(())
}

#[test]
fn test_feed_finish_early_saves_every_captured_frame_ok() -> Result<(), Box<dyn Error>> {
    let input = common::temp_file("feed_early_save_in", &many_frames(100_000))?;
    let output = std::env::temp_dir().join("yeyo-test-feed_early_save_out.pcap");

    let mut cap = Capture::file(&input)?;
    cap.save_to(&output)?;
    let feed = cap.spawn();
    feed.recv();
    let stats = feed.finish()?;
    let saved = common::read_all(&output)?;
    std::fs::remove_file(&input)?;
    std::fs::remove_file(&output)?;

    assert_eq!(saved.len() as u64, stats.captured);
    Ok(())
}

#[test]
fn test_feed_stop_ends_feed_ok() -> Result<(), Box<dyn Error>> {
    let path = common::temp_file("feed_stop", &many_frames(100_000))?;

    let cap = Capture::file(&path)?;
    let stop = cap.stopper();
    let feed = cap.spawn();
    stop.stop();
    let mut count: u64 = 0;
    while feed.recv().is_some() {
        count += 1;
    }
    let stats = feed.finish()?;
    std::fs::remove_file(&path)?;

    assert_eq!(count, stats.captured);
    assert!(count < 100_000, "received {count}");
    Ok(())
}

#[test]
fn test_feed_read_error_still_flushes_savefile_err() -> Result<(), Box<dyn Error>> {
    let mut bytes = common::two_frames();
    let record = common::pcap_record(&[0; 100], 100);
    bytes.extend(&record[..16 + 10]);
    let input = common::temp_file("feed_error_in", &bytes)?;
    let output = std::env::temp_dir().join("yeyo-test-feed_error_out.pcap");

    let mut cap = Capture::file(&input)?;
    cap.save_to(&output)?;
    let feed = cap.spawn();
    let mut count = 0;
    while feed.recv().is_some() {
        count += 1;
    }
    let result = feed.finish();
    let saved = common::read_all(&output)?;
    std::fs::remove_file(&input)?;
    std::fs::remove_file(&output)?;

    assert_eq!(count, 2);
    assert!(matches!(result, Err(YeyoError::Capture(_))));
    assert_eq!(saved.len(), 2);
    Ok(())
}

#[test]
fn test_feed_try_recv_then_disconnected_ok() -> Result<(), Box<dyn Error>> {
    use std::sync::mpsc::TryRecvError;

    let path = common::temp_file("feed_try_recv", &common::two_frames())?;

    let feed = Capture::file(&path)?.spawn();
    let mut frames = 0;
    let end = loop {
        match feed.try_recv() {
            Ok(_) => frames += 1,
            Err(TryRecvError::Empty) => std::thread::yield_now(),
            Err(e) => break e,
        }
    };
    feed.finish()?;
    std::fs::remove_file(&path)?;

    assert_eq!(frames, 2);
    assert_eq!(end, TryRecvError::Disconnected);
    Ok(())
}
