mod common;

use std::error::Error;
use std::io::{BufRead, BufReader};
use std::process::{Command, Output, Stdio};

fn yeyo(args: &[&str]) -> std::io::Result<Output> {
    Command::new(env!("CARGO_BIN_EXE_yeyo")).args(args).output()
}

fn rejected(args: &[&str], mentions: &str) -> Result<(), Box<dyn Error>> {
    let out = yeyo(args)?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "args {args:?}, stderr: {stderr}"
    );
    assert!(stderr.contains(mentions), "args {args:?}, stderr: {stderr}");
    Ok(())
}

fn accepted(args: &[&str]) -> Result<(), Box<dyn Error>> {
    let out = yeyo(args)?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(1),
        "args {args:?}, stderr: {stderr}"
    );
    assert!(
        stderr.contains("yeyo-no-such-device"),
        "args {args:?}, stderr: {stderr}"
    );
    Ok(())
}

#[test]
fn test_snaplen_zero_err() -> Result<(), Box<dyn Error>> {
    rejected(&["-s", "0"], "--snaplen")
}

#[test]
fn test_snaplen_too_large_err() -> Result<(), Box<dyn Error>> {
    rejected(&["-s", "262145"], "--snaplen")
}

#[test]
fn test_snaplen_not_a_number_err() -> Result<(), Box<dyn Error>> {
    rejected(&["-s", "abc"], "--snaplen")
}

#[test]
fn test_buffer_zero_err() -> Result<(), Box<dyn Error>> {
    rejected(&["-B", "0"], "--buffer-size")
}

#[test]
fn test_buffer_too_large_err() -> Result<(), Box<dyn Error>> {
    rejected(&["-B", "2097152"], "--buffer-size")
}

#[test]
fn test_capture_options_conflict_with_read_err() -> Result<(), Box<dyn Error>> {
    rejected(&["-r", "x.pcap", "-s", "96"], "cannot be used with")?;
    rejected(&["-r", "x.pcap", "-p"], "cannot be used with")?;
    rejected(&["-r", "x.pcap", "-B", "1024"], "cannot be used with")
}

#[test]
fn test_list_conflicts_with_capture_options_err() -> Result<(), Box<dyn Error>> {
    rejected(&["-D", "-s", "96"], "cannot be used with")
}

#[test]
fn test_option_boundaries_accepted_ok() -> Result<(), Box<dyn Error>> {
    let dev = ["-i", "yeyo-no-such-device"];
    accepted(&[&dev[..], &["-s", "1"]].concat())?;
    accepted(&[&dev[..], &["-s", "262144"]].concat())?;
    accepted(&[&dev[..], &["-B", "1"]].concat())?;
    accepted(&[&dev[..], &["-B", "2097151"]].concat())?;
    accepted(&[&dev[..], &["-p"]].concat())
}

#[test]
fn test_closed_pipe_stops_quietly_ok() -> Result<(), Box<dyn Error>> {
    let ip = common::ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], &common::udp(1, 2, &[]));
    let mut bytes = common::pcap_header(101);
    for _ in 0..100_000 {
        bytes.extend(common::pcap_record(&ip, ip.len() as u32));
    }
    let path = common::temp_file("cli-closed-pipe", &bytes)?;

    let mut child = Command::new(env!("CARGO_BIN_EXE_yeyo"))
        .arg("-r")
        .arg(&path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut first = String::new();
    BufReader::new(child.stdout.take().ok_or("no stdout")?).read_line(&mut first)?;
    let out = child.wait_with_output()?;
    std::fs::remove_file(&path)?;

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(first.contains("UDP"), "first line: {first}");
    assert_eq!(out.status.code(), Some(0), "stderr: {stderr}");
    assert!(stderr.contains("packets captured"), "stderr: {stderr}");
    Ok(())
}
