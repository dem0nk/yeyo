use crate::error::YeyoError;
use pcap::{Activated, ConnectionStatus, Device};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SNAPLEN: i32 = 262_144;
const READ_TIMEOUT_MS: i32 = 100;
const MICROS_PER_SEC: u64 = 1_000_000;

#[derive(Debug, Clone)]
pub struct Stop(Arc<AtomicBool>);

impl Stop {
    pub fn stop(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

pub struct Capture {
    handle: pcap::Capture<dyn Activated>,
    save: Option<pcap::Savefile>,
    source: Option<PathBuf>,
    stop: Arc<AtomicBool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub data: Vec<u8>,
    pub len: u32,
    pub time: Option<SystemTime>,
}

impl Capture {
    pub fn live(device: Device) -> Result<Self, YeyoError> {
        let handle = pcap::Capture::from_device(device)?
            .snaplen(SNAPLEN)
            .timeout(READ_TIMEOUT_MS)
            .immediate_mode(true)
            .open()?;
        Ok(Capture {
            handle: handle.into(),
            save: None,
            source: None,
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn link_type(&self) -> i32 {
        self.handle.get_datalink().0
    }

    pub fn stopper(&self) -> Stop {
        Stop(Arc::clone(&self.stop))
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, YeyoError> {
        loop {
            if self.stop.load(Ordering::Relaxed) {
                return Ok(None);
            }
            match self.handle.next_packet() {
                Ok(packet) => {
                    if let Some(save) = &mut self.save {
                        save.write(&packet);
                    }
                    return Ok(Some(Frame {
                        data: packet.data.to_vec(),
                        len: packet.header.len,
                        time: timestamp(packet.header.ts.tv_sec, packet.header.ts.tv_usec),
                    }));
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(pcap::Error::NoMorePackets) => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }
    }

    pub fn file(path: &Path) -> Result<Self, YeyoError> {
        let handle = pcap::Capture::from_file(utf8(path)?)?;
        Ok(Capture {
            handle: handle.into(),
            save: None,
            source: Some(path.to_path_buf()),
            stop: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn save_to(&mut self, path: &Path) -> Result<(), YeyoError> {
        if let Some(source) = &self.source
            && same_file::is_same_file(source, path).unwrap_or(false)
        {
            return Err(YeyoError::SameFile(path.to_path_buf()));
        }
        self.save = Some(self.handle.savefile(utf8(path)?)?);
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), YeyoError> {
        if let Some(save) = &mut self.save {
            save.flush()?;
        }
        Ok(())
    }

    pub fn filter(&mut self, expr: &str) -> Result<(), YeyoError> {
        self.handle.filter(expr, true).map_err(|e| {
            let reason = match e {
                pcap::Error::PcapError(msg) => msg,
                other => other.to_string(),
            };
            YeyoError::CaptureFilter {
                expr: expr.to_string(),
                reason,
            }
        })
    }
}

pub fn device(name: Option<&str>) -> Result<Device, YeyoError> {
    match name {
        Some(name) => Ok(Device::from(name)),
        None => first_connected(Device::list()?),
    }
}

pub fn first_connected(devices: Vec<Device>) -> Result<Device, YeyoError> {
    devices
        .into_iter()
        .find(is_usable)
        .ok_or(YeyoError::NoDevice)
}

fn is_usable(d: &Device) -> bool {
    d.flags.is_up()
        && d.flags.is_running()
        && !d.flags.is_loopback()
        && d.flags.connection_status == ConnectionStatus::Connected
}

fn utf8(path: &Path) -> Result<&str, YeyoError> {
    path.to_str()
        .ok_or_else(|| YeyoError::InvalidPath(path.to_path_buf()))
}

fn timestamp(sec: impl TryInto<u64>, usec: impl TryInto<u64>) -> Option<SystemTime> {
    let sec = sec.try_into().ok()?;
    let usec = usec.try_into().ok().filter(|&us| us < MICROS_PER_SEC)?;
    UNIX_EPOCH.checked_add(Duration::from_secs(sec) + Duration::from_micros(usec))
}
