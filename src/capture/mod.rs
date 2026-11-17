mod device;
mod frame;

pub use device::{Interface, describe, device, first_connected, interfaces};
pub use frame::Frame;

use crate::error::YeyoError;
use pcap::{Activated, Device};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const SNAPLEN: i32 = 262_144;
const READ_TIMEOUT_MS: i32 = 100;

pub struct Capture {
    handle: pcap::Capture<dyn Activated>,
    save: Option<pcap::Savefile>,
    source: Option<PathBuf>,
    stop: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub struct Stop(Arc<AtomicBool>);

impl Stop {
    pub fn stop(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

impl Capture {
    pub fn live(device: Device) -> Result<Self, YeyoError> {
        let name = device.name.clone();
        let handle = pcap::Capture::from_device(device)?
            .snaplen(SNAPLEN)
            .timeout(READ_TIMEOUT_MS)
            .immediate_mode(true)
            .open()
            .map_err(|e| open_error(&name, e))?;
        Ok(Self::from_handle(handle.into(), None))
    }

    pub fn file(path: &Path) -> Result<Self, YeyoError> {
        let handle = pcap::Capture::from_file(utf8(path)?)?;
        Ok(Self::from_handle(handle.into(), Some(path.to_path_buf())))
    }

    fn from_handle(handle: pcap::Capture<dyn Activated>, source: Option<PathBuf>) -> Self {
        Capture {
            handle,
            save: None,
            source,
            stop: Arc::new(AtomicBool::new(false)),
        }
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

    pub fn save_to(&mut self, path: &Path) -> Result<(), YeyoError> {
        if let Some(source) = &self.source
            && same_file::is_same_file(source, path).unwrap_or(false)
        {
            return Err(YeyoError::SameFile(path.to_path_buf()));
        }
        self.save = Some(self.handle.savefile(utf8(path)?)?);
        Ok(())
    }

    pub fn stopper(&self) -> Stop {
        Stop(Arc::clone(&self.stop))
    }

    pub fn link_type(&self) -> i32 {
        self.handle.get_datalink().0
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
                    return Ok(Some(Frame::from_packet(&packet)));
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(pcap::Error::NoMorePackets) => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }
    }

    pub fn finish(&mut self) -> Result<(), YeyoError> {
        if let Some(save) = &mut self.save {
            save.flush()?;
        }
        Ok(())
    }
}

fn utf8(path: &Path) -> Result<&str, YeyoError> {
    path.to_str()
        .ok_or_else(|| YeyoError::InvalidPath(path.to_path_buf()))
}

fn open_error(device: &str, e: pcap::Error) -> YeyoError {
    let device = device.to_string();
    match e {
        pcap::Error::PcapError(reason) if is_permission(&reason) => {
            YeyoError::PermissionDenied { device, reason }
        }
        pcap::Error::PcapError(reason) => YeyoError::Open { device, reason },
        other => YeyoError::Open {
            device,
            reason: other.to_string(),
        },
    }
}

fn is_permission(msg: &str) -> bool {
    let msg = msg.to_lowercase();
    msg.contains("permission") || msg.contains("not permitted")
}
