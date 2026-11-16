use crate::error::YeyoError;
use pcap::{Activated, ConnectionStatus, Device};
use std::path::{Path, PathBuf};

const SNAPLEN: i32 = 262_144;

pub struct Capture {
    handle: pcap::Capture<dyn Activated>,
    save: Option<pcap::Savefile>,
    source: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub data: Vec<u8>,
    pub len: u32,
}

impl Capture {
    pub fn live(device: Device) -> Result<Self, YeyoError> {
        let handle = pcap::Capture::from_device(device)?
            .snaplen(SNAPLEN)
            .immediate_mode(true)
            .open()?;
        Ok(Capture {
            handle: handle.into(),
            save: None,
            source: None,
        })
    }

    pub fn link_type(&self) -> i32 {
        self.handle.get_datalink().0
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, YeyoError> {
        match self.handle.next_packet() {
            Ok(packet) => {
                if let Some(save) = &mut self.save {
                    save.write(&packet);
                }
                Ok(Some(Frame {
                    data: packet.data.to_vec(),
                    len: packet.header.len,
                }))
            }
            Err(pcap::Error::NoMorePackets) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn file(path: &Path) -> Result<Self, YeyoError> {
        let handle = pcap::Capture::from_file(utf8(path)?)?;
        Ok(Capture {
            handle: handle.into(),
            save: None,
            source: Some(path.to_path_buf()),
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
