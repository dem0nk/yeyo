use crate::error::YeyoError;
use pcap::{Activated, ConnectionStatus, Device};
use std::path::Path;

const SNAPLEN: i32 = 262_144;

pub struct Capture {
    handle: pcap::Capture<dyn Activated>,
}

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
        })
    }

    pub fn link_type(&self) -> i32 {
        self.handle.get_datalink().0
    }

    pub fn next_frame(&mut self) -> Result<Option<Frame>, YeyoError> {
        match self.handle.next_packet() {
            Ok(packet) => Ok(Some(Frame {
                data: packet.data.to_vec(),
                len: packet.header.len,
            })),
            Err(pcap::Error::NoMorePackets) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn file(path: &Path) -> Result<Self, YeyoError> {
        let handle = pcap::Capture::from_file(path)?;
        Ok(Capture {
            handle: handle.into(),
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
