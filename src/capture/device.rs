use crate::error::YeyoError;
use pcap::{ConnectionStatus, Device};

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
