use crate::error::YeyoError;
use pcap::{ConnectionStatus, Device};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
    pub labels: Vec<&'static str>,
    pub default: bool,
}

impl fmt::Display for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)?;
        if let Some(desc) = &self.description {
            write!(f, " ({desc})")?;
        }
        if !self.labels.is_empty() {
            write!(f, " [{}]", self.labels.join(", "))?;
        }
        if self.default {
            f.write_str(" (default)")?;
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

pub fn interfaces() -> Result<Vec<Interface>, YeyoError> {
    Ok(describe(Device::list()?))
}

pub fn describe(devices: Vec<Device>) -> Vec<Interface> {
    let default = devices.iter().position(is_usable);
    devices
        .into_iter()
        .enumerate()
        .map(|(i, d)| {
            let labels = labels(&d);
            Interface {
                name: d.name,
                description: d.desc,
                labels,
                default: Some(i) == default,
            }
        })
        .collect()
}

fn is_usable(d: &Device) -> bool {
    d.flags.is_up()
        && d.flags.is_running()
        && !d.flags.is_loopback()
        && d.flags.connection_status == ConnectionStatus::Connected
}

fn labels(d: &Device) -> Vec<&'static str> {
    let wireless = d.flags.is_wireless();
    let mut labels = Vec::new();
    if d.flags.is_up() {
        labels.push("Up");
    }
    if d.flags.is_running() {
        labels.push("Running");
    }
    if wireless {
        labels.push("Wireless");
    }
    if d.flags.is_loopback() {
        labels.push("Loopback");
    }
    match d.flags.connection_status {
        ConnectionStatus::Connected if wireless => labels.push("Associated"),
        ConnectionStatus::Connected => labels.push("Connected"),
        ConnectionStatus::Disconnected if wireless => labels.push("Not associated"),
        ConnectionStatus::Disconnected => labels.push("Disconnected"),
        ConnectionStatus::Unknown | ConnectionStatus::NotApplicable => {}
    }
    labels
}
