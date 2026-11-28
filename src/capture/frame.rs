use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MICROS_PER_SEC: u64 = 1_000_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub data: Vec<u8>,
    pub len: u32,
    pub time: Option<SystemTime>,
}

impl Frame {
    pub(super) fn from_packet(packet: &pcap::Packet<'_>) -> Self {
        Frame {
            data: packet.data.to_vec(),
            len: packet.header.len,
            time: timestamp(packet.header.ts.tv_sec, packet.header.ts.tv_usec),
        }
    }
}

fn timestamp(sec: impl TryInto<u64>, usec: impl TryInto<u64>) -> Option<SystemTime> {
    let sec = sec.try_into().ok()?;
    // Corrupt savefiles can hold negative or out-of-range times; show them as unknown.
    let usec = usec.try_into().ok().filter(|&us| us < MICROS_PER_SEC)?;
    UNIX_EPOCH.checked_add(Duration::from_secs(sec) + Duration::from_micros(usec))
}
