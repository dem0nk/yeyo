use super::summary::summary;
use crate::capture::Feed;
use crate::error::YeyoError;
use crate::filter::Filter;
use crate::packet::Packet;
use crate::packet::link::LinkType;
use std::io::{self, ErrorKind, Write};
use std::time::{Duration, SystemTime};

pub struct Lines<W> {
    out: W,
    start: Option<SystemTime>,
}

impl<W: Write> Lines<W> {
    pub fn new(out: W) -> Self {
        Lines { out, start: None }
    }

    pub fn packet(
        &mut self,
        time: Option<SystemTime>,
        len: u32,
        packet: &Packet<'_>,
    ) -> io::Result<()> {
        let time = self.elapsed(time);
        writeln!(self.out, "{time} {} len {len}", summary(packet))
    }

    pub fn bad(&mut self, time: Option<SystemTime>, len: u32, err: &YeyoError) -> io::Result<()> {
        let time = self.elapsed(time);
        writeln!(self.out, "{time} bad packet: {err}, len {len}")
    }

    fn elapsed(&mut self, time: Option<SystemTime>) -> String {
        let time = match time {
            Some(time) => time,
            None => return "?".to_string(),
        };
        let start = *self.start.get_or_insert(time);
        match time.duration_since(start) {
            Ok(ahead) => seconds(ahead),
            Err(behind) => format!("-{}", seconds(behind.duration())),
        }
    }
}

pub fn print_lines(
    feed: &Feed,
    link_type: LinkType,
    filter: Option<&Filter>,
) -> Result<(), YeyoError> {
    let mut lines = Lines::new(io::stdout().lock());
    while let Some(frame) = feed.recv() {
        let written = match (Packet::parse(link_type, &frame.data), filter) {
            (Ok(packet), Some(filter)) if !filter.matches(&packet) => continue,
            (Ok(packet), _) => lines.packet(frame.time, frame.len, &packet),
            (Err(_), Some(_)) => continue,
            (Err(e), None) => lines.bad(frame.time, frame.len, &e),
        };
        match written {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::BrokenPipe => break,
            Err(e) => return Err(YeyoError::Output(e.to_string())),
        }
    }
    Ok(())
}

fn seconds(d: Duration) -> String {
    format!("{}.{:06}", d.as_secs(), d.subsec_micros())
}
