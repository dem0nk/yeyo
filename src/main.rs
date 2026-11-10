use std::net::{Ipv4Addr, Ipv6Addr};
use yeyo::packet::{IpHeader, Packet, Transport};

fn open_bad() -> Result<(), yeyo::error::YeyoError> {
    pcap::Capture::from_device("nope0")?.open()?;
    Ok(())
}

fn main() -> Result<(), pcap::Error> {
    match open_bad() {
        Ok(()) => println!("opened?"),
        Err(e) => println!("{e}"),
    }

    Ok(())
}
