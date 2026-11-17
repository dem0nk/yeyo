use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;
use yeyo::capture::{self, Capture, MAX_SNAPLEN, Options};
use yeyo::error::YeyoError;
use yeyo::packet::link::LinkType;
use yeyo::packet::{IpHeader, Packet, Transport};

/// Live packet sniffer with a peek view
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// Interface to capture on (e.g. en0)
    #[arg(short, long)]
    interface: Option<String>,
    /// Read packets from a .pcap file instead of a live interface
    #[arg(short, long, conflicts_with = "interface")]
    read: Option<PathBuf>,
    /// Save every captured packet to a .pcap file
    #[arg(short, long)]
    write: Option<PathBuf>,
    /// Capture filter in BPF syntax (e.g. "tcp port 80")
    #[arg(short = 'f', long = "capture-filter")]
    capture_filter: Option<String>,
    /// Keep only the first N bytes of each packet
    #[arg(
        short = 's',
        long,
        conflicts_with = "read",
        value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_SNAPLEN))
    )]
    snaplen: Option<u32>,
    /// Don't put the interface into promiscuous mode
    #[arg(short = 'p', long = "no-promiscuous-mode", conflicts_with = "read")]
    no_promisc: bool,
    /// Kernel buffer size in KiB (raise it if packets are dropped by kernel)
    #[arg(
        short = 'B',
        long = "buffer-size",
        value_name = "KiB",
        conflicts_with = "read",
        value_parser = clap::value_parser!(u32).range(1..=2_097_151)
    )]
    buffer_size: Option<u32>,
    /// List capture interfaces and exit
    #[arg(
        short = 'D',
        long,
        conflicts_with_all = [
            "interface", "read", "write", "capture_filter",
            "snaplen", "no_promisc", "buffer_size",
        ]
    )]
    list_interfaces: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("yeyo: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &Args) -> Result<(), YeyoError> {
    if args.list_interfaces {
        for (i, iface) in capture::interfaces()?.iter().enumerate() {
            println!("{}. {iface}", i + 1);
        }
        return Ok(());
    }

    let options = Options {
        snaplen: args.snaplen.unwrap_or(MAX_SNAPLEN),
        promisc: !args.no_promisc,
        buffer_kib: args.buffer_size,
    };

    let mut cap = match &args.read {
        Some(path) => Capture::file(path)?,
        None => Capture::live(capture::device(args.interface.as_deref())?, &options)?,
    };

    let link_type = LinkType::try_from(cap.link_type())?;

    if let Some(expr) = &args.capture_filter {
        cap.filter(expr)?;
    }

    let stop = cap.stopper();
    ctrlc::set_handler(move || stop.stop()).map_err(|e| YeyoError::Signal(e.to_string()))?;

    if let Some(path) = &args.write {
        cap.save_to(path)?;
    }

    while let Some(frame) = cap.next_frame()? {
        let pkt = match Packet::parse(link_type, &frame.data) {
            Ok(pkt) => pkt,
            Err(e) => {
                println!("bad packet: {e}");
                continue;
            }
        };

        match &pkt.ip {
            Some(IpHeader::V6(ip)) => println!("{} -> {}", ip.src, ip.dst),
            Some(IpHeader::V4(ip)) => println!("{} -> {}", ip.src, ip.dst),
            None => {}
        }

        match &pkt.transport {
            Some(Transport::Tcp(tcp)) => println!(
                "    tcp {} -> {} flags={:08b}",
                tcp.src_port,
                tcp.dst_port,
                tcp.flags.bits()
            ),
            Some(Transport::Udp(udp)) => {
                println!("    udp {} -> {}", udp.src_port, udp.dst_port)
            }
            None => {}
        }
    }
    cap.finish()?;
    eprintln!("{}", cap.stats()?);
    Ok(())
}
