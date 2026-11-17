use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    pub captured: u64,
    pub kernel: Option<KernelStats>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelStats {
    pub received: u32,
    pub dropped: u32,
    pub if_dropped: u32,
}

impl KernelStats {
    pub(super) fn from_pcap(s: pcap::Stat) -> Self {
        KernelStats {
            received: s.received,
            dropped: s.dropped,
            if_dropped: s.if_dropped,
        }
    }
}

impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} captured", self.captured, packets(self.captured))?;
        if let Some(k) = &self.kernel {
            write!(
                f,
                "\n{} {} received by filter",
                k.received,
                packets(k.received.into())
            )?;
            write!(
                f,
                "\n{} {} dropped by kernel",
                k.dropped,
                packets(k.dropped.into())
            )?;
            if k.if_dropped > 0 {
                write!(
                    f,
                    "\n{} {} dropped by interface",
                    k.if_dropped,
                    packets(k.if_dropped.into())
                )?;
            }
        }
        Ok(())
    }
}

fn packets(n: u64) -> &'static str {
    if n == 1 { "packet" } else { "packets" }
}
