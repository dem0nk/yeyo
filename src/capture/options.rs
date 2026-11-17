pub const MAX_SNAPLEN: u32 = 262_144;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub snaplen: u32,
    pub promisc: bool,
    pub buffer_kib: Option<u32>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            snaplen: MAX_SNAPLEN,
            promisc: true,
            buffer_kib: None,
        }
    }
}

impl Options {
    pub(super) fn snaplen_bytes(&self) -> i32 {
        let len = if self.snaplen == 0 || self.snaplen > MAX_SNAPLEN {
            MAX_SNAPLEN
        } else {
            self.snaplen
        };
        i32::try_from(len).unwrap_or(i32::MAX)
    }

    pub(super) fn buffer_bytes(&self) -> Option<i32> {
        self.buffer_kib
            .map(|kib| i32::try_from(u64::from(kib) * 1024).unwrap_or(i32::MAX))
    }
}
