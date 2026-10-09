#[derive(Debug)]
pub enum YeyoError {
    PacketTooShort { needed: usize, got: usize },
    BadIpVersion { expected: u8, got: u8 },
}
