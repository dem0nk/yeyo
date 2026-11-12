use crate::error::YeyoError;

const DLT_NULL: i32 = 0;
const DLT_EN10MB: i32 = 1;
const DLT_RAW: i32 = 12;
const LINKTYPE_RAW: i32 = 101;
const DLT_LOOP: i32 = 108;
const DLT_IPV4: i32 = 228;
const DLT_IPV6: i32 = 229;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Ethernet,
    Loopback,
    Raw,
}

impl TryFrom<i32> for LinkType {
    type Error = YeyoError;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            DLT_EN10MB => Ok(LinkType::Ethernet),
            DLT_NULL | DLT_LOOP => Ok(LinkType::Loopback),
            DLT_RAW | LINKTYPE_RAW | DLT_IPV4 | DLT_IPV6 => Ok(LinkType::Raw),
            other => Err(YeyoError::UnsupportedLinkType(other)),
        }
    }
}
