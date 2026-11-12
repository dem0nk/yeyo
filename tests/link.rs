use yeyo::error::YeyoError;
use yeyo::packet::link::LinkType;

#[test]
fn test_try_from_ethernet_ok() {
    assert_eq!(LinkType::try_from(1), Ok(LinkType::Ethernet));
}

#[test]
fn test_try_from_loopback_ok() {
    assert_eq!(LinkType::try_from(0), Ok(LinkType::Loopback));
    assert_eq!(LinkType::try_from(108), Ok(LinkType::Loopback));
}

#[test]
fn test_try_from_raw_ok() {
    assert_eq!(LinkType::try_from(12), Ok(LinkType::Raw));
    assert_eq!(LinkType::try_from(101), Ok(LinkType::Raw));
    assert_eq!(LinkType::try_from(228), Ok(LinkType::Raw));
    assert_eq!(LinkType::try_from(229), Ok(LinkType::Raw));
}

#[test]
fn test_try_from_unknown_err() {
    assert_eq!(
        LinkType::try_from(147),
        Err(YeyoError::UnsupportedLinkType(147))
    );
}

#[test]
fn test_try_from_negative_err() {
    assert_eq!(
        LinkType::try_from(-1),
        Err(YeyoError::UnsupportedLinkType(-1))
    );
}
