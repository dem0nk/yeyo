use crate::common;

use proptest::prelude::*;
use yeyo::packet::Packet;
use yeyo::packet::link::LinkType;

fn link_type() -> impl Strategy<Value = LinkType> {
    prop_oneof![
        Just(LinkType::Ethernet),
        Just(LinkType::Loopback),
        Just(LinkType::Raw),
    ]
}

fn valid_frame() -> Vec<u8> {
    let tcp = common::tcp(51000, 80, 0x18, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    let ip = common::ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], &tcp);
    common::ethernet(0x0800, &ip)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn test_parse_random_bytes_never_panics_ok(
        link in link_type(),
        bytes in prop::collection::vec(any::<u8>(), 0..1500),
    ) {
        let _ = Packet::parse(link, &bytes);
    }

    #[test]
    fn test_parse_mutated_frame_never_panics_ok(
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..16),
        cut in any::<prop::sample::Index>(),
    ) {
        let mut bytes = valid_frame();
        for (at, value) in edits {
            let i = at.index(bytes.len());
            bytes[i] = value;
        }
        let len = cut.index(bytes.len() + 1);
        let _ = Packet::parse(LinkType::Ethernet, &bytes[..len]);
    }
}
