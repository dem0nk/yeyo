use super::stream::{Side, Stream};
use crate::packet::tcp::TcpFlags;
use crate::packet::{Endpoints, Packet, Transport};
use std::collections::HashMap;
use std::net::SocketAddr;

const MAX_CONVERSATIONS: usize = 128;
const PROTO_TCP: u8 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    protocol: u8,
    a: SocketAddr,
    b: SocketAddr,
}

impl Key {
    pub fn new(endpoints: Endpoints) -> Self {
        let (a, b) = if endpoints.src <= endpoints.dst {
            (endpoints.src, endpoints.dst)
        } else {
            (endpoints.dst, endpoints.src)
        };
        Self {
            protocol: endpoints.protocol,
            a,
            b,
        }
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn protocol_name(&self) -> &'static str {
        if self.protocol == PROTO_TCP {
            "TCP"
        } else {
            "UDP"
        }
    }
}

#[derive(Debug)]
pub struct Conversation {
    client: SocketAddr,
    server: SocketAddr,
    packets: u64,
    bytes: u64,
    last_active: u64,
    stream: Stream,
}

impl Conversation {
    pub fn client(&self) -> SocketAddr {
        self.client
    }

    pub fn server(&self) -> SocketAddr {
        self.server
    }

    pub fn packets(&self) -> u64 {
        self.packets
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn stream(&self) -> &Stream {
        &self.stream
    }

    pub fn clear(&mut self) {
        self.stream.clear();
    }

    fn side(&self, src: SocketAddr) -> Side {
        if src == self.client {
            Side::Client
        } else {
            Side::Server
        }
    }
}

#[derive(Debug, Default)]
pub struct Conversations {
    map: HashMap<Key, Conversation>,
    clock: u64,
    pinned: Option<Key>,
}

impl Conversations {
    pub fn record(&mut self, packet: &Packet<'_>, len: u32, text: &str) -> Option<(Key, Side)> {
        let endpoints = packet.endpoints()?;
        let key = Key::new(endpoints);
        if !self.map.contains_key(&key) && self.map.len() >= MAX_CONVERSATIONS {
            self.evict_quietest();
        }
        self.clock += 1;
        let conversation = self.map.entry(key).or_insert_with(|| {
            let (client, server) = roles(packet, endpoints);
            Conversation {
                client,
                server,
                packets: 0,
                bytes: 0,
                last_active: 0,
                stream: Stream::default(),
            }
        });
        conversation.packets += 1;
        conversation.bytes += u64::from(len);
        conversation.last_active = self.clock;
        let side = conversation.side(endpoints.src);
        conversation.stream.push(Some(side), text.to_string());
        Some((key, side))
    }

    pub fn get(&self, key: &Key) -> Option<&Conversation> {
        self.map.get(key)
    }

    pub fn get_mut(&mut self, key: &Key) -> Option<&mut Conversation> {
        self.map.get_mut(key)
    }

    pub fn recent(&self) -> Vec<Key> {
        let mut entries: Vec<(&Key, &Conversation)> = self.map.iter().collect();
        entries.sort_by_key(|(_, conversation)| std::cmp::Reverse(conversation.last_active));
        entries.into_iter().map(|(key, _)| *key).collect()
    }

    pub fn pin(&mut self, key: Option<Key>) {
        self.pinned = key;
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn evict_quietest(&mut self) {
        let quietest = self
            .map
            .iter()
            .filter(|(key, _)| Some(**key) != self.pinned)
            .min_by_key(|(_, conversation)| conversation.last_active)
            .map(|(key, _)| *key);
        if let Some(key) = quietest {
            self.map.remove(&key);
        }
    }
}

fn roles(packet: &Packet<'_>, endpoints: Endpoints) -> (SocketAddr, SocketAddr) {
    match &packet.transport {
        Some(Transport::Tcp(tcp))
            if tcp.flags.contains(TcpFlags::SYN) && tcp.flags.contains(TcpFlags::ACK) =>
        {
            (endpoints.dst, endpoints.src)
        }
        _ => (endpoints.src, endpoints.dst),
    }
}
