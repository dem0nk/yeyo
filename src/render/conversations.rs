use super::stream::{Side, Stream};
use crate::packet::tcp::TcpFlags;
use crate::packet::{Endpoints, Packet, Transport};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

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
        protocol_name(self.protocol)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Connection {
        key: Key,
        client: SocketAddr,
        server: SocketAddr,
    },
    Server {
        protocol: u8,
        client: IpAddr,
        server: SocketAddr,
    },
}

impl Target {
    pub fn connection(key: Key, conversation: &Conversation) -> Self {
        Self::Connection {
            key,
            client: conversation.client,
            server: conversation.server,
        }
    }

    pub fn server(key: Key, conversation: &Conversation) -> Self {
        Self::Server {
            protocol: key.protocol,
            client: conversation.client.ip(),
            server: conversation.server,
        }
    }

    pub fn matches(&self, key: &Key) -> bool {
        match *self {
            Self::Connection { key: wanted, .. } => *key == wanted,
            Self::Server {
                protocol,
                client,
                server,
            } => {
                let other = if key.a == server {
                    key.b
                } else if key.b == server {
                    key.a
                } else {
                    return false;
                };
                key.protocol == protocol && other.ip() == client
            }
        }
    }

    pub fn side(&self, endpoints: &Endpoints) -> Side {
        let server = match *self {
            Self::Connection { server, .. } | Self::Server { server, .. } => server,
        };
        if endpoints.src == server {
            Side::Server
        } else {
            Side::Client
        }
    }
}

#[derive(Debug)]
pub struct Conversation {
    client: SocketAddr,
    server: SocketAddr,
    packets: u64,
    bytes: u64,
    first_seen: u64,
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
}

impl Conversations {
    pub fn record(&mut self, packet: &Packet<'_>, len: u32, text: &str) -> Option<(Key, Side)> {
        let endpoints = packet.endpoints()?;
        let key = Key::new(endpoints);
        if !self.map.contains_key(&key) && self.map.len() >= MAX_CONVERSATIONS {
            self.evict_quietest();
        }
        self.clock += 1;
        let clock = self.clock;
        let conversation = self.map.entry(key).or_insert_with(|| {
            let (client, server) = roles(packet, endpoints);
            Conversation {
                client,
                server,
                packets: 0,
                bytes: 0,
                first_seen: clock,
                last_active: 0,
                stream: Stream::default(),
            }
        });
        conversation.packets += 1;
        conversation.bytes += u64::from(len);
        conversation.last_active = clock;
        let side = conversation.side(endpoints.src);
        conversation.stream.push(Some(side), text.to_string());
        Some((key, side))
    }

    pub fn get(&self, key: &Key) -> Option<&Conversation> {
        self.map.get(key)
    }

    pub fn recent(&self) -> Vec<Key> {
        let mut entries: Vec<(&Key, &Conversation)> = self.map.iter().collect();
        entries.sort_by_key(|(_, conversation)| std::cmp::Reverse(conversation.last_active));
        entries.into_iter().map(|(key, _)| *key).collect()
    }

    pub fn matching(&self, target: &Target) -> Vec<&Conversation> {
        let mut found: Vec<&Conversation> = self
            .map
            .iter()
            .filter(|(key, _)| target.matches(key))
            .map(|(_, conversation)| conversation)
            .collect();
        found.sort_by_key(|conversation| conversation.first_seen);
        found
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

pub(super) fn protocol_name(protocol: u8) -> &'static str {
    if protocol == PROTO_TCP { "TCP" } else { "UDP" }
}
