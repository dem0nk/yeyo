use std::collections::VecDeque;

const STREAM_LIMIT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Client,
    Server,
}

#[derive(Debug)]
struct Chunk {
    side: Option<Side>,
    text: String,
}

#[derive(Debug, Default)]
pub struct Stream {
    chunks: VecDeque<Chunk>,
    len: usize,
}

impl Stream {
    pub fn push(&mut self, side: Option<Side>, text: String) {
        if text.is_empty() {
            return;
        }
        self.len += text.len();
        self.chunks.push_back(Chunk { side, text });
        self.trim();
    }

    pub fn clear(&mut self) {
        self.chunks.clear();
        self.len = 0;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn text(&self) -> String {
        self.chunks
            .iter()
            .map(|chunk| chunk.text.as_str())
            .collect()
    }

    pub fn parts(&self) -> Vec<(Option<Side>, &str)> {
        self.chunks
            .iter()
            .map(|chunk| (chunk.side, chunk.text.as_str()))
            .collect()
    }

    fn trim(&mut self) {
        while self.len > STREAM_LIMIT {
            let excess = self.len - STREAM_LIMIT;
            let Some(front) = self.chunks.front_mut() else {
                break;
            };
            if front.text.len() <= excess {
                self.len -= front.text.len();
                self.chunks.pop_front();
            } else {
                let mut cut = excess;
                while !front.text.is_char_boundary(cut) {
                    cut += 1;
                }
                front.text.drain(..cut);
                self.len -= cut;
            }
        }
    }
}
