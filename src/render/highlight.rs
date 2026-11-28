use crate::dissect::METHODS;

const SECRET_HEADERS: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];
const SECRET_KEY_PARTS: [&str; 6] = ["pass", "pwd", "token", "secret", "apikey", "api_key"];
const SECRET_KEYS: [&str; 1] = ["auth"];
const VERSION_PREFIX: &str = "HTTP/1.";
const STATUS_LINE_LEN: usize = 12;
const TOKEN_SYMBOLS: &[u8] = b"!#$%&'*+-.^_`|~";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    Plain,
    Method,
    Header,
    Key,
    Secret,
}

struct Pieces {
    ranges: Vec<(Mark, usize, usize)>,
}

impl Pieces {
    fn push(&mut self, mark: Mark, start: usize, end: usize) {
        if start == end {
            return;
        }
        match self.ranges.last_mut() {
            Some((last, _, last_end)) if *last == mark && *last_end == start => *last_end = end,
            _ => self.ranges.push((mark, start, end)),
        }
    }
}

pub fn marks(text: &str) -> Vec<(Mark, &str)> {
    let mut pieces = Pieces { ranges: Vec::new() };
    let mut in_headers = false;
    let mut start = 0;
    for line in text.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let end = start + body.len();
        if let Some(method) = request_method(body) {
            pieces.push(Mark::Method, start, start + method.len());
            request_rest(&mut pieces, text, start + method.len(), end);
            in_headers = true;
        } else if is_status_line(body) {
            pieces.push(Mark::Method, start, start + STATUS_LINE_LEN);
            pieces.push(Mark::Plain, start + STATUS_LINE_LEN, end);
            in_headers = true;
        } else if in_headers && body.is_empty() {
            in_headers = false;
        } else if in_headers && let Some(colon) = header_colon(body) {
            header(&mut pieces, text, start, start + colon, end);
        } else if is_form_line(body) {
            pairs(&mut pieces, text, start, end);
        } else {
            pieces.push(Mark::Plain, start, end);
        }
        pieces.push(Mark::Plain, end, start + line.len());
        start += line.len();
    }
    pieces
        .ranges
        .into_iter()
        .map(|(mark, start, end)| (mark, &text[start..end]))
        .collect()
}

fn request_method(line: &str) -> Option<&str> {
    let (method, _) = line.split_once(' ')?;
    METHODS.contains(&method).then_some(method)
}

fn request_rest(pieces: &mut Pieces, text: &str, start: usize, end: usize) {
    let Some(question) = text[start..end].find('?').map(|at| start + at) else {
        pieces.push(Mark::Plain, start, end);
        return;
    };
    pieces.push(Mark::Plain, start, question + 1);
    let query_end = text[question + 1..end]
        .find(' ')
        .map_or(end, |at| question + 1 + at);
    pairs(pieces, text, question + 1, query_end);
    pieces.push(Mark::Plain, query_end, end);
}

fn is_status_line(line: &str) -> bool {
    let bytes = line.as_bytes();
    line.starts_with(VERSION_PREFIX)
        && bytes.len() >= STATUS_LINE_LEN
        && bytes[7].is_ascii_digit()
        && bytes[8] == b' '
        && bytes[9..STATUS_LINE_LEN].iter().all(u8::is_ascii_digit)
        && bytes.get(STATUS_LINE_LEN).is_none_or(|&byte| byte == b' ')
}

fn header_colon(line: &str) -> Option<usize> {
    let colon = line.find(':')?;
    let name = &line.as_bytes()[..colon];
    let valid = !name.is_empty()
        && name
            .iter()
            .all(|&byte| byte.is_ascii_alphanumeric() || TOKEN_SYMBOLS.contains(&byte));
    valid.then_some(colon)
}

fn header(pieces: &mut Pieces, text: &str, start: usize, colon: usize, end: usize) {
    pieces.push(Mark::Header, start, colon);
    let value = text[colon..end]
        .find(|c: char| c != ':' && c != ' ')
        .map_or(end, |at| colon + at);
    pieces.push(Mark::Plain, colon, value);
    let name = &text[start..colon];
    let secret = SECRET_HEADERS
        .iter()
        .any(|header| header.eq_ignore_ascii_case(name));
    let mark = if secret { Mark::Secret } else { Mark::Plain };
    pieces.push(mark, value, end);
}

fn is_form_line(line: &str) -> bool {
    line.contains('=') && !line.contains(char::is_whitespace)
}

fn pairs(pieces: &mut Pieces, text: &str, start: usize, end: usize) {
    let mut pair_start = start;
    while pair_start <= end {
        let pair_end = text[pair_start..end]
            .find('&')
            .map_or(end, |at| pair_start + at);
        match text[pair_start..pair_end].find('=') {
            Some(at) => {
                let eq = pair_start + at;
                pieces.push(Mark::Key, pair_start, eq);
                pieces.push(Mark::Plain, eq, eq + 1);
                let mark = if is_secret_key(&text[pair_start..eq]) {
                    Mark::Secret
                } else {
                    Mark::Plain
                };
                pieces.push(mark, eq + 1, pair_end);
            }
            None => pieces.push(Mark::Plain, pair_start, pair_end),
        }
        pieces.push(Mark::Plain, pair_end, (pair_end + 1).min(end));
        pair_start = pair_end + 1;
    }
}

fn is_secret_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    SECRET_KEY_PARTS.iter().any(|part| key.contains(part)) || SECRET_KEYS.contains(&key.as_str())
}
