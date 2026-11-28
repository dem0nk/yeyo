pub const METHODS: [&str; 9] = [
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];
const MAX_HEADERS: usize = 64;
const VERSION_PREFIX: &str = "HTTP/1.";
const STATUS_DIGITS: usize = 3;
const TOKEN_SYMBOLS: &[u8] = b"!#$%&'*+-.^_`|~";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<'a> {
    pub name: &'a str,
    pub value: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Http<'a> {
    Request {
        method: &'a str,
        path: &'a str,
        version: &'a str,
        headers: Vec<Header<'a>>,
        body: &'a [u8],
    },
    Response {
        version: &'a str,
        status: u16,
        reason: &'a str,
        headers: Vec<Header<'a>>,
        body: &'a [u8],
    },
}

enum Start<'a> {
    Request {
        method: &'a str,
        path: &'a str,
        version: &'a str,
    },
    Response {
        version: &'a str,
        status: u16,
        reason: &'a str,
    },
}

impl<'a> Http<'a> {
    pub fn parse(payload: &'a [u8]) -> Option<Http<'a>> {
        let (first, rest) = next_line(payload)?;
        let start = start_line(std::str::from_utf8(first).ok()?)?;

        let mut headers = Vec::new();
        let mut body: &[u8] = &[];
        let mut remaining = rest;
        while let Some((line, rest)) = next_line(remaining) {
            remaining = rest;
            if line.is_empty() {
                body = rest;
                break;
            }
            let line = std::str::from_utf8(line).ok()?;
            if headers.len() < MAX_HEADERS
                && let Some(header) = header(line)
            {
                headers.push(header);
            }
        }

        Some(match start {
            Start::Request {
                method,
                path,
                version,
            } => Http::Request {
                method,
                path,
                version,
                headers,
                body,
            },
            Start::Response {
                version,
                status,
                reason,
            } => Http::Response {
                version,
                status,
                reason,
                headers,
                body,
            },
        })
    }

    pub fn method(&self) -> Option<&'a str> {
        match self {
            Http::Request { method, .. } => Some(method),
            Http::Response { .. } => None,
        }
    }

    pub fn headers(&self) -> &[Header<'a>] {
        match self {
            Http::Request { headers, .. } | Http::Response { headers, .. } => headers,
        }
    }

    pub fn body(&self) -> &'a [u8] {
        match self {
            Http::Request { body, .. } | Http::Response { body, .. } => body,
        }
    }

    pub fn header(&self, name: &str) -> Option<&'a str> {
        self.headers()
            .iter()
            .find(|header| header.name.eq_ignore_ascii_case(name))
            .map(|header| header.value)
    }

    pub fn host(&self) -> Option<&'a str> {
        self.header("Host")
    }

    pub fn content_type(&self) -> Option<&'a str> {
        self.header("Content-Type")
    }
}

fn next_line(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let end = bytes.iter().position(|&byte| byte == b'\n')?;
    let line = &bytes[..end];
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    Some((line, &bytes[end + 1..]))
}

fn start_line(line: &str) -> Option<Start<'_>> {
    if line.starts_with(VERSION_PREFIX) {
        let (version, rest) = line.split_once(' ')?;
        if !is_version(version) {
            return None;
        }
        let (code, reason) = rest.split_once(' ').unwrap_or((rest, ""));
        if code.len() != STATUS_DIGITS || !code.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        return Some(Start::Response {
            version,
            status: code.parse().ok()?,
            reason,
        });
    }

    let mut parts = line.split(' ');
    let (method, path, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some()
        || !METHODS.contains(&method)
        || path.is_empty()
        || !is_version(version)
    {
        return None;
    }
    Some(Start::Request {
        method,
        path,
        version,
    })
}

fn is_version(version: &str) -> bool {
    version
        .strip_prefix(VERSION_PREFIX)
        .is_some_and(|minor| minor.len() == 1 && minor.bytes().all(|byte| byte.is_ascii_digit()))
}

fn header(line: &str) -> Option<Header<'_>> {
    let (name, value) = line.split_once(':')?;
    if name.is_empty() || !name.bytes().all(is_token) {
        return None;
    }
    Some(Header {
        name,
        value: value.trim_matches([' ', '\t']),
    })
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || TOKEN_SYMBOLS.contains(&byte)
}
