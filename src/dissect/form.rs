use super::Http;

const FORM_TYPE: &str = "application/x-www-form-urlencoded";
const MAX_PAIRS: usize = 64;

pub fn form(http: &Http) -> Option<Vec<(String, String)>> {
    let content_type = http.content_type()?;
    let media_type = content_type.split(';').next().unwrap_or("").trim();
    if !media_type.eq_ignore_ascii_case(FORM_TYPE) {
        return None;
    }

    let pairs = http
        .body()
        .split(|&byte| byte == b'&')
        .filter(|pair| !pair.is_empty())
        .take(MAX_PAIRS)
        .map(|pair| {
            let (key, value) = match pair.iter().position(|&byte| byte == b'=') {
                Some(at) => (&pair[..at], &pair[at + 1..]),
                None => (pair, &[][..]),
            };
            (decode(key), decode(value))
        })
        .collect();
    Some(pairs)
}

fn decode(bytes: &[u8]) -> String {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                if let (Some(high), Some(low)) = (
                    bytes.get(i + 1).and_then(|&byte| hex(byte)),
                    bytes.get(i + 2).and_then(|&byte| hex(byte)),
                ) {
                    out.push(high << 4 | low);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            byte => out.push(byte),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(byte: u8) -> Option<u8> {
    char::from(byte).to_digit(16).map(|digit| digit as u8)
}
