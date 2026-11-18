use unicode_width::UnicodeWidthChar;

const TAB: &str = "    ";
const HIDDEN: char = '.';

pub fn printable(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\n' => out.push('\n'),
            '\r' if chars.peek() == Some(&'\n') => {}
            '\t' => out.push_str(TAB),
            c if is_hidden(c) => out.push(HIDDEN),
            c => out.push(c),
        }
    }
    out
}

pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let mut rows = Vec::new();
    if width == 0 {
        return rows;
    }
    for line in text.split('\n') {
        let mut row = String::new();
        let mut used = 0;
        for c in line.chars() {
            let w = c.width().unwrap_or(0);
            if used + w > width && !row.is_empty() {
                rows.push(std::mem::take(&mut row));
                used = 0;
            }
            row.push(c);
            used += w;
        }
        rows.push(row);
    }
    rows
}

fn is_hidden(c: char) -> bool {
    c.is_control()
        || c == char::REPLACEMENT_CHARACTER
        || matches!(
            c,
            '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}
