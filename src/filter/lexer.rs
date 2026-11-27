use super::Op;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Kind {
    Word(String),
    Quoted(String),
    Op(Op),
    Not,
    And,
    Or,
    Open,
    Close,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Token {
    pub(super) kind: Kind,
    pub(super) column: usize,
}

pub(super) type Error = (usize, String);

pub(super) const MAX_LEN: usize = 1024;

pub(super) fn tokenize(src: &str) -> Result<Vec<Token>, Error> {
    if src.chars().count() > MAX_LEN {
        return Err((
            MAX_LEN + 1,
            format!("filter is longer than {MAX_LEN} characters"),
        ));
    }

    let chars: Vec<char> = src.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let column = i + 1;
        let next = chars.get(i + 1).copied();
        let (kind, width) = match chars[i] {
            c if c.is_whitespace() => {
                i += 1;
                continue;
            }
            '(' => (Kind::Open, 1),
            ')' => (Kind::Close, 1),
            '=' if next == Some('=') => (Kind::Op(Op::Eq), 2),
            '=' => return Err((column, "expected '=='".to_string())),
            '!' if next == Some('=') => (Kind::Op(Op::Ne), 2),
            '!' => (Kind::Not, 1),
            '>' if next == Some('=') => (Kind::Op(Op::Ge), 2),
            '>' => (Kind::Op(Op::Gt), 1),
            '<' if next == Some('=') => (Kind::Op(Op::Le), 2),
            '<' => (Kind::Op(Op::Lt), 1),
            '&' if next == Some('&') => (Kind::And, 2),
            '&' => return Err((column, "expected '&&'".to_string())),
            '|' if next == Some('|') => (Kind::Or, 2),
            '|' => return Err((column, "expected '||'".to_string())),
            '"' => quoted(&chars, i)?,
            c if is_word(c) => {
                let len = chars[i..].iter().take_while(|&&c| is_word(c)).count();
                let word: String = chars[i..i + len].iter().collect();
                let kind = match word.as_str() {
                    "and" => Kind::And,
                    "or" => Kind::Or,
                    "not" => Kind::Not,
                    _ => Kind::Word(word),
                };
                (kind, len)
            }
            c => {
                return Err((
                    column,
                    format!("unexpected character '{}'", c.escape_default()),
                ));
            }
        };
        tokens.push(Token { kind, column });
        i += width;
    }
    Ok(tokens)
}

fn quoted(chars: &[char], start: usize) -> Result<(Kind, usize), Error> {
    let mut text = String::new();
    let mut i = start + 1;
    while let Some(&c) = chars.get(i) {
        match c {
            '"' => return Ok((Kind::Quoted(text), i + 1 - start)),
            '\\' => match chars.get(i + 1) {
                Some(&escaped) => {
                    text.push(escaped);
                    i += 2;
                }
                None => break,
            },
            c => {
                text.push(c);
                i += 1;
            }
        }
    }
    Err((start + 1, "unclosed string".to_string()))
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '/' | '-')
}
