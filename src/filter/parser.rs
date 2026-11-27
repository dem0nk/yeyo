use super::lexer::{Error, Kind, Token};
use super::{Expr, Field, Net, Op, Value};
use std::net::IpAddr;

pub(super) const MAX_DEPTH: usize = 32;

const PROTOCOLS: [(&str, u16); 4] = [("icmp", 1), ("tcp", 6), ("udp", 17), ("icmpv6", 58)];

enum Type {
    Presence,
    Address,
    Port,
    Protocol,
    Text,
}

struct Parser<'t> {
    tokens: &'t [Token],
    pos: usize,
    end: usize,
    depth: usize,
}

pub(super) fn parse(tokens: &[Token], src: &str) -> Result<Expr, Error> {
    let mut parser = Parser {
        tokens,
        pos: 0,
        end: src.chars().count() + 1,
        depth: 0,
    };
    let expr = parser.or()?;
    match parser.peek() {
        None => Ok(expr),
        Some(token) => Err((
            token.column,
            "expected '&&', '||' or end of filter".to_string(),
        )),
    }
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn column(&self) -> usize {
        self.peek().map_or(self.end, |token| token.column)
    }

    fn eat(&mut self, kind: &Kind) -> Option<usize> {
        let token = self.peek().filter(|token| token.kind == *kind)?;
        let column = token.column;
        self.pos += 1;
        Some(column)
    }

    fn or(&mut self) -> Result<Expr, Error> {
        let mut left = self.and()?;
        while self.eat(&Kind::Or).is_some() {
            left = Expr::Or(Box::new(left), Box::new(self.and()?));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, Error> {
        let mut left = self.not()?;
        while self.eat(&Kind::And).is_some() {
            left = Expr::And(Box::new(left), Box::new(self.not()?));
        }
        Ok(left)
    }

    fn not(&mut self) -> Result<Expr, Error> {
        if let Some(column) = self.eat(&Kind::Not) {
            self.enter(column)?;
            let inner = self.not()?;
            self.depth -= 1;
            return Ok(Expr::Not(Box::new(inner)));
        }
        if let Some(column) = self.eat(&Kind::Open) {
            self.enter(column)?;
            let inner = self.or()?;
            if self.eat(&Kind::Close).is_none() {
                return Err((self.column(), "expected ')'".to_string()));
            }
            self.depth -= 1;
            return Ok(inner);
        }
        self.comparison()
    }

    fn enter(&mut self, column: usize) -> Result<(), Error> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err((
                column,
                format!("filter is nested more than {MAX_DEPTH} levels deep"),
            ));
        }
        Ok(())
    }

    fn comparison(&mut self) -> Result<Expr, Error> {
        let column = self.column();
        let Some(Token {
            kind: Kind::Word(name),
            ..
        }) = self.peek()
        else {
            return Err((column, "expected a field".to_string()));
        };
        let field = field(name).ok_or_else(|| (column, format!("unknown field '{name}'")))?;
        self.pos += 1;

        let Some(&Token {
            kind: Kind::Op(op),
            column: op_column,
        }) = self.peek()
        else {
            return Ok(Expr::Has(field));
        };
        self.pos += 1;

        let kind = kind(field);
        let ordered = matches!(op, Op::Gt | Op::Lt | Op::Ge | Op::Le);
        match kind {
            Type::Presence => {
                return Err((
                    op_column,
                    format!("'{}' can't be compared; use it alone", name_of(field)),
                ));
            }
            Type::Address | Type::Text if ordered => {
                return Err((
                    op_column,
                    format!("'{}' only supports '==' and '!='", name_of(field)),
                ));
            }
            _ => {}
        }

        let column = self.column();
        let text = match self.peek().map(|token| &token.kind) {
            Some(Kind::Word(text) | Kind::Quoted(text)) => text.clone(),
            _ => return Err((column, "expected a value".to_string())),
        };
        self.pos += 1;
        let value = value(&kind, &text).ok_or_else(|| (column, invalid(&kind, &text)))?;
        Ok(Expr::Cmp(field, op, value))
    }
}

const FIELDS: [(&str, Field); 16] = [
    ("ip", Field::Ip),
    ("ip.src", Field::IpSrc),
    ("ip.dst", Field::IpDst),
    ("ip.addr", Field::IpAddr),
    ("ip.proto", Field::IpProto),
    ("tcp", Field::Tcp),
    ("tcp.port", Field::TcpPort),
    ("tcp.srcport", Field::TcpSrcPort),
    ("tcp.dstport", Field::TcpDstPort),
    ("udp", Field::Udp),
    ("udp.port", Field::UdpPort),
    ("udp.srcport", Field::UdpSrcPort),
    ("udp.dstport", Field::UdpDstPort),
    ("http", Field::Http),
    ("http.request.method", Field::HttpMethod),
    ("http.host", Field::HttpHost),
];

fn field(name: &str) -> Option<Field> {
    FIELDS
        .iter()
        .find(|(known, _)| *known == name)
        .map(|&(_, field)| field)
}

fn name_of(field: Field) -> &'static str {
    FIELDS
        .iter()
        .find(|&&(_, known)| known == field)
        .map_or("?", |&(name, _)| name)
}

fn kind(field: Field) -> Type {
    match field {
        Field::Ip | Field::Tcp | Field::Udp | Field::Http => Type::Presence,
        Field::IpSrc | Field::IpDst | Field::IpAddr => Type::Address,
        Field::IpProto => Type::Protocol,
        Field::TcpPort
        | Field::TcpSrcPort
        | Field::TcpDstPort
        | Field::UdpPort
        | Field::UdpSrcPort
        | Field::UdpDstPort => Type::Port,
        Field::HttpMethod | Field::HttpHost => Type::Text,
    }
}

fn value(kind: &Type, text: &str) -> Option<Value> {
    match kind {
        Type::Presence => None,
        Type::Address => net(text).map(Value::Net),
        Type::Port => number(text).map(Value::Num),
        Type::Protocol => PROTOCOLS
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(text))
            .map(|&(_, number)| number)
            .or_else(|| number(text).filter(|&n| n <= u16::from(u8::MAX)))
            .map(Value::Num),
        Type::Text => Some(Value::Text(text.to_string())),
    }
}

fn invalid(kind: &Type, text: &str) -> String {
    match kind {
        Type::Address => format!("'{text}' is not an IP address or network"),
        Type::Port => format!("'{text}' is not a port (0-65535)"),
        Type::Protocol => format!("'{text}' is not a protocol number (0-255) or name"),
        Type::Presence | Type::Text => format!("'{text}' is not a valid value"),
    }
}

fn number(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

fn net(text: &str) -> Option<Net> {
    match text.split_once('/') {
        Some((addr, prefix)) => {
            let addr: IpAddr = addr.parse().ok()?;
            let prefix = number(prefix)?;
            Net::new(addr, u8::try_from(prefix).ok()?)
        }
        None => {
            let addr: IpAddr = text.parse().ok()?;
            let prefix = if addr.is_ipv4() { 32 } else { 128 };
            Net::new(addr, prefix)
        }
    }
}
