mod eval;
mod lexer;
mod parser;

use crate::error::YeyoError;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    text: String,
    expr: Expr,
    uses_http: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Has(Field),
    Cmp(Field, Op, Value),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Ip,
    IpSrc,
    IpDst,
    IpAddr,
    IpProto,
    Tcp,
    TcpPort,
    TcpSrcPort,
    TcpDstPort,
    Udp,
    UdpPort,
    UdpSrcPort,
    UdpDstPort,
    Arp,
    Icmp,
    IcmpType,
    Icmpv6,
    Icmpv6Type,
    Http,
    HttpMethod,
    HttpHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Gt,
    Lt,
    Ge,
    Le,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Net(Net),
    Num(u16),
    Text(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Net {
    addr: IpAddr,
    prefix: u8,
}

impl Filter {
    pub fn parse(expr: &str) -> Result<Filter, YeyoError> {
        let parsed = lexer::tokenize(expr).and_then(|tokens| parser::parse(&tokens, expr));
        match parsed {
            Ok(tree) => Ok(Filter {
                text: expr.to_string(),
                uses_http: tree.uses_http(),
                expr: tree,
            }),
            Err((column, reason)) => Err(YeyoError::DisplayFilter {
                expr: expr.to_string(),
                column,
                reason,
            }),
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn expr(&self) -> &Expr {
        &self.expr
    }
}

impl Expr {
    fn uses_http(&self) -> bool {
        match self {
            Expr::Has(field) | Expr::Cmp(field, ..) => field.is_http(),
            Expr::Not(inner) => inner.uses_http(),
            Expr::And(left, right) | Expr::Or(left, right) => left.uses_http() || right.uses_http(),
        }
    }
}

impl Field {
    fn is_http(self) -> bool {
        matches!(self, Field::Http | Field::HttpMethod | Field::HttpHost)
    }
}

impl Net {
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Net> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        (prefix <= max).then_some(Net { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    // Shifting by the full width overflows; a /0 prefix matches everything.
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}
