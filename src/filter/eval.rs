use super::{Expr, Field, Filter, Op, Value};
use crate::dissect::{App, Http, dissect};
use crate::packet::{Packet, Transport};
use std::net::IpAddr;

enum Got<'a> {
    Ip(IpAddr),
    Num(u16),
    Text(&'a str),
}

struct Context<'p, 'a> {
    packet: &'p Packet<'a>,
    http: Option<Http<'a>>,
}

impl Filter {
    pub fn matches(&self, packet: &Packet<'_>) -> bool {
        // Dissecting is the costly part, so it only runs when the filter asks for HTTP.
        let http = if self.uses_http {
            dissect(packet.payload).map(|App::Http(http)| http)
        } else {
            None
        };
        eval(&self.expr, &Context { packet, http })
    }
}

fn eval(expr: &Expr, context: &Context) -> bool {
    match expr {
        Expr::Has(field) => has(*field, context),
        Expr::Cmp(field, op, value) => compare(*field, *op, value, &values(*field, context)),
        Expr::Not(inner) => !eval(inner, context),
        Expr::And(left, right) => eval(left, context) && eval(right, context),
        Expr::Or(left, right) => eval(left, context) || eval(right, context),
    }
}

fn has(field: Field, context: &Context) -> bool {
    let packet = context.packet;
    match field {
        Field::Ip => packet.ip().is_some(),
        Field::Tcp => matches!(packet.transport, Some(Transport::Tcp(_))),
        Field::Udp => matches!(packet.transport, Some(Transport::Udp(_))),
        Field::Arp => packet.arp().is_some(),
        Field::Icmp => matches!(packet.transport, Some(Transport::Icmp(_))),
        Field::Icmpv6 => matches!(packet.transport, Some(Transport::Icmpv6(_))),
        Field::Http => context.http.is_some(),
        _ => !values(field, context).is_empty(),
    }
}

fn values<'a>(field: Field, context: &Context<'_, 'a>) -> Vec<Got<'a>> {
    let packet = context.packet;
    let ip = packet.ip();
    let ports = |want_tcp: bool| match (&packet.transport, want_tcp) {
        (Some(Transport::Tcp(tcp)), true) => Some((tcp.src_port, tcp.dst_port)),
        (Some(Transport::Udp(udp)), false) => Some((udp.src_port, udp.dst_port)),
        _ => None,
    };
    let http = context.http.as_ref();
    match field {
        Field::IpSrc => ip.map(|ip| Got::Ip(ip.src())).into_iter().collect(),
        Field::IpDst => ip.map(|ip| Got::Ip(ip.dst())).into_iter().collect(),
        Field::IpAddr => ip
            .map(|ip| vec![Got::Ip(ip.src()), Got::Ip(ip.dst())])
            .unwrap_or_default(),
        Field::IpProto => ip
            .map(|ip| Got::Num(u16::from(ip.protocol())))
            .into_iter()
            .collect(),
        Field::TcpPort | Field::UdpPort => ports(field == Field::TcpPort)
            .map(|(src, dst)| vec![Got::Num(src), Got::Num(dst)])
            .unwrap_or_default(),
        Field::TcpSrcPort | Field::UdpSrcPort => ports(field == Field::TcpSrcPort)
            .map(|(src, _)| Got::Num(src))
            .into_iter()
            .collect(),
        Field::TcpDstPort | Field::UdpDstPort => ports(field == Field::TcpDstPort)
            .map(|(_, dst)| Got::Num(dst))
            .into_iter()
            .collect(),
        Field::IcmpType => match &packet.transport {
            Some(Transport::Icmp(icmp)) => vec![Got::Num(u16::from(icmp.kind))],
            _ => Vec::new(),
        },
        Field::Icmpv6Type => match &packet.transport {
            Some(Transport::Icmpv6(icmp)) => vec![Got::Num(u16::from(icmp.kind))],
            _ => Vec::new(),
        },
        Field::HttpMethod => http
            .and_then(|http| http.method())
            .map(Got::Text)
            .into_iter()
            .collect(),
        Field::HttpHost => http
            .and_then(|http| http.host())
            .map(Got::Text)
            .into_iter()
            .collect(),
        Field::Ip
        | Field::Tcp
        | Field::Udp
        | Field::Arp
        | Field::Icmp
        | Field::Icmpv6
        | Field::Http => Vec::new(),
    }
}

fn compare(field: Field, op: Op, want: &Value, got: &[Got]) -> bool {
    // A field the packet doesn't have never matches, for '!=' too (as in Wireshark).
    if got.is_empty() {
        return false;
    }
    match op {
        // Two-sided fields like ip.addr: '!=' means neither side equals the value.
        Op::Ne => got.iter().all(|got| !test(field, Op::Eq, want, got)),
        _ => got.iter().any(|got| test(field, op, want, got)),
    }
}

fn test(field: Field, op: Op, want: &Value, got: &Got) -> bool {
    match (want, got) {
        (Value::Net(net), Got::Ip(ip)) => net.contains(*ip),
        (Value::Num(want), Got::Num(got)) => match op {
            Op::Eq | Op::Ne => got == want,
            Op::Gt => got > want,
            Op::Lt => got < want,
            Op::Ge => got >= want,
            Op::Le => got <= want,
        },
        // Host names are case-insensitive; methods are not.
        (Value::Text(want), Got::Text(got)) if field == Field::HttpHost => {
            got.eq_ignore_ascii_case(want)
        }
        (Value::Text(want), Got::Text(got)) => got == want,
        _ => false,
    }
}
