use std::error::Error;
use std::net::IpAddr;
use yeyo::error::YeyoError;
use yeyo::filter::{Expr, Field, Filter, Net, Op, Value};

fn tree(expr: &str) -> Result<Expr, YeyoError> {
    Ok(Filter::parse(expr)?.expr().clone())
}

fn port(field: Field, n: u16) -> Expr {
    Expr::Cmp(field, Op::Eq, Value::Num(n))
}

fn not(inner: Expr) -> Expr {
    Expr::Not(Box::new(inner))
}

fn and(left: Expr, right: Expr) -> Expr {
    Expr::And(Box::new(left), Box::new(right))
}

fn or(left: Expr, right: Expr) -> Expr {
    Expr::Or(Box::new(left), Box::new(right))
}

fn net(addr: &str, prefix: u8) -> Result<Value, Box<dyn Error>> {
    let addr: IpAddr = addr.parse()?;
    Ok(Value::Net(Net::new(addr, prefix).ok_or("bad prefix")?))
}

fn rejected(expr: &str, column: usize, mentions: &str) {
    match Filter::parse(expr) {
        Err(YeyoError::DisplayFilter {
            column: got,
            reason,
            ..
        }) => {
            assert_eq!(got, column, "filter {expr:?}: {reason}");
            assert!(reason.contains(mentions), "filter {expr:?}: {reason}");
        }
        other => panic!("filter {expr:?} should fail, got {other:?}"),
    }
}

#[test]
fn test_parse_comparison_ok() -> Result<(), Box<dyn Error>> {
    assert_eq!(tree("tcp.port == 80")?, port(Field::TcpPort, 80));
    Ok(())
}

#[test]
fn test_parse_every_operator_ok() -> Result<(), Box<dyn Error>> {
    for (text, op) in [
        ("==", Op::Eq),
        ("!=", Op::Ne),
        (">", Op::Gt),
        ("<", Op::Lt),
        (">=", Op::Ge),
        ("<=", Op::Le),
    ] {
        assert_eq!(
            tree(&format!("udp.dstport {text} 53"))?,
            Expr::Cmp(Field::UdpDstPort, op, Value::Num(53))
        );
    }
    Ok(())
}

#[test]
fn test_parse_without_spaces_ok() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        tree("tcp.port==80&&!udp")?,
        and(port(Field::TcpPort, 80), not(Expr::Has(Field::Udp)))
    );
    Ok(())
}

#[test]
fn test_parse_and_binds_tighter_than_or_ok() -> Result<(), Box<dyn Error>> {
    let a = port(Field::TcpPort, 1);
    let b = port(Field::TcpPort, 2);
    let c = port(Field::TcpPort, 3);

    assert_eq!(
        tree("tcp.port == 1 || tcp.port == 2 && tcp.port == 3")?,
        or(a.clone(), and(b.clone(), c.clone()))
    );
    assert_eq!(
        tree("tcp.port == 1 && tcp.port == 2 || tcp.port == 3")?,
        or(and(a, b), c)
    );
    Ok(())
}

#[test]
fn test_parse_not_binds_tightest_ok() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        tree("!tcp && udp")?,
        and(not(Expr::Has(Field::Tcp)), Expr::Has(Field::Udp))
    );
    Ok(())
}

#[test]
fn test_parse_parentheses_override_precedence_ok() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        tree("(tcp || udp) && ip")?,
        and(
            or(Expr::Has(Field::Tcp), Expr::Has(Field::Udp)),
            Expr::Has(Field::Ip)
        )
    );
    Ok(())
}

#[test]
fn test_parse_chains_are_left_grouped_ok() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        tree("ip && tcp && http")?,
        and(
            and(Expr::Has(Field::Ip), Expr::Has(Field::Tcp)),
            Expr::Has(Field::Http)
        )
    );
    Ok(())
}

#[test]
fn test_parse_word_operators_ok() -> Result<(), Box<dyn Error>> {
    assert_eq!(tree("not tcp and udp or ip")?, tree("!tcp && udp || ip")?);
    Ok(())
}

#[test]
fn test_parse_double_not_ok() -> Result<(), Box<dyn Error>> {
    assert_eq!(tree("!!tcp")?, not(not(Expr::Has(Field::Tcp))));
    Ok(())
}

#[test]
fn test_parse_bare_value_field_is_presence_ok() -> Result<(), Box<dyn Error>> {
    assert_eq!(tree("http.host")?, Expr::Has(Field::HttpHost));
    Ok(())
}

#[test]
fn test_parse_addresses_and_networks_ok() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        tree("ip.src == 10.0.0.1")?,
        Expr::Cmp(Field::IpSrc, Op::Eq, net("10.0.0.1", 32)?)
    );
    assert_eq!(
        tree("ip.dst == 10.0.0.0/8")?,
        Expr::Cmp(Field::IpDst, Op::Eq, net("10.0.0.0", 8)?)
    );
    assert_eq!(
        tree("ip.addr != 2001:db8::/32")?,
        Expr::Cmp(Field::IpAddr, Op::Ne, net("2001:db8::", 32)?)
    );
    assert_eq!(
        tree("ip.addr == ::1")?,
        Expr::Cmp(Field::IpAddr, Op::Eq, net("::1", 128)?)
    );
    Ok(())
}

#[test]
fn test_parse_protocol_names_and_numbers_ok() -> Result<(), Box<dyn Error>> {
    for (text, number) in [
        ("tcp", 6),
        ("UDP", 17),
        ("icmp", 1),
        ("icmpv6", 58),
        ("0", 0),
        ("255", 255),
    ] {
        assert_eq!(
            tree(&format!("ip.proto == {text}"))?,
            Expr::Cmp(Field::IpProto, Op::Eq, Value::Num(number))
        );
    }
    Ok(())
}

#[test]
fn test_parse_strings_quoted_and_bare_ok() -> Result<(), Box<dyn Error>> {
    let post = Expr::Cmp(Field::HttpMethod, Op::Eq, Value::Text("POST".to_string()));

    assert_eq!(tree("http.request.method == POST")?, post);
    assert_eq!(tree("http.request.method == \"POST\"")?, post);
    assert_eq!(
        tree(r#"http.host == "a \"b\" \\ c && d""#)?,
        Expr::Cmp(
            Field::HttpHost,
            Op::Eq,
            Value::Text(r#"a "b" \ c && d"#.to_string())
        )
    );
    Ok(())
}

#[test]
fn test_parse_port_boundaries_ok() -> Result<(), Box<dyn Error>> {
    assert_eq!(tree("tcp.port == 0")?, port(Field::TcpPort, 0));
    assert_eq!(tree("tcp.port == 65535")?, port(Field::TcpPort, 65535));
    Ok(())
}

#[test]
fn test_parse_nesting_at_limit_ok() -> Result<(), Box<dyn Error>> {
    let expr = format!("{}tcp{}", "(".repeat(32), ")".repeat(32));

    assert_eq!(tree(&expr)?, Expr::Has(Field::Tcp));
    Ok(())
}

#[test]
fn test_parse_length_at_limit_ok() -> Result<(), Box<dyn Error>> {
    let expr = format!("tcp{}", " ".repeat(1021));

    assert_eq!(tree(&expr)?, Expr::Has(Field::Tcp));
    Ok(())
}

#[test]
fn test_parse_empty_err() {
    rejected("", 1, "expected a field");
    rejected("   ", 4, "expected a field");
}

#[test]
fn test_parse_missing_value_err() {
    rejected("tcp.port ==", 12, "expected a value");
    rejected("tcp.port == && udp", 13, "expected a value");
}

#[test]
fn test_parse_missing_field_err() {
    rejected("== 80", 1, "expected a field");
    rejected("tcp &&", 7, "expected a field");
    rejected("tcp || || udp", 8, "expected a field");
}

#[test]
fn test_parse_unknown_field_err() {
    rejected("tcp.prot == 80", 1, "unknown field 'tcp.prot'");
    rejected("TCP", 1, "unknown field");
    rejected("80", 1, "unknown field");
}

#[test]
fn test_parse_unclosed_parenthesis_err() {
    rejected("(tcp", 5, "expected ')'");
    rejected("((tcp)", 7, "expected ')'");
}

#[test]
fn test_parse_stray_closing_parenthesis_err() {
    rejected("tcp)", 4, "end of filter");
    rejected("()", 2, "expected a field");
}

#[test]
fn test_parse_missing_operator_between_terms_err() {
    rejected("tcp udp", 5, "expected '&&', '||' or end of filter");
    rejected("tcp.port == 80 443", 16, "end of filter");
}

#[test]
fn test_parse_port_out_of_range_err() {
    rejected("tcp.port == 70000", 13, "not a port");
    rejected("tcp.port == 65536", 13, "not a port");
    rejected("tcp.port == -1", 13, "not a port");
    rejected("tcp.port == +80", 13, "unexpected character '+'");
    rejected("tcp.port == http", 13, "not a port");
}

#[test]
fn test_parse_bad_protocol_err() {
    rejected("ip.proto == 256", 13, "not a protocol");
    rejected("ip.proto == gre", 13, "not a protocol");
}

#[test]
fn test_parse_bad_address_err() {
    rejected("ip.src == 10.0.0", 11, "not an IP address");
    rejected("ip.src == 10.0.0.256", 11, "not an IP address");
    rejected("ip.src == 10.0.0.0/33", 11, "not an IP address");
    rejected("ip.src == ::/129", 11, "not an IP address");
    rejected("ip.src == 10.0.0.0/", 11, "not an IP address");
    rejected("ip.src == 10.0.0.0/x", 11, "not an IP address");
    rejected("ip.src == a.com", 11, "not an IP address");
}

#[test]
fn test_parse_ordering_on_strings_and_addresses_err() {
    rejected("http.host > \"a\"", 11, "only supports '==' and '!='");
    rejected("ip.src <= 10.0.0.1", 8, "only supports");
}

#[test]
fn test_parse_comparing_presence_field_err() {
    rejected("tcp == 6", 5, "'tcp' can't be compared");
    rejected("http != x", 6, "'http' can't be compared");
}

#[test]
fn test_parse_single_symbol_operators_err() {
    rejected("tcp.port = 80", 10, "expected '=='");
    rejected("tcp & udp", 5, "expected '&&'");
    rejected("tcp | udp", 5, "expected '||'");
}

#[test]
fn test_parse_stray_characters_err() {
    rejected("tcp $", 5, "unexpected character '$'");
    rejected("tcp\u{1b}[31m", 4, "unexpected character '\\u{1b}'");
}

#[test]
fn test_parse_non_ascii_column_counts_chars_err() {
    rejected("http.host == é", 14, "unexpected character");
    rejected("\"é\" tcp", 1, "expected a field");
}

#[test]
fn test_parse_unclosed_string_err() {
    rejected("http.host == \"abc", 14, "unclosed string");
    rejected("http.host == \"abc\\", 14, "unclosed string");
}

#[test]
fn test_parse_nested_too_deep_err() {
    let expr = format!("{}tcp{}", "(".repeat(33), ")".repeat(33));

    rejected(&expr, 33, "nested more than 32 levels");
}

#[test]
fn test_parse_many_nots_err() {
    let expr = format!("{}tcp", "!".repeat(1000));

    rejected(&expr, 33, "nested more than 32 levels");
}

#[test]
fn test_parse_too_long_err() {
    let expr = format!("tcp{}", " ".repeat(1022));

    rejected(&expr, 1025, "longer than 1024 characters");
}

#[test]
fn test_parse_huge_input_err() {
    let expr = "!".repeat(10_000);

    rejected(&expr, 1025, "longer than 1024");
}

#[test]
fn test_parse_long_flat_chain_ok() -> Result<(), Box<dyn Error>> {
    let expr = vec!["tcp"; 200].join("&&");

    assert!(Filter::parse(&expr).is_ok());
    Ok(())
}
