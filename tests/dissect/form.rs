use crate::http::parsed;
use yeyo::dissect::form;

fn form_request(content_type: &str, body: &str) -> Vec<u8> {
    format!("POST /login HTTP/1.1\r\nContent-Type: {content_type}\r\n\r\n{body}").into_bytes()
}

fn pairs(content_type: &str, body: &str) -> Option<Vec<(String, String)>> {
    let payload = form_request(content_type, body);
    form(&parsed(&payload))
}

fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_string(), value.to_string())
}

#[test]
fn test_form_decodes_pairs_ok() {
    assert_eq!(
        pairs(
            "application/x-www-form-urlencoded",
            "user=bob&pw=x%40y&note=hi+there"
        ),
        Some(vec![
            pair("user", "bob"),
            pair("pw", "x@y"),
            pair("note", "hi there")
        ])
    );
}

#[test]
fn test_form_content_type_params_and_case_ok() {
    assert_eq!(
        pairs("Application/X-WWW-Form-Urlencoded; charset=UTF-8", "a=1"),
        Some(vec![pair("a", "1")])
    );
}

#[test]
fn test_form_decodes_utf8_ok() {
    assert_eq!(
        pairs("application/x-www-form-urlencoded", "name=%C3%A9"),
        Some(vec![pair("name", "é")])
    );
}

#[test]
fn test_form_broken_percent_kept_ok() {
    assert_eq!(
        pairs("application/x-www-form-urlencoded", "a=%&b=%4&c=%zz&d=x%"),
        Some(vec![
            pair("a", "%"),
            pair("b", "%4"),
            pair("c", "%zz"),
            pair("d", "x%")
        ])
    );
}

#[test]
fn test_form_invalid_utf8_replaced_ok() {
    assert_eq!(
        pairs("application/x-www-form-urlencoded", "a=%ff"),
        Some(vec![pair("a", "\u{fffd}")])
    );
}

#[test]
fn test_form_empty_key_value_and_segments_ok() {
    assert_eq!(
        pairs("application/x-www-form-urlencoded", "=v&k=&&flag&a=b=c"),
        Some(vec![
            pair("", "v"),
            pair("k", ""),
            pair("flag", ""),
            pair("a", "b=c")
        ])
    );
}

#[test]
fn test_form_empty_body_ok() {
    assert_eq!(pairs("application/x-www-form-urlencoded", ""), Some(vec![]));
}

#[test]
fn test_form_pair_count_capped_ok() {
    let body = (0..1000)
        .map(|i| format!("k{i}=v"))
        .collect::<Vec<_>>()
        .join("&");

    let decoded = pairs("application/x-www-form-urlencoded", &body).unwrap_or_default();

    assert_eq!(decoded.len(), 64);
    assert_eq!(decoded[63], pair("k63", "v"));
}

#[test]
fn test_form_other_content_type_none_err() {
    assert_eq!(pairs("application/json", "{\"a\":1}"), None);
    assert_eq!(pairs("application/x-www-form-urlencodedx", "a=1"), None);
}

#[test]
fn test_form_without_content_type_none_err() {
    assert_eq!(form(&parsed(b"POST / HTTP/1.1\r\n\r\na=1")), None);
}
