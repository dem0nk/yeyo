use yeyo::dissect::{App, Header, Http, dissect, form};

fn http(payload: &[u8]) -> Http<'_> {
    match dissect(payload) {
        Some(App::Http(http)) => http,
        None => panic!("expected HTTP"),
    }
}

fn form_request(content_type: &str, body: &str) -> Vec<u8> {
    format!("POST /login HTTP/1.1\r\nContent-Type: {content_type}\r\n\r\n{body}").into_bytes()
}

fn pairs(content_type: &str, body: &str) -> Option<Vec<(String, String)>> {
    let payload = form_request(content_type, body);
    form(&http(&payload))
}

fn pair(key: &str, value: &str) -> (String, String) {
    (key.to_string(), value.to_string())
}

#[test]
fn test_dissect_request_ok() {
    let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";

    assert_eq!(
        http(payload),
        Http::Request {
            method: "GET",
            path: "/index.html",
            version: "HTTP/1.1",
            headers: vec![
                Header {
                    name: "Host",
                    value: "example.com"
                },
                Header {
                    name: "Accept",
                    value: "*/*"
                },
            ],
            body: b"",
        }
    );
}

#[test]
fn test_dissect_response_ok() {
    let payload = b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno";

    assert_eq!(
        http(payload),
        Http::Response {
            version: "HTTP/1.1",
            status: 404,
            reason: "Not Found",
            headers: vec![Header {
                name: "Content-Length",
                value: "2"
            }],
            body: b"no",
        }
    );
}

#[test]
fn test_dissect_response_without_reason_ok() {
    let parsed = http(b"HTTP/1.0 200\r\n\r\n");

    assert!(matches!(
        parsed,
        Http::Response {
            status: 200,
            reason: "",
            ..
        }
    ));
}

#[test]
fn test_dissect_every_method_ok() {
    for method in [
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
    ] {
        let payload = format!("{method} / HTTP/1.1\r\n\r\n");
        assert_eq!(http(payload.as_bytes()).method(), Some(method));
    }
}

#[test]
fn test_dissect_bare_lf_lines_ok() {
    let parsed = http(b"GET / HTTP/1.1\nHost: a.com\n\nbody");

    assert_eq!(parsed.host(), Some("a.com"));
    assert_eq!(parsed.body(), b"body");
}

#[test]
fn test_dissect_header_lookup_ignores_case_ok() {
    let parsed = http(b"GET / HTTP/1.1\r\nhOsT: a.com\r\ncontent-type: text/plain\r\n\r\n");

    assert_eq!(parsed.host(), Some("a.com"));
    assert_eq!(parsed.header("HOST"), Some("a.com"));
    assert_eq!(parsed.content_type(), Some("text/plain"));
    assert_eq!(parsed.header("Cookie"), None);
}

#[test]
fn test_dissect_header_value_trimmed_ok() {
    let parsed = http(b"GET / HTTP/1.1\r\nHost: \t a.com \t\r\n\r\n");

    assert_eq!(parsed.host(), Some("a.com"));
}

#[test]
fn test_dissect_header_value_keeps_colons_ok() {
    let parsed = http(b"GET / HTTP/1.1\r\nHost: a.com:8080\r\n\r\n");

    assert_eq!(parsed.host(), Some("a.com:8080"));
}

#[test]
fn test_dissect_response_has_no_method_ok() {
    assert_eq!(http(b"HTTP/1.1 200 OK\r\n\r\n").method(), None);
}

#[test]
fn test_dissect_body_keeps_binary_ok() {
    let parsed = http(b"POST / HTTP/1.1\r\n\r\n\xff\x00\xfe");

    assert_eq!(parsed.body(), b"\xff\x00\xfe");
}

#[test]
fn test_dissect_empty_payload_none_err() {
    assert_eq!(dissect(b""), None);
}

#[test]
fn test_dissect_tls_bytes_none_err() {
    assert_eq!(
        dissect(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\n"),
        None
    );
}

#[test]
fn test_dissect_unknown_method_none_err() {
    assert_eq!(dissect(b"GETX / HTTP/1.1\r\n\r\n"), None);
    assert_eq!(dissect(b"BREW / HTTP/1.1\r\n\r\n"), None);
}

#[test]
fn test_dissect_lowercase_method_none_err() {
    assert_eq!(dissect(b"get / HTTP/1.1\r\n\r\n"), None);
}

#[test]
fn test_dissect_bad_request_line_none_err() {
    assert_eq!(dissect(b"GET HTTP/1.1\r\n\r\n"), None);
    assert_eq!(dissect(b"GET  HTTP/1.1\r\n\r\n"), None);
    assert_eq!(dissect(b"GET / HTTP/1.1 extra\r\n\r\n"), None);
    assert_eq!(dissect(b"GET / HTTP/2\r\n\r\n"), None);
    assert_eq!(dissect(b"GET / HTTP/1.x\r\n\r\n"), None);
    assert_eq!(dissect(b"GET / HTTP/1.11\r\n\r\n"), None);
    assert_eq!(dissect(b"GET /\r\n\r\n"), None);
}

#[test]
fn test_dissect_bad_status_none_err() {
    assert_eq!(dissect(b"HTTP/1.1 9x OK\r\n\r\n"), None);
    assert_eq!(dissect(b"HTTP/1.1 20 OK\r\n\r\n"), None);
    assert_eq!(dissect(b"HTTP/1.1 2000 OK\r\n\r\n"), None);
    assert_eq!(dissect(b"HTTP/1.1 +20 OK\r\n\r\n"), None);
    assert_eq!(dissect(b"HTTP/1.1\r\n\r\n"), None);
    assert_eq!(dissect(b"HTTP/1.x 200 OK\r\n\r\n"), None);
}

#[test]
fn test_dissect_invalid_utf8_header_none_err() {
    assert_eq!(dissect(b"GET / HTTP/1.1\r\nHost: \xff\r\n\r\n"), None);
    assert_eq!(dissect(b"GET /\xff HTTP/1.1\r\n\r\n"), None);
}

#[test]
fn test_dissect_cut_request_line_none_err() {
    assert_eq!(dissect(b"GET / HTTP/1.1"), None);
    assert_eq!(dissect(b"GET / HT"), None);
}

#[test]
fn test_dissect_cut_mid_header_keeps_complete_lines_ok() {
    let parsed = http(b"GET / HTTP/1.1\r\nHost: a.com\r\nUser-Ag");

    assert_eq!(parsed.headers().len(), 1);
    assert_eq!(parsed.host(), Some("a.com"));
    assert_eq!(parsed.body(), b"");
}

#[test]
fn test_dissect_no_blank_line_has_no_body_ok() {
    let parsed = http(b"GET / HTTP/1.1\r\nHost: a.com\r\n");

    assert_eq!(parsed.host(), Some("a.com"));
    assert_eq!(parsed.body(), b"");
}

#[test]
fn test_dissect_malformed_headers_skipped_ok() {
    let parsed = http(
        b"GET / HTTP/1.1\r\nno colon\r\n: empty name\r\nbad name: x\r\n folded\r\nHost: a.com\r\n\r\n",
    );

    assert_eq!(
        parsed.headers(),
        [Header {
            name: "Host",
            value: "a.com"
        }]
    );
}

#[test]
fn test_dissect_header_count_capped_ok() {
    let mut payload = b"GET / HTTP/1.1\r\n".to_vec();
    for i in 0..1000 {
        payload.extend_from_slice(format!("X-{i}: v\r\n").as_bytes());
    }
    payload.extend_from_slice(b"\r\nbody");

    let parsed = http(&payload);

    assert_eq!(parsed.headers().len(), 64);
    assert_eq!(parsed.headers()[63].name, "X-63");
    assert_eq!(parsed.body(), b"body");
}

#[test]
fn test_dissect_huge_first_line_ok() {
    let mut payload = b"GET /".to_vec();
    payload.extend(std::iter::repeat_n(b'a', 60_000));
    payload.extend_from_slice(b" HTTP/1.1\r\n\r\n");

    assert_eq!(http(&payload).method(), Some("GET"));
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
    assert_eq!(form(&http(b"POST / HTTP/1.1\r\n\r\na=1")), None);
}
