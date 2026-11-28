use yeyo::render::{Mark, marks};

fn joined(pieces: &[(Mark, &str)]) -> String {
    pieces.iter().map(|(_, text)| *text).collect()
}

fn marked(text: &str, mark: Mark) -> Vec<String> {
    marks(text)
        .into_iter()
        .filter(|(got, _)| *got == mark)
        .map(|(_, piece)| piece.to_string())
        .collect()
}

#[test]
fn test_marks_request_line_ok() {
    assert_eq!(
        marks("GET /index.html HTTP/1.1"),
        [
            (Mark::Method, "GET"),
            (Mark::Plain, " /index.html HTTP/1.1")
        ]
    );
}

#[test]
fn test_marks_every_method_ok() {
    for method in [
        "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE",
    ] {
        let line = format!("{method} / HTTP/1.1");
        assert_eq!(marked(&line, Mark::Method), [method]);
    }
}

#[test]
fn test_marks_status_line_ok() {
    assert_eq!(
        marks("HTTP/1.1 404 Not Found"),
        [(Mark::Method, "HTTP/1.1 404"), (Mark::Plain, " Not Found")]
    );
    assert_eq!(marked("HTTP/1.0 200", Mark::Method), ["HTTP/1.0 200"]);
}

#[test]
fn test_marks_not_a_start_line_ok() {
    for text in [
        "GETX / HTTP/1.1",
        "get / HTTP/1.1",
        "say GET / HTTP/1.1",
        "GET",
        "HTTP/1.1 20 OK",
        "HTTP/1.1 2000",
        "HTTP/2 200",
    ] {
        assert!(marked(text, Mark::Method).is_empty(), "text {text:?}");
    }
}

#[test]
fn test_marks_headers_after_start_line_ok() {
    let text = "GET / HTTP/1.1\nHost: a.com\nAccept: */*\n\nbody: not a header";

    assert_eq!(marked(text, Mark::Header), ["Host", "Accept"]);
}

#[test]
fn test_marks_no_headers_without_start_line_ok() {
    assert!(marked("Host: a.com\nnote: hi", Mark::Header).is_empty());
}

#[test]
fn test_marks_header_without_value_ok() {
    let text = "GET / HTTP/1.1\nX-Empty:\nCookie:";

    assert_eq!(marked(text, Mark::Header), ["X-Empty", "Cookie"]);
    assert!(marked(text, Mark::Secret).is_empty());
}

#[test]
fn test_marks_bad_header_name_is_plain_ok() {
    let text = "GET / HTTP/1.1\nbad name: x\n: x";

    assert!(marked(text, Mark::Header).is_empty());
}

#[test]
fn test_marks_secret_headers_ok() {
    let text = "GET / HTTP/1.1\nAuthorization: Basic Ym9iOnB3\nCOOKIE: sid=abc\nproxy-authorization: x\nHost: a.com";

    assert_eq!(
        marked(text, Mark::Secret),
        ["Basic Ym9iOnB3", "sid=abc", "x"]
    );
}

#[test]
fn test_marks_set_cookie_in_response_ok() {
    let text = "HTTP/1.1 200 OK\nSet-Cookie: sid=xyz; HttpOnly";

    assert_eq!(marked(text, Mark::Secret), ["sid=xyz; HttpOnly"]);
}

#[test]
fn test_marks_form_body_ok() {
    let text = "POST /login HTTP/1.1\nContent-Type: x\n\nuser=bob&password=hunter2&remember=1";

    assert_eq!(marked(text, Mark::Key), ["user", "password", "remember"]);
    assert_eq!(marked(text, Mark::Secret), ["hunter2"]);
}

#[test]
fn test_marks_secret_key_names_ignore_case_ok() {
    let text = "a=1&Password=x1&PWD=x2&passwd=x3&access_token=x4&client_secret=x5&apiKey=x6&api_key=x7&auth=x8&author=me";

    assert_eq!(
        marked(text, Mark::Secret),
        ["x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8"]
    );
}

#[test]
fn test_marks_query_string_ok() {
    let text = "GET /cb?code=1&token=abc HTTP/1.1";

    assert_eq!(marked(text, Mark::Key), ["code", "token"]);
    assert_eq!(marked(text, Mark::Secret), ["abc"]);
    assert_eq!(joined(&marks(text)), text);
}

#[test]
fn test_marks_empty_and_missing_values_ok() {
    let text = "password=&token&=v&&a=b=c";

    assert_eq!(marked(text, Mark::Key), ["password", "a"]);
    assert_eq!(marked(text, Mark::Secret), Vec::<String>::new());
    assert_eq!(joined(&marks(text)), text);
}

#[test]
fn test_marks_prose_with_equals_is_plain_ok() {
    let text = "x = password = y";

    assert_eq!(marks(text), [(Mark::Plain, text)]);
}

#[test]
fn test_marks_plain_text_is_one_piece_ok() {
    assert_eq!(marks("hello\nworld"), [(Mark::Plain, "hello\nworld")]);
    assert!(marks("").is_empty());
}

#[test]
fn test_marks_non_ascii_ok() {
    let text = "GET /é?ключ=значение&pass=пароль HTTP/1.1\nHöst: x\n\nname=é&pwd=日本";

    assert_eq!(marked(text, Mark::Secret), ["пароль", "日本"]);
    assert_eq!(marked(text, Mark::Header), Vec::<String>::new());
    assert_eq!(joined(&marks(text)), text);
}

#[test]
fn test_marks_always_rejoin_to_input_ok() {
    let samples = [
        "",
        "\n",
        "\n\n\n",
        "&&&",
        "===",
        "?",
        "GET ?",
        "GET /?",
        "GET /?& HTTP/1.1",
        "GET /a?b=c",
        "POST / HTTP/1.1\nCookie: a\n\npass=1\nGET / HTTP/1.1\nAuthorization: b",
        "HTTP/1.1 200 OK\n\n\nk=v",
        "日本=語&pass=..&\n",
    ];
    for text in samples {
        let pieces = marks(text);
        assert_eq!(joined(&pieces), text, "text {text:?}");
        assert!(
            pieces.iter().all(|(_, piece)| !piece.is_empty()),
            "text {text:?}"
        );
        assert!(
            pieces.windows(2).all(|pair| pair[0].0 != pair[1].0),
            "text {text:?}: {pieces:?}"
        );
    }
}
