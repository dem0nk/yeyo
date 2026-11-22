use yeyo::render::{printable, wrap, wrap_tagged};

#[test]
fn test_printable_plain_ascii_ok() {
    assert_eq!(printable(b"GET / HTTP/1.1"), "GET / HTTP/1.1");
}

#[test]
fn test_printable_crlf_becomes_newline_ok() {
    assert_eq!(
        printable(b"Host: x\r\nAccept: */*\r\n\r\n"),
        "Host: x\nAccept: */*\n\n"
    );
}

#[test]
fn test_printable_lone_cr_hidden_ok() {
    assert_eq!(printable(b"a\rb"), "a.b");
    assert_eq!(printable(b"a\r"), "a.");
}

#[test]
fn test_printable_tab_expanded_ok() {
    assert_eq!(printable(b"a\tb"), "a    b");
}

#[test]
fn test_printable_escape_sequence_neutralised_ok() {
    let text = printable(b"\x1b[2J\x1b]0;pwned\x07hi");

    assert_eq!(text, ".[2J.]0;pwned.hi");
    assert!(!text.contains('\x1b'));
}

#[test]
fn test_printable_control_bytes_hidden_ok() {
    assert_eq!(printable(&[0x00, 0x08, 0x7f, b'x']), "...x");
}

#[test]
fn test_printable_c1_controls_hidden_ok() {
    assert_eq!(printable("a\u{9b}b\u{85}c".as_bytes()), "a.b.c");
}

#[test]
fn test_printable_invalid_utf8_hidden_ok() {
    assert_eq!(printable(&[b'a', 0xff, b'b', 0xc3]), "a.b.");
}

#[test]
fn test_printable_unicode_kept_ok() {
    assert_eq!(printable("héllo 世界 🦀".as_bytes()), "héllo 世界 🦀");
}

#[test]
fn test_printable_bidi_override_hidden_ok() {
    assert_eq!(printable("user\u{202e}gpj.exe".as_bytes()), "user.gpj.exe");
    assert_eq!(printable("a\u{2066}b\u{200f}c".as_bytes()), "a.b.c");
}

#[test]
fn test_printable_empty_ok() {
    assert_eq!(printable(&[]), "");
}

#[test]
fn test_wrap_short_line_ok() {
    assert_eq!(wrap("hello", 10), ["hello"]);
}

#[test]
fn test_wrap_exact_width_ok() {
    assert_eq!(wrap("abcde", 5), ["abcde"]);
}

#[test]
fn test_wrap_one_over_width_ok() {
    assert_eq!(wrap("abcdef", 5), ["abcde", "f"]);
}

#[test]
fn test_wrap_keeps_line_breaks_ok() {
    assert_eq!(wrap("ab\n\ncd\n", 10), ["ab", "", "cd", ""]);
}

#[test]
fn test_wrap_wide_chars_ok() {
    assert_eq!(wrap("世界世", 4), ["世界", "世"]);
    assert_eq!(wrap("a世", 2), ["a", "世"]);
}

#[test]
fn test_wrap_wide_char_wider_than_width_ok() {
    assert_eq!(wrap("世界", 1), ["世", "界"]);
}

#[test]
fn test_wrap_zero_width_ok() {
    assert!(wrap("abc", 0).is_empty());
}

#[test]
fn test_wrap_empty_ok() {
    assert_eq!(wrap("", 10), [""]);
}

#[test]
fn test_wrap_tagged_merges_same_tag_ok() {
    let rows = wrap_tagged(&[(1, "ab"), (1, "cd")], 10);

    assert_eq!(rows, [vec![(1, "abcd".to_string())]]);
}

#[test]
fn test_wrap_tagged_keeps_tags_apart_ok() {
    let rows = wrap_tagged(&[(1, "ab"), (2, "cd")], 10);

    assert_eq!(rows, [vec![(1, "ab".to_string()), (2, "cd".to_string())]]);
}

#[test]
fn test_wrap_tagged_tag_crosses_row_break_ok() {
    let rows = wrap_tagged(&[(1, "abc"), (2, "defg")], 5);

    assert_eq!(
        rows,
        [
            vec![(1, "abc".to_string()), (2, "de".to_string())],
            vec![(2, "fg".to_string())],
        ]
    );
}

#[test]
fn test_wrap_tagged_newline_inside_part_ok() {
    let rows = wrap_tagged(&[(1, "a\nb"), (2, "c\n")], 10);

    assert_eq!(
        rows,
        [
            vec![(1, "a".to_string())],
            vec![(1, "b".to_string()), (2, "c".to_string())],
            vec![],
        ]
    );
}

#[test]
fn test_wrap_tagged_empty_parts_ok() {
    let rows = wrap_tagged::<u8>(&[], 10);

    assert_eq!(rows, [Vec::<(u8, String)>::new()]);
}
