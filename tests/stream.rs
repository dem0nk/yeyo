use yeyo::render::{Side, Stream};

const LIMIT: usize = 64 * 1024;

#[test]
fn test_stream_keeps_arrival_order_ok() {
    let mut stream = Stream::default();

    stream.push(Some(Side::Client), "GET ".to_string());
    stream.push(Some(Side::Server), "200".to_string());

    assert_eq!(stream.text(), "GET 200");
    assert_eq!(stream.len(), 7);
}

#[test]
fn test_stream_parts_keep_sides_ok() {
    let mut stream = Stream::default();

    stream.push(Some(Side::Client), "a".to_string());
    stream.push(None, "b".to_string());
    stream.push(Some(Side::Server), "c".to_string());

    assert_eq!(
        stream.parts(),
        [
            (Some(Side::Client), "a"),
            (None, "b"),
            (Some(Side::Server), "c"),
        ]
    );
}

#[test]
fn test_stream_empty_push_ignored_ok() {
    let mut stream = Stream::default();

    stream.push(Some(Side::Client), String::new());

    assert!(stream.is_empty());
    assert!(stream.parts().is_empty());
}

#[test]
fn test_stream_clear_ok() {
    let mut stream = Stream::default();
    stream.push(None, "data".to_string());

    stream.clear();

    assert!(stream.is_empty());
    assert_eq!(stream.text(), "");
}

#[test]
fn test_stream_exactly_at_limit_kept_ok() {
    let mut stream = Stream::default();

    stream.push(None, "a".repeat(LIMIT));

    assert_eq!(stream.len(), LIMIT);
}

#[test]
fn test_stream_one_byte_over_limit_trimmed_ok() {
    let mut stream = Stream::default();
    stream.push(None, "a".repeat(LIMIT));

    stream.push(None, "b".to_string());

    assert_eq!(stream.len(), LIMIT);
    assert!(stream.text().ends_with("ab"));
}

#[test]
fn test_stream_huge_chunk_capped_ok() {
    let mut stream = Stream::default();

    stream.push(None, format!("{}END", "x".repeat(LIMIT * 2)));

    assert_eq!(stream.len(), LIMIT);
    assert!(stream.text().ends_with("END"));
}

#[test]
fn test_stream_trim_respects_char_boundaries_ok() {
    let mut stream = Stream::default();

    stream.push(None, "é".repeat(LIMIT));

    let text = stream.text();
    assert!(stream.len() <= LIMIT);
    assert_eq!(stream.len(), text.len());
    assert!(text.chars().all(|c| c == 'é'));
}

#[test]
fn test_stream_many_small_chunks_bounded_ok() {
    let mut stream = Stream::default();

    for i in 0..20_000 {
        stream.push(Some(Side::Client), format!("{i:05} "));
    }

    assert!(stream.len() <= LIMIT);
    assert_eq!(stream.len(), stream.text().len());
    assert!(stream.text().ends_with("19999 "));
}
