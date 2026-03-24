use std::io::{BufReader, Cursor};
use std::path::PathBuf;

use super::{
    GrepMatch, MAX_REGEX_LINE_BYTES, ReadLineCapped, ReadLineCappedOptions,
    initial_line_buffer_capacity, initial_reader_capacity, matches_sorted_by_path_line,
    max_capped_line_bytes_for_request, maybe_shrink_line_buffer, maybe_sort_grep_matches,
    to_owned_utf8_prefix_within,
};

fn m(path: &str, line: u64) -> GrepMatch {
    GrepMatch {
        path: PathBuf::from(path),
        line,
        text: String::new(),
        line_truncated: false,
    }
}

#[test]
fn match_order_detects_sorted_input() {
    let matches = vec![m("a.txt", 1), m("a.txt", 2), m("b.txt", 1)];
    assert!(matches_sorted_by_path_line(&matches));
}

#[test]
fn match_order_detects_unsorted_input() {
    let matches = vec![m("b.txt", 1), m("a.txt", 2)];
    assert!(!matches_sorted_by_path_line(&matches));
}

#[test]
fn maybe_sort_grep_matches_respects_stable_sort_enabled() {
    let mut matches = vec![m("b.txt", 1), m("a.txt", 2)];
    maybe_sort_grep_matches(&mut matches, true, false);
    assert_eq!(matches[0].path, PathBuf::from("a.txt"));
    assert_eq!(matches[1].path, PathBuf::from("b.txt"));
}

#[test]
fn maybe_sort_grep_matches_skips_sort_when_stable_sort_disabled() {
    let mut matches = vec![m("b.txt", 1), m("a.txt", 2)];
    maybe_sort_grep_matches(&mut matches, false, false);
    assert_eq!(matches[0].path, PathBuf::from("b.txt"));
    assert_eq!(matches[1].path, PathBuf::from("a.txt"));
}

#[test]
fn regex_line_cap_is_bounded() {
    let capped = max_capped_line_bytes_for_request(8 * 1024, u64::MAX, true);
    assert_eq!(capped, MAX_REGEX_LINE_BYTES);
}

#[test]
fn initial_capacities_respect_small_max_read_bytes() {
    assert_eq!(initial_line_buffer_capacity(16 * 1024, 1023), 1024);
    assert_eq!(initial_reader_capacity(16 * 1024, 2047), 2048);
}

#[test]
fn initial_capacities_keep_default_bounds_for_large_max_read_bytes() {
    assert_eq!(initial_line_buffer_capacity(1024, u64::MAX), 8 * 1024);
    assert_eq!(initial_reader_capacity(1024 * 1024, u64::MAX), 64 * 1024);
}

#[test]
fn read_line_capped_does_not_match_across_line_boundaries() {
    let input = Cursor::new(b"aaane\nedle\n".to_vec());
    let mut reader = BufReader::with_capacity(3, input);
    let mut line_buf = Vec::new();
    let mut query_window = Vec::new();

    let first = super::read_line_capped(
        &mut reader,
        &mut line_buf,
        1024,
        Some(b"needle"),
        &mut query_window,
        ReadLineCappedOptions::new(None, None),
    )
    .expect("first line");
    assert!(matches!(
        first,
        ReadLineCapped::Line {
            contains_query: false,
            ..
        }
    ));

    let second = super::read_line_capped(
        &mut reader,
        &mut line_buf,
        1024,
        Some(b"needle"),
        &mut query_window,
        ReadLineCappedOptions::new(None, None),
    )
    .expect("second line");
    assert!(matches!(
        second,
        ReadLineCapped::Line {
            contains_query: false,
            ..
        }
    ));
}

#[test]
fn read_line_capped_does_not_match_across_bare_cr_boundaries() {
    let input = Cursor::new(b"aaane\redle\r".to_vec());
    let mut reader = BufReader::with_capacity(3, input);
    let mut line_buf = Vec::new();
    let mut query_window = Vec::new();

    let first = super::read_line_capped(
        &mut reader,
        &mut line_buf,
        1024,
        Some(b"needle"),
        &mut query_window,
        ReadLineCappedOptions::new(None, None),
    )
    .expect("first line");
    assert!(matches!(
        first,
        ReadLineCapped::Line {
            contains_query: false,
            ..
        }
    ));

    let second = super::read_line_capped(
        &mut reader,
        &mut line_buf,
        1024,
        Some(b"needle"),
        &mut query_window,
        ReadLineCappedOptions::new(None, None),
    )
    .expect("second line");
    assert!(matches!(
        second,
        ReadLineCapped::Line {
            contains_query: false,
            ..
        }
    ));
}

#[test]
fn read_line_capped_matches_query_split_across_chunks() {
    let input = Cursor::new(b"xxneedlezz\n".to_vec());
    let mut reader = BufReader::with_capacity(2, input);
    let mut line_buf = Vec::new();
    let mut query_window = Vec::new();

    let line = super::read_line_capped(
        &mut reader,
        &mut line_buf,
        1024,
        Some(b"needle"),
        &mut query_window,
        ReadLineCappedOptions::new(None, None),
    )
    .expect("line");
    assert!(matches!(
        line,
        ReadLineCapped::Line {
            contains_query: true,
            ..
        }
    ));
}

#[test]
fn read_line_capped_keeps_utf8_validity_when_pending_needs_multiple_chunks() {
    let input = Cursor::new(vec![b'a', 0xE2, 0x82, 0xAC, 0xC2, 0xA2, b'\n']);
    let mut reader = BufReader::with_capacity(3, input);
    let mut line_buf = Vec::new();
    let mut query_window = Vec::new();

    let line = super::read_line_capped(
        &mut reader,
        &mut line_buf,
        1024,
        Some(b"a"),
        &mut query_window,
        ReadLineCappedOptions::new(None, None),
    )
    .expect("line");

    assert!(matches!(
        line,
        ReadLineCapped::Line {
            utf8_valid: true,
            ..
        }
    ));
}

#[test]
fn read_line_capped_single_byte_query_uses_zero_window_state() {
    let input = Cursor::new(b"axb\n".to_vec());
    let mut reader = BufReader::with_capacity(1, input);
    let mut line_buf = Vec::new();
    let mut query_window = Vec::with_capacity(1024);

    let line = super::read_line_capped(
        &mut reader,
        &mut line_buf,
        1024,
        Some(b"x"),
        &mut query_window,
        ReadLineCappedOptions::new(None, None),
    )
    .expect("line");

    assert!(matches!(
        line,
        ReadLineCapped::Line {
            contains_query: true,
            ..
        }
    ));
    assert!(query_window.is_empty());
}

#[test]
fn read_line_capped_single_byte_newline_query_matches_crlf() {
    let input = Cursor::new(b"abc\r\n".to_vec());
    let mut reader = BufReader::with_capacity(2, input);
    let mut line_buf = Vec::new();
    let mut query_window = Vec::new();

    let line = super::read_line_capped(
        &mut reader,
        &mut line_buf,
        1024,
        Some(b"\n"),
        &mut query_window,
        ReadLineCappedOptions::new(None, None),
    )
    .expect("line");

    assert!(matches!(
        line,
        ReadLineCapped::Line {
            contains_query: true,
            ..
        }
    ));
}

#[test]
fn read_line_capped_honors_time_budget_during_chunk_scan() {
    let input = Cursor::new(b"needle\n".to_vec());
    let mut reader = BufReader::with_capacity(1, input);
    let mut line_buf = Vec::new();
    let mut query_window = Vec::new();
    let started = std::time::Instant::now();

    let line = super::read_line_capped(
        &mut reader,
        &mut line_buf,
        1024,
        Some(b"needle"),
        &mut query_window,
        ReadLineCappedOptions::new(Some(&started), Some(std::time::Duration::ZERO)),
    )
    .expect("line");
    assert!(matches!(line, ReadLineCapped::TimeLimit));
}

#[test]
fn read_line_capped_reports_eof_before_time_limit() {
    let input = Cursor::new(Vec::<u8>::new());
    let mut reader = BufReader::with_capacity(1, input);
    let mut line_buf = Vec::new();
    let mut query_window = Vec::new();
    let started = std::time::Instant::now();

    let line = super::read_line_capped(
        &mut reader,
        &mut line_buf,
        1024,
        Some(b"needle"),
        &mut query_window,
        ReadLineCappedOptions::new(Some(&started), Some(std::time::Duration::ZERO)),
    )
    .expect("line");
    assert!(matches!(line, ReadLineCapped::Eof));
}

#[test]
fn read_line_capped_can_short_circuit_after_cap() {
    let input = Cursor::new(b"0123456789abcdef".to_vec());
    let mut reader = BufReader::with_capacity(4, input);
    let mut line_buf = Vec::new();
    let mut query_window = Vec::new();

    let line = super::read_line_capped(
        &mut reader,
        &mut line_buf,
        4,
        None,
        &mut query_window,
        ReadLineCappedOptions::new(None, None).with_stop_after_cap(true),
    )
    .expect("line");

    match line {
        ReadLineCapped::Line {
            bytes_read,
            capped,
            contains_query,
            ..
        } => {
            assert!(capped);
            assert!(!contains_query);
            assert!(bytes_read < 16);
        }
        _ => panic!("expected capped line"),
    }
}

#[test]
fn maybe_shrink_line_buffer_releases_oversized_capacity() {
    let mut buf = Vec::<u8>::with_capacity(512 * 1024);
    buf.extend(std::iter::repeat_n(b'x', 256 * 1024));
    maybe_shrink_line_buffer(&mut buf, 1024);
    assert!(buf.capacity() <= 8 * 1024);
}

#[test]
fn maybe_shrink_line_buffer_keeps_capacity_for_large_retained_hint() {
    let mut buf = Vec::<u8>::with_capacity(300 * 1024);
    buf.extend(std::iter::repeat_n(b'x', 64 * 1024));
    maybe_shrink_line_buffer(&mut buf, 200 * 1024);
    assert!(buf.capacity() >= 300 * 1024);
}

#[test]
fn update_query_match_state_detects_boundary_match() {
    let mut query_window = Vec::<u8>::new();
    let mut matched = false;

    super::update_query_match_state(&mut query_window, b"needle", b"nee", &mut matched);
    assert!(!matched);
    super::update_query_match_state(&mut query_window, b"needle", b"dle", &mut matched);
    assert!(matched);
}

#[test]
fn update_query_match_state_keeps_small_tail_on_large_no_match_chunk() {
    let mut query_window = Vec::<u8>::new();
    let mut matched = false;

    super::update_query_match_state(&mut query_window, b"needle", b"abc", &mut matched);
    assert!(!matched);

    let long_chunk = vec![b'x'; 64 * 1024];
    super::update_query_match_state(&mut query_window, b"needle", &long_chunk, &mut matched);
    assert!(!matched);
    assert_eq!(query_window.len(), b"needle".len().saturating_sub(1));
    assert_eq!(
        query_window.as_slice(),
        &long_chunk[long_chunk.len().saturating_sub(query_window.len())..]
    );
}

#[test]
fn to_owned_utf8_prefix_within_returns_full_text_when_already_within_limit() {
    let text = "hello";
    assert_eq!(to_owned_utf8_prefix_within(text, 64), "hello");
}

#[test]
fn to_owned_utf8_prefix_within_clips_at_utf8_boundary_when_limited() {
    let text = "你好a";
    // "你" is 3 bytes and "好" starts at byte 3. Limiting to 4 must keep only "你".
    assert_eq!(to_owned_utf8_prefix_within(text, 4), "你");
}
