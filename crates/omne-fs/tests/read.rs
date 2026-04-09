mod common;
#[cfg(unix)]
#[path = "common/unix_helpers.rs"]
mod unix_helpers;

use std::path::PathBuf;

use common::test_policy;
use omne_fs::ops::{Context, ReadRequest, ReadResponse, read_file};
use policy_meta::WriteScope;

fn read_enabled_policy(root: &std::path::Path, mode: WriteScope) -> omne_fs::policy::SandboxPolicy {
    let mut policy = test_policy(root, mode);
    policy.permissions.read = true;
    policy
}

const ROOT_ID: &str = "root";
const MSG_ABSOLUTE_REQUEST_PATHS: &str = "absolute request paths";
#[cfg(unix)]
const MSG_NOT_REGULAR_FILE: &str = "not a regular file";
const MSG_LINE_RANGE_TOGETHER: &str = "must be provided together";
const MSG_INVALID_LINE_RANGE: &str = "invalid line range";
const MSG_LINE_RANGE: &str = "line range";
const MSG_OUT_OF_BOUNDS: &str = "out of bounds";

fn req(path: impl Into<PathBuf>, start_line: Option<u64>, end_line: Option<u64>) -> ReadRequest {
    ReadRequest {
        root_id: ROOT_ID.to_string(),
        path: path.into(),
        start_line,
        end_line,
    }
}

fn read_ok(
    ctx: &Context,
    path: impl Into<PathBuf>,
    start_line: Option<u64>,
    end_line: Option<u64>,
) -> ReadResponse {
    read_file(ctx, req(path, start_line, end_line)).expect("read")
}

fn read_err(
    ctx: &Context,
    path: impl Into<PathBuf>,
    start_line: Option<u64>,
    end_line: Option<u64>,
) -> omne_fs::Error {
    read_file(ctx, req(path, start_line, end_line)).expect_err("should reject")
}

fn invalid_path_message(err: omne_fs::Error) -> String {
    match err {
        omne_fs::Error::InvalidPath(message) => message,
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_redacts_matches() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hello.txt");
    std::fs::write(&path, "API_KEY=abc123\nhello\n").expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.secrets.redact_regexes = vec!["API_KEY=([A-Za-z0-9_]+)".to_string()];
    let ctx = Context::new(policy).expect("ctx");
    let response = read_ok(&ctx, "hello.txt", None, None);

    assert_eq!(response.path, PathBuf::from("hello.txt"));
    assert_eq!(response.requested_path, PathBuf::from("hello.txt"));
    assert!(!response.truncated);
    assert_eq!(response.bytes_read, 21);
    assert!(response.content.contains("***REDACTED***"));
    assert!(!response.content.contains("abc123"));
    assert!(response.content.contains("hello"));
}

#[test]
fn read_allows_env_variants_when_policy_does_not_deny_them() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".env.local"), "SECRET=1\n").expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.secrets.deny_globs.clear();
    let ctx = Context::new(policy).expect("ctx");
    let response = read_ok(&ctx, ".env.local", None, None);

    assert_eq!(response.path, PathBuf::from(".env.local"));
    assert_eq!(response.content, "SECRET=1\n");
}

#[test]
fn read_denies_env_variants_when_deny_globs_match() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".env.local"), "SECRET=1\n").expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.secrets.deny_globs = vec![".env*".to_string()];
    let ctx = Context::new(policy).expect("ctx");
    let err = read_err(&ctx, ".env.local", None, None);
    match err {
        omne_fs::Error::SecretPathDenied(path) => {
            assert_eq!(path, PathBuf::from(".env.local"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_allows_env_example_and_template_variants() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join(".env.example"), "SECRET=example\n").expect("write");
    std::fs::write(dir.path().join(".env.template"), "SECRET=template\n").expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.secrets.deny_globs.clear();
    let ctx = Context::new(policy).expect("ctx");

    let example = read_ok(&ctx, ".env.example", None, None);
    assert!(example.content.contains("SECRET=example"));

    let template = read_ok(&ctx, ".env.template", None, None);
    assert!(template.content.contains("SECRET=template"));
}

#[test]
fn read_fails_when_redaction_output_exceeds_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("huge-redacted.txt");
    std::fs::write(&path, "a".repeat(8_200)).expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.secrets.redact_regexes = vec!["a".to_string()];
    policy.secrets.replacement = "x".repeat(1024);
    let ctx = Context::new(policy).expect("ctx");

    let err = read_err(&ctx, "huge-redacted.txt", None, None);
    match err {
        omne_fs::Error::IoPath { op, path, .. } => {
            assert_eq!(op, "redact");
            assert_eq!(path, PathBuf::from("huge-redacted.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_absolute_paths_return_root_relative_requested_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let abs_path = dir.path().join("hello.txt");
    std::fs::write(&abs_path, "hello\n").expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.paths.allow_absolute = true;
    let ctx = Context::new(policy).expect("ctx");
    let response = read_ok(&ctx, abs_path, None, None);

    assert_eq!(response.path, PathBuf::from("hello.txt"));
    assert_eq!(response.requested_path, PathBuf::from("hello.txt"));
}

#[test]
fn absolute_paths_can_be_disabled_by_policy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let abs_path = dir.path().join("hello.txt");
    std::fs::write(&abs_path, "hello\n").expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.paths.allow_absolute = false;
    let ctx = Context::new(policy).expect("ctx");
    let message = invalid_path_message(read_err(&ctx, abs_path, None, None));
    assert!(message.contains(MSG_ABSOLUTE_REQUEST_PATHS));
}

#[test]
fn read_redacts_literal_replacement_without_expanding_capture_groups() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hello.txt");
    std::fs::write(&path, "API_KEY=abc123\nhello\n").expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.secrets.redact_regexes = vec!["API_KEY=([A-Za-z0-9_]+)".to_string()];
    policy.secrets.replacement = "***$1***".to_string();

    let ctx = Context::new(policy).expect("ctx");
    let response = read_ok(&ctx, "hello.txt", None, None);

    assert!(response.content.contains("***$1***"));
    assert!(!response.content.contains("abc123"));
    assert!(response.content.contains("hello"));
}

#[test]
fn read_rejects_outside_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(outside.path(), "hello").expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.paths.allow_absolute = true;
    let ctx = Context::new(policy).expect("ctx");
    let err = read_err(&ctx, outside.path().to_path_buf(), None, None);

    match err {
        omne_fs::Error::OutsideRoot { path, .. } => {
            assert!(path.is_absolute());
            assert_eq!(path, outside.path());
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_rejects_missing_absolute_paths_outside_root_as_outside_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    let missing = outside.path().join("missing.txt");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.paths.allow_absolute = true;
    let ctx = Context::new(policy).expect("ctx");
    let err = read_err(&ctx, missing, None, None);

    match err {
        omne_fs::Error::OutsideRoot { path, .. } => {
            assert!(path.is_absolute());
            assert_eq!(path, outside.path().join("missing.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn read_rejects_dangling_symlink_escape() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    let link_target = outside.path().join("missing.txt");
    symlink(&link_target, dir.path().join("link.txt")).expect("symlink");

    let ctx = Context::new(read_enabled_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let err = read_err(&ctx, "link.txt", None, None);

    match err {
        omne_fs::Error::OutsideRoot { path, .. } => {
            assert_eq!(path, PathBuf::from("link.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_supports_line_ranges() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lines.txt");
    std::fs::write(&path, "one\ntwo\nthree\nfour\n").expect("write");

    let ctx = Context::new(read_enabled_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let response = read_ok(&ctx, "lines.txt", Some(2), Some(3));

    assert_eq!(response.content, "two\nthree\n");
    assert_eq!(response.start_line, Some(2));
    assert_eq!(response.end_line, Some(3));
    assert!(!response.truncated);
    assert_eq!(response.bytes_read, 14);
}

#[test]
fn read_supports_line_ranges_without_trailing_newline() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lines.txt");
    std::fs::write(&path, "one\ntwo\nthree").expect("write");

    let ctx = Context::new(read_enabled_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let response = read_ok(&ctx, "lines.txt", Some(3), Some(3));

    assert_eq!(response.content, "three");
    assert_eq!(response.start_line, Some(3));
    assert_eq!(response.end_line, Some(3));
    assert!(!response.truncated);
    assert_eq!(response.bytes_read, 13);
}

#[test]
fn read_supports_line_ranges_with_bare_cr_line_endings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lines.txt");
    std::fs::write(&path, "one\rtwo\rthree\rfour\r").expect("write");

    let ctx = Context::new(read_enabled_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let response = read_ok(&ctx, "lines.txt", Some(2), Some(3));

    assert_eq!(response.content, "two\rthree\r");
    assert_eq!(response.start_line, Some(2));
    assert_eq!(response.end_line, Some(3));
    assert!(!response.truncated);
    assert_eq!(response.bytes_read, 14);
}

#[test]
fn read_line_ranges_skip_large_prefix_line_without_retaining_scratch_buffer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lines.txt");
    let large_prefix = "x".repeat(512 * 1024);
    std::fs::write(&path, format!("{large_prefix}\nkeep\n")).expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_read_bytes = (large_prefix.len() as u64).saturating_add(8);
    let ctx = Context::new(policy).expect("ctx");

    let response = read_ok(&ctx, "lines.txt", Some(2), Some(2));
    assert_eq!(response.content, "keep\n");
    assert_eq!(
        response.bytes_read,
        (large_prefix.len() as u64).saturating_add(6)
    );
}

#[test]
fn read_rejects_non_utf8_file_full_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("invalid.txt");
    std::fs::write(&path, b"fo\x80").expect("write");

    let ctx = Context::new(read_enabled_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let err = read_err(&ctx, "invalid.txt", None, None);

    match err {
        omne_fs::Error::InvalidUtf8 { path, .. } => {
            assert_eq!(path, PathBuf::from("invalid.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_rejects_non_utf8_file_line_range_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("invalid.txt");
    std::fs::write(&path, b"ok\n\xff\n").expect("write");

    let ctx = Context::new(read_enabled_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let err = read_err(&ctx, "invalid.txt", Some(2), Some(2));

    match err {
        omne_fs::Error::InvalidUtf8 { path, .. } => {
            assert_eq!(path, PathBuf::from("invalid.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_rejects_non_utf8_bytes_before_selected_line_range() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("invalid-prefix.txt");
    std::fs::write(&path, b"\xff\nok\n").expect("write");

    let ctx = Context::new(read_enabled_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let err = read_err(&ctx, "invalid-prefix.txt", Some(2), Some(2));

    match err {
        omne_fs::Error::InvalidUtf8 { path, .. } => {
            assert_eq!(path, PathBuf::from("invalid-prefix.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_line_ranges_respects_max_read_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bigline.txt");
    std::fs::write(&path, "x".repeat(200)).expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_read_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let err = read_err(&ctx, "bigline.txt", Some(1), Some(1));

    match err {
        omne_fs::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => {
            assert_eq!(path, PathBuf::from("bigline.txt"));
            assert_eq!(max_bytes, 64);
            assert!(size_bytes >= max_bytes.saturating_add(1));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn read_line_ranges_accept_file_at_max_read_bytes_boundary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("edge.txt");
    let content = "x".repeat(64);
    std::fs::write(&path, &content).expect("write");

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_read_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let response = read_ok(&ctx, "edge.txt", Some(1), Some(1));
    assert_eq!(response.path, PathBuf::from("edge.txt"));
    assert_eq!(response.content, content);
    assert!(!response.truncated);
    assert_eq!(response.bytes_read, 64);
}

#[test]
#[cfg(unix)]
fn read_rejects_fifo_special_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    unix_helpers::create_fifo(&fifo);

    let mut policy = read_enabled_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_read_bytes = 8;
    let ctx = Context::new(policy).expect("ctx");

    let message = invalid_path_message(read_err(&ctx, "pipe", None, None));
    assert!(message.contains(MSG_NOT_REGULAR_FILE));
    assert!(!message.contains(&dir.path().display().to_string()));
}

#[test]
#[cfg(unix)]
fn read_line_ranges_reject_fifo_special_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let fifo = dir.path().join("pipe");
    unix_helpers::create_fifo(&fifo);

    let ctx = Context::new(read_enabled_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");

    let message = invalid_path_message(read_err(&ctx, "pipe", Some(1), Some(1)));
    assert!(message.contains(MSG_NOT_REGULAR_FILE));
    assert!(!message.contains(&dir.path().display().to_string()));
}

#[test]
fn read_rejects_incomplete_line_ranges() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "one\ntwo\n").expect("write");

    let ctx = Context::new(read_enabled_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");

    let message = invalid_path_message(read_err(&ctx, "file.txt", Some(1), None));
    assert!(message.contains(MSG_LINE_RANGE_TOGETHER));

    let message = invalid_path_message(read_err(&ctx, "file.txt", None, Some(1)));
    assert!(message.contains(MSG_LINE_RANGE_TOGETHER));
}

#[test]
fn read_rejects_invalid_line_ranges() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "one\ntwo\n").expect("write");

    let ctx = Context::new(read_enabled_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");

    let message = invalid_path_message(read_err(&ctx, "file.txt", Some(0), Some(1)));
    assert!(message.contains(MSG_INVALID_LINE_RANGE));

    let message = invalid_path_message(read_err(&ctx, "file.txt", Some(2), Some(1)));
    assert!(message.contains(MSG_INVALID_LINE_RANGE));
}

#[test]
fn read_line_ranges_reject_out_of_bounds_requests() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "one\ntwo\n").expect("write");

    let ctx = Context::new(read_enabled_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");

    let message = invalid_path_message(read_err(&ctx, "file.txt", Some(1), Some(3)));
    assert!(message.contains(MSG_LINE_RANGE));
    assert!(message.contains(MSG_OUT_OF_BOUNDS));
}
