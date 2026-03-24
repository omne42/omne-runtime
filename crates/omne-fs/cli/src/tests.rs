use super::*;

#[cfg(unix)]
const FIFO_CHILD_ENV: &str = "SAFE_FS_TOOLS_FIFO_TEST_CHILD";
#[cfg(unix)]
const FIFO_CHILD_MARKER_ENV: &str = "SAFE_FS_TOOLS_FIFO_TEST_MARKER";
#[cfg(unix)]
const FIFO_CHILD_TIMEOUT_SECS_LOCAL: u64 = 5;
#[cfg(unix)]
const FIFO_CHILD_TIMEOUT_SECS_CI: u64 = 20;
#[cfg(unix)]
const FIFO_CHILD_POLL_MILLIS: u64 = 20;

const STDIN_CHILD_ENV: &str = "SAFE_FS_TOOLS_STDIN_TEST_CHILD";
const STDIN_CHILD_PAYLOAD: &str = "stdin payload\n";

#[cfg(unix)]
fn create_fifo(path: &std::path::Path) {
    let status = std::process::Command::new("mkfifo")
        .arg("-m")
        .arg("600")
        .arg(path)
        .status()
        .expect("spawn mkfifo");
    assert!(status.success(), "mkfifo failed with status {status}");
}

fn json_contains_string(value: &serde_json::Value, needle: &str) -> bool {
    match value {
        serde_json::Value::String(text) => text.contains(needle),
        serde_json::Value::Array(values) => values.iter().any(|v| json_contains_string(v, needle)),
        serde_json::Value::Object(map) => map.values().any(|v| json_contains_string(v, needle)),
        _ => false,
    }
}

fn normalize_path_for_compare(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let mut collapsed = String::with_capacity(normalized.len());
    let mut prev_sep = false;
    for ch in normalized.chars() {
        if ch == '/' {
            if !prev_sep {
                collapsed.push(ch);
            }
            prev_sep = true;
        } else {
            collapsed.push(ch);
            prev_sep = false;
        }
    }
    if cfg!(windows) {
        collapsed.to_ascii_lowercase()
    } else {
        collapsed
    }
}

fn json_contains_normalized_path(value: &serde_json::Value, normalized_needle: &str) -> bool {
    match value {
        serde_json::Value::String(text) => {
            normalize_path_for_compare(text).contains(normalized_needle)
        }
        serde_json::Value::Array(values) => values
            .iter()
            .any(|v| json_contains_normalized_path(v, normalized_needle)),
        serde_json::Value::Object(map) => map
            .values()
            .any(|v| json_contains_normalized_path(v, normalized_needle)),
        _ => false,
    }
}

fn alternate_path_representation(path: &std::path::Path) -> String {
    let rendered = path.display().to_string();
    #[cfg(windows)]
    {
        rendered.replace('\\', "/").to_ascii_uppercase()
    }
    #[cfg(not(windows))]
    {
        rendered.replace('/', "//")
    }
}

fn env_flag_enabled(name: &str) -> bool {
    let Ok(value) = std::env::var(name) else {
        return false;
    };
    let normalized = value.trim().to_ascii_lowercase();
    matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
}

fn make_redaction() -> (tempfile::TempDir, PathRedaction) {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = omne_fs::policy::SandboxPolicy::single_root(
        "root",
        dir.path(),
        omne_fs::policy::RootMode::ReadOnly,
    );
    let redaction = PathRedaction::from_policy(&policy);
    (dir, redaction)
}

fn assert_kind(details: &serde_json::Value, expected_kind: &str) {
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some(expected_kind)
    );
}

fn assert_no_abs_path_leak(details: &serde_json::Value, abs_path: &std::path::Path) {
    let normalized_abs_path = normalize_path_for_compare(&abs_path.display().to_string());
    assert!(
        !json_contains_normalized_path(details, &normalized_abs_path),
        "expected redacted details to not contain absolute path: {details}"
    );
}

#[cfg(unix)]
fn run_fifo_rejection_case() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("pipe.diff");
    create_fifo(&path);

    let err = super::input::load_text_limited(&path, 8).expect_err("should reject");
    match err {
        omne_fs::Error::InvalidPath(_) => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn cli_rejects_zero_max_patch_bytes() {
    let err = Cli::try_parse_from([
        "omne-fs",
        "--policy",
        "policy.toml",
        "--max-patch-bytes",
        "0",
        "read",
        "--root",
        "root",
        "README.md",
    ])
    .expect_err("expected clap to reject --max-patch-bytes=0");
    let message = err.to_string();
    assert!(
        message.contains("max-patch-bytes"),
        "unexpected clap error: {message}"
    );
}

#[test]
fn load_text_limited_rejects_large_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("big.diff");
    std::fs::write(&path, "x".repeat(100)).expect("write");

    let err = super::input::load_text_limited(&path, 10).expect_err("should reject");
    match err {
        omne_fs::Error::InputTooLarge {
            size_bytes,
            max_bytes,
        } => {
            assert_eq!(size_bytes, 100);
            assert_eq!(max_bytes, 10);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn load_text_limited_rejects_zero_max_bytes() {
    let err = super::input::load_text_limited(std::path::Path::new("-"), 0)
        .expect_err("zero max bytes should be rejected");
    match err {
        omne_fs::Error::InvalidPolicy(message) => {
            assert!(
                message.contains("must be > 0"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn load_text_limited_rejects_max_bytes_above_hard_limit() {
    let err = super::input::load_text_limited(std::path::Path::new("-"), u64::MAX)
        .expect_err("max bytes above hard limit should be rejected");
    match err {
        omne_fs::Error::InvalidPolicy(message) => {
            assert!(
                message.contains("hard limit"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn load_text_limited_reads_stdin_dash_path() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    if env_flag_enabled(STDIN_CHILD_ENV) {
        let text = super::input::load_text_limited(
            std::path::Path::new("-"),
            u64::try_from(STDIN_CHILD_PAYLOAD.len()).expect("payload len"),
        )
        .expect("read stdin payload");
        assert_eq!(text, STDIN_CHILD_PAYLOAD);
        return;
    }

    let mut child = Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg("tests::load_text_limited_reads_stdin_dash_path")
        .arg("--nocapture")
        .env(STDIN_CHILD_ENV, "1")
        .stdin(Stdio::piped())
        .spawn()
        .expect("spawn child test process");

    let mut stdin = child.stdin.take().expect("child stdin");
    stdin
        .write_all(STDIN_CHILD_PAYLOAD.as_bytes())
        .expect("write child stdin");
    drop(stdin);

    let status = child.wait().expect("wait child status");
    assert!(status.success(), "child test failed: {status}");
}

#[test]
fn load_text_limited_rejects_invalid_utf8() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("invalid-utf8.bin");
    std::fs::write(&path, [0xf0, 0x28, 0x8c, 0x28]).expect("write invalid utf8 bytes");

    let err = super::input::load_text_limited(&path, 32).expect_err("should reject invalid utf8");
    match err {
        omne_fs::Error::InvalidUtf8 {
            path: err_path,
            source: _,
        } => assert_eq!(err_path, path),
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn load_text_limited_rejects_symlink_paths() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.diff");
    let link = dir.path().join("link.diff");
    std::fs::write(&real, "ok\n").expect("write");
    symlink(&real, &link).expect("symlink");

    let err = super::input::load_text_limited(&link, 16).expect_err("should reject");
    match err {
        omne_fs::Error::InvalidPath(message) => {
            assert!(message.contains("symlink"), "unexpected message: {message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(windows)]
fn load_text_limited_rejects_symlink_paths() {
    use std::io::ErrorKind;
    use std::os::windows::fs::symlink_file;

    let dir = tempfile::tempdir().expect("tempdir");
    let real = dir.path().join("real.diff");
    let link = dir.path().join("link.diff");
    std::fs::write(&real, "ok\n").expect("write");

    match symlink_file(&real, &link) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            if env_flag_enabled("CI") {
                panic!(
                    "symlink test requires Windows symlink privileges in CI (set Developer Mode or grant SeCreateSymbolicLinkPrivilege): {err}"
                );
            }
            if env_flag_enabled("SAFE_FS_TOOLS_ALLOW_WINDOWS_SYMLINK_SKIP") {
                eprintln!(
                    "skipping symlink test due to permission denied (SAFE_FS_TOOLS_ALLOW_WINDOWS_SYMLINK_SKIP=1): {err}"
                );
                return;
            }
            panic!(
                "symlink_file permission denied. Enable Developer Mode or grant SeCreateSymbolicLinkPrivilege. \
Set SAFE_FS_TOOLS_ALLOW_WINDOWS_SYMLINK_SKIP=1 to skip this test explicitly on local machines: {err}"
            );
        }
        Err(err) => panic!("symlink_file failed: {err}"),
    }

    let err = super::input::load_text_limited(&link, 16).expect_err("should reject");
    match &err {
        omne_fs::Error::InvalidPath(message) => {
            assert!(message.contains("symlink"), "unexpected message: {message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let details = tool_error_details_with(&err, None, true, true);
    assert_kind(&details, "invalid_path");
    assert_eq!(
        details.get("message").and_then(|v| v.as_str()),
        Some("invalid path")
    );
    assert_no_abs_path_leak(&details, dir.path());
}

#[test]
#[cfg(unix)]
fn load_text_limited_rejects_fifo_special_files() {
    use std::process::Command;
    use std::time::{Duration, Instant};

    if env_flag_enabled(FIFO_CHILD_ENV) {
        run_fifo_rejection_case();
        if let Ok(marker) = std::env::var(FIFO_CHILD_MARKER_ENV) {
            std::fs::write(&marker, "done").expect("write child marker");
        }
        return;
    }

    let marker_dir = tempfile::tempdir().expect("tempdir");
    let marker_path = marker_dir.path().join("fifo-child.done");
    let mut child = Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg("tests::load_text_limited_rejects_fifo_special_files")
        .arg("--nocapture")
        .env(FIFO_CHILD_ENV, "1")
        .env(FIFO_CHILD_MARKER_ENV, marker_path.as_os_str())
        .spawn()
        .expect("spawn child test process");

    let timeout = Duration::from_secs(if env_flag_enabled("CI") {
        FIFO_CHILD_TIMEOUT_SECS_CI
    } else {
        FIFO_CHILD_TIMEOUT_SECS_LOCAL
    });
    let start = Instant::now();
    loop {
        match child.try_wait().expect("wait child status") {
            Some(status) => {
                let elapsed = start.elapsed();
                assert!(
                    status.success(),
                    "child test exited with non-zero status after {elapsed:?}: {status}"
                );
                assert!(
                    marker_path.exists(),
                    "child process exited after {elapsed:?} with status {status} but did not execute fifo assertion path"
                );
                break;
            }
            None if start.elapsed() >= timeout => {
                let elapsed = start.elapsed();
                let status_before_kill = child.try_wait().expect("poll child before kill");
                let kill_result = child.kill();
                let status_after_kill = child.wait().ok();
                panic!(
                    "load_text_limited timed out on fifo path in child process after {elapsed:?} (timeout {timeout:?}); status_before_kill={status_before_kill:?}; kill_result={kill_result:?}; status_after_kill={status_after_kill:?}"
                );
            }
            None => std::thread::sleep(Duration::from_millis(FIFO_CHILD_POLL_MILLIS)),
        }
    }
}

#[test]
fn assert_no_abs_path_leak_catches_equivalent_path_representation() {
    let dir = tempfile::tempdir().expect("tempdir");
    let leaked = serde_json::json!({
        "path": format!("{}/file.txt", alternate_path_representation(dir.path()))
    });
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_no_abs_path_leak(&leaked, dir.path());
    }));
    assert!(
        panic.is_err(),
        "expected path leak detector to catch equivalent path representation"
    );
}

#[test]
fn tool_error_details_covers_invalid_path() {
    let err = omne_fs::Error::InvalidPath("bad path".to_string());
    let details = tool_error_details(&err);
    assert_kind(&details, "invalid_path");
    assert_eq!(
        details.get("message").and_then(|v| v.as_str()),
        Some("bad path")
    );
}

#[test]
fn tool_error_details_includes_safe_invalid_path_message_when_redacting() {
    let err = omne_fs::Error::InvalidPath("bad path".to_string());
    let details = tool_error_details_with(&err, None, true, false);
    assert_kind(&details, "invalid_path");
    assert_eq!(
        details.get("message").and_then(|v| v.as_str()),
        Some("invalid path")
    );
}

#[test]
fn tool_error_details_covers_root_not_found() {
    let err = omne_fs::Error::RootNotFound("missing".to_string());
    let details = tool_error_details(&err);
    assert_kind(&details, "root_not_found");
    assert_eq!(
        details.get("root_id").and_then(|v| v.as_str()),
        Some("missing")
    );
}

#[test]
fn tool_error_details_includes_safe_invalid_policy_message_when_redacting() {
    let err = omne_fs::Error::InvalidPolicy("bad policy".to_string());
    let details = tool_error_details_with(&err, None, true, false);
    assert_kind(&details, "invalid_policy");
    assert_eq!(
        details.get("message").and_then(|v| v.as_str()),
        Some("invalid policy")
    );
}

#[test]
fn format_path_for_error_strips_root_prefix_when_redacting() {
    let (dir, redaction) = make_redaction();
    let path = dir.path().join("sub").join("file.txt");

    let formatted = crate::error::format_path_for_error(&path, Some(&redaction), true, false);
    assert_eq!(
        PathBuf::from(formatted),
        PathBuf::from("sub").join("file.txt")
    );
}

#[test]
fn format_path_for_error_strict_redaction_hides_file_names_outside_roots() {
    let (_dir, redaction) = make_redaction();
    let other = tempfile::tempdir().expect("tempdir");
    let path = other.path().join(".env");

    let formatted = crate::error::format_path_for_error(&path, Some(&redaction), true, true);
    assert_eq!(formatted, "<redacted>");
}

#[test]
fn format_path_for_error_redacts_relative_paths_to_file_name() {
    let path = PathBuf::from("nested/secret/file.txt");
    let formatted = crate::error::format_path_for_error(&path, None, true, false);
    assert_eq!(formatted, "file.txt");
}

#[test]
fn tool_error_details_redacts_walkdir_message() {
    let (dir, redaction) = make_redaction();

    let missing = dir.path().join("missing");
    let walk_err = walkdir::WalkDir::new(&missing)
        .into_iter()
        .filter_map(|entry| entry.err())
        .next()
        .expect("walkdir error");
    let err = omne_fs::Error::WalkDir(walk_err);

    let details = tool_error_details_with(&err, Some(&redaction), true, false);
    assert_kind(&details, "walkdir");
    assert!(
        details.get("message").is_none(),
        "expected walkdir message omitted in redacted mode"
    );
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("missing")
    );

    assert_no_abs_path_leak(&details, dir.path());
}

#[test]
fn tool_error_details_redacts_walkdir_root_message() {
    let (dir, redaction) = make_redaction();

    let err = omne_fs::Error::WalkDirRoot {
        path: dir.path().join("missing"),
        source: std::io::Error::from_raw_os_error(2),
    };

    let details = tool_error_details_with(&err, Some(&redaction), true, false);
    assert_kind(&details, "walkdir_root");
    assert!(
        details.get("message").is_none(),
        "expected walkdir message omitted in redacted mode"
    );
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("missing")
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );

    assert_no_abs_path_leak(&details, dir.path());
}

#[test]
fn tool_error_details_includes_walkdir_root_message_when_not_redacting() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("missing");

    let err = omne_fs::Error::WalkDirRoot {
        path: missing.clone(),
        source: std::io::Error::from_raw_os_error(2),
    };

    let details = tool_error_details_with(&err, None, false, false);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("walkdir_root")
    );
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some(missing.to_string_lossy().as_ref())
    );
    assert!(
        details.get("message").and_then(|v| v.as_str()).is_some(),
        "expected message in non-redacted mode"
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );

    assert!(
        json_contains_string(&details, &dir.path().display().to_string()),
        "expected details to include absolute path in non-redacted mode: {details}"
    );
}

#[test]
fn tool_error_details_redacts_io_message() {
    let err = omne_fs::Error::Io(std::io::Error::from_raw_os_error(2));
    let details = tool_error_details_with(&err, None, true, false);
    assert_eq!(details.get("kind").and_then(|v| v.as_str()), Some("io"));
    assert!(
        details.get("message").is_none(),
        "expected io message omitted in redacted mode"
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );
}

#[test]
fn tool_error_details_includes_io_details_when_not_redacting() {
    let err = omne_fs::Error::Io(std::io::Error::from_raw_os_error(2));
    let details = tool_error_details_with(&err, None, false, false);
    assert_eq!(details.get("kind").and_then(|v| v.as_str()), Some("io"));
    assert!(
        details.get("message").and_then(|v| v.as_str()).is_some(),
        "expected io message in non-redacted mode"
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );
}

#[test]
fn tool_error_details_redacts_io_path_details() {
    let (dir, redaction) = make_redaction();

    let err = omne_fs::Error::IoPath {
        op: "open",
        path: dir.path().join("file.txt"),
        source: std::io::Error::from_raw_os_error(2),
    };
    let details = tool_error_details_with(&err, Some(&redaction), true, false);
    assert_kind(&details, "io_path");
    assert_eq!(details.get("op").and_then(|v| v.as_str()), Some("open"));
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("file.txt")
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );

    assert_no_abs_path_leak(&details, dir.path());
}

#[test]
fn tool_error_details_includes_io_path_details_when_not_redacting() {
    let err = omne_fs::Error::IoPath {
        op: "open",
        path: PathBuf::from("file.txt"),
        source: std::io::Error::from_raw_os_error(2),
    };
    let details = tool_error_details_with(&err, None, false, false);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("io_path")
    );
    assert_eq!(details.get("op").and_then(|v| v.as_str()), Some("open"));
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("file.txt")
    );
    assert!(
        details.get("message").and_then(|v| v.as_str()).is_some(),
        "expected message in non-redacted mode"
    );
    assert!(
        details.get("io_kind").and_then(|v| v.as_str()).is_some(),
        "expected io_kind"
    );
    assert_eq!(
        details.get("raw_os_error").and_then(|v| v.as_i64()),
        Some(2)
    );
}

#[test]
fn tool_error_details_strict_redacts_io_path_details() {
    let (dir, redaction) = make_redaction();

    let err = omne_fs::Error::IoPath {
        op: "open",
        path: dir.path().join("file.txt"),
        source: std::io::Error::from_raw_os_error(2),
    };
    let details = tool_error_details_with(&err, Some(&redaction), true, true);
    assert_kind(&details, "io_path");
    assert_eq!(details.get("op").and_then(|v| v.as_str()), Some("open"));
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("<redacted>")
    );
    assert!(
        details.get("message").is_none(),
        "expected message omitted in redacted mode"
    );
    assert_no_abs_path_leak(&details, dir.path());

    let message = tool_public_message(&err, Some(&redaction), true, true);
    assert_eq!(message, "io error during open (<redacted>)");
}

#[test]
fn tool_error_details_redacts_patch_message() {
    let raw = "/abs/path/file.txt: bad patch";
    let err = omne_fs::Error::Patch(raw.to_string());
    let details = tool_error_details_with(&err, None, true, false);
    assert_eq!(details.get("kind").and_then(|v| v.as_str()), Some("patch"));
    assert!(
        details.get("message").is_none(),
        "expected patch message omitted in redacted mode"
    );
    assert!(
        !json_contains_string(&details, raw),
        "expected redacted patch details to not contain raw path: {details}"
    );
}

#[test]
fn tool_error_details_keeps_patch_message_when_not_redacting() {
    let err = omne_fs::Error::Patch("file.txt: bad patch".to_string());
    let details = tool_error_details_with(&err, None, false, false);
    assert_eq!(details.get("kind").and_then(|v| v.as_str()), Some("patch"));
    assert_eq!(
        details.get("message").and_then(|v| v.as_str()),
        Some("file.txt: bad patch")
    );
}

#[test]
fn tool_error_details_redacts_not_permitted_message() {
    let err = omne_fs::Error::NotPermitted("/abs/path is blocked".to_string());
    let details = tool_error_details_with(&err, None, true, false);
    assert_eq!(
        details.get("kind").and_then(|v| v.as_str()),
        Some("not_permitted")
    );
    assert_eq!(
        details.get("message").and_then(|v| v.as_str()),
        Some("not permitted")
    );
}

#[test]
fn tool_public_message_redacts_patch_message() {
    let err = omne_fs::Error::Patch("/abs/path/file.txt: bad patch".to_string());
    let message = tool_public_message(&err, None, true, false);
    assert_eq!(message, "failed to apply patch");
}

#[test]
fn tool_public_message_redacts_io_message() {
    let err = omne_fs::Error::Io(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        "/abs/path denied",
    ));
    let message = tool_public_message(&err, None, true, false);
    assert_eq!(message, "io error");
}

#[test]
fn tool_public_message_redacts_not_permitted_message() {
    let err = omne_fs::Error::NotPermitted("/abs/path denied".to_string());
    let message = tool_public_message(&err, None, true, false);
    assert_eq!(message, "not permitted");
}

#[test]
fn tool_error_details_strict_redacts_walkdir_message() {
    let (dir, redaction) = make_redaction();

    let missing = dir.path().join("missing");
    let walk_err = walkdir::WalkDir::new(&missing)
        .into_iter()
        .filter_map(|entry| entry.err())
        .next()
        .expect("walkdir error");
    let err = omne_fs::Error::WalkDir(walk_err);

    let details = tool_error_details_with(&err, Some(&redaction), true, true);
    assert_kind(&details, "walkdir");
    assert!(
        details.get("message").is_none(),
        "expected walkdir message omitted in redacted mode"
    );
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("<redacted>")
    );
    assert!(
        !json_contains_string(&details, "missing"),
        "expected strict redaction to hide file names: {details}"
    );
    assert_no_abs_path_leak(&details, dir.path());

    let message = tool_public_message(&err, Some(&redaction), true, true);
    assert_eq!(message, "walkdir error");
}

#[test]
fn tool_error_details_strict_redacts_outside_root_path() {
    let (_dir, redaction) = make_redaction();
    let other = tempfile::tempdir().expect("tempdir");

    let blocked = other.path().join("secret.txt");
    let err = omne_fs::Error::OutsideRoot {
        root_id: "root".to_string(),
        path: blocked.clone(),
    };
    let details = tool_error_details_with(&err, Some(&redaction), true, true);
    assert_kind(&details, "outside_root");
    assert_eq!(
        details.get("root_id").and_then(|v| v.as_str()),
        Some("<redacted>")
    );
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("<redacted>")
    );
    assert!(
        !json_contains_string(&details, "secret.txt"),
        "expected strict redaction to hide file names: {details}"
    );
    assert_no_abs_path_leak(&details, &blocked);

    let message = tool_public_message(&err, Some(&redaction), true, true);
    assert_eq!(message, "path resolves outside root '<redacted>'");
}

#[test]
fn tool_error_details_strict_redacts_secret_path_denied_path() {
    let (dir, redaction) = make_redaction();

    let denied = dir.path().join(".env");
    let err = omne_fs::Error::SecretPathDenied(denied.clone());
    let details = tool_error_details_with(&err, Some(&redaction), true, true);
    assert_kind(&details, "secret_path_denied");
    assert_eq!(
        details.get("path").and_then(|v| v.as_str()),
        Some("<redacted>")
    );
    assert!(
        !json_contains_string(&details, ".env"),
        "expected strict redaction to hide file names: {details}"
    );
    assert_no_abs_path_leak(&details, &denied);

    let message = tool_public_message(&err, Some(&redaction), true, true);
    assert_eq!(message, "path is denied by secret rules: <redacted>");
}
