#![cfg(feature = "grep")]

mod common;

#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;

use common::test_policy;
use omne_fs::ops::{Context, GrepRequest, grep};
use policy_meta::WriteScope;

#[cfg(all(feature = "glob", unix))]
use omne_fs::ops::{GlobRequest, glob_paths};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[cfg(unix)]
fn is_running_as_root() -> bool {
    // SAFETY:
    // - Rust std does not expose the effective uid on Unix.
    // - `geteuid` takes no pointers, touches no caller-owned memory, and has no preconditions.
    // - The call is read-only process inspection used only to decide whether a permission test
    //   should expect `EACCES` behavior or skip under root.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(unix)]
struct PermissionRestoreGuard {
    path: PathBuf,
    mode: u32,
}

#[cfg(unix)]
impl PermissionRestoreGuard {
    fn set(path: &std::path::Path, mode: u32) -> Self {
        let prev = std::fs::symlink_metadata(path)
            .expect("stat before chmod")
            .permissions()
            .mode()
            & 0o777;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        Self {
            path: path.to_path_buf(),
            mode: prev,
        }
    }
}

#[cfg(unix)]
impl Drop for PermissionRestoreGuard {
    fn drop(&mut self) {
        if let Err(err) =
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(self.mode))
        {
            eprintln!(
                "failed to restore permissions for {}: {err}",
                self.path.display()
            );
        }
    }
}

#[cfg(unix)]
fn chmod_000_blocks_read_dir(path: &std::path::Path) -> PermissionRestoreGuard {
    let guard = PermissionRestoreGuard::set(path, 0o000);
    match std::fs::read_dir(path) {
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => guard,
        Ok(_) => {
            panic!(
                "permission precondition failed: {} remains traversable after chmod 000",
                path.display()
            );
        }
        Err(err) => {
            panic!(
                "permission precondition failed: probe read_dir({}) returned unexpected error: {err}",
                path.display()
            );
        }
    }
}

#[cfg(unix)]
fn chmod_000_blocks_file_read(path: &std::path::Path) -> PermissionRestoreGuard {
    let guard = PermissionRestoreGuard::set(path, 0o000);
    match std::fs::File::open(path) {
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => guard,
        Ok(_) => {
            panic!(
                "permission precondition failed: {} remains readable after chmod 000",
                path.display()
            );
        }
        Err(err) => {
            panic!(
                "permission precondition failed: probe open({}) returned unexpected error: {err}",
                path.display()
            );
        }
    }
}

#[test]
fn grep_globs_support_leading_dot_slash() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("src")).expect("mkdir");
    std::fs::write(dir.path().join("src").join("a.txt"), "needle\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("./src/*.txt".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("src/a.txt"));
}

#[test]
fn grep_globs_reject_absolute_and_parent_segments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");

    for (pattern, expected_message_fragment) in [
        ("/src/*.txt", "must not start with '/'"),
        ("../**/*.txt", "must not contain '..' segments"),
        ("src/../*.txt", "must not contain '..' segments"),
    ] {
        let err = grep(
            &ctx,
            GrepRequest {
                root_id: "root".to_string(),
                query: "needle".to_string(),
                regex: false,
                glob: Some(pattern.to_string()),
            },
        )
        .expect_err("should reject");

        match err {
            omne_fs::Error::InvalidPath(message) => {
                assert!(
                    message.contains(expected_message_fragment),
                    "expected error message to contain {expected_message_fragment:?}, got {message:?}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
fn grep_glob_file_prefix_is_not_filtered_by_directory_probe_skip_glob() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.traversal.skip_globs = vec!["a.txt/*".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("a.txt".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
}

#[test]
fn grep_rejects_empty_query() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    for query in ["", "   \t"] {
        let err = grep(
            &ctx,
            GrepRequest {
                root_id: "root".to_string(),
                query: query.to_string(),
                regex: false,
                glob: None,
            },
        )
        .expect_err("empty query should be rejected");

        match err {
            omne_fs::Error::InvalidPath(message) => {
                assert!(
                    message.contains("must not be empty"),
                    "expected empty-query error, got {message:?}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
fn grep_rejects_oversized_query() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let oversized = "a".repeat((8 * 1024) + 1);
    for regex in [false, true] {
        let err = grep(
            &ctx,
            GrepRequest {
                root_id: "root".to_string(),
                query: oversized.clone(),
                regex,
                glob: None,
            },
        )
        .expect_err("oversized query should be rejected");

        match err {
            omne_fs::Error::InvalidPath(message) => {
                assert!(
                    message.contains("grep query is too large"),
                    "expected oversized-query error, got {message:?}"
                );
                assert!(
                    !message.contains("aaaa"),
                    "oversized query content should not be echoed in error: {message:?}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}

#[test]
fn grep_multiple_matches_keep_relative_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle one\nneedle two\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 2);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
    assert_eq!(resp.matches[1].path, PathBuf::from("a.txt"));
}

#[test]
fn grep_splits_bare_cr_lines_and_reports_line_numbers() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), b"alpha\rneedle\romega\r").expect("write");

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
    assert_eq!(resp.matches[0].line, 2);
    assert_eq!(resp.matches[0].text, "needle");
}

#[test]
#[cfg(unix)]
fn grep_skips_dangling_symlink_targets() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let missing = dir.path().join("missing.txt");
    symlink(&missing, dir.path().join("b.txt")).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
    assert_eq!(resp.skipped_dangling_symlink_targets, 1);
}

#[test]
#[cfg(unix)]
fn grep_does_not_follow_symlink_root_prefix() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(outside.path().join("a.txt"), "needle\n").expect("write");
    symlink(outside.path(), dir.path().join("sub")).expect("symlink dir");

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let result = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("sub/**/*.txt".to_string()),
        },
    );

    match result {
        Ok(resp) => {
            assert!(resp.matches.is_empty());
            assert!(
                resp.skipped_walk_errors > 0,
                "expected root-prefix symlink escape to be reported as walk error"
            );
            assert!(!resp.scan_limit_reached);
            assert!(!resp.truncated);
            assert_eq!(resp.scan_limit_reason, None);
        }
        Err(omne_fs::Error::InvalidPath(message)) => {
            assert!(
                message.contains("escapes selected root"),
                "unexpected error: {message}"
            );
        }
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn grep_skips_walkdir_errors() {
    if is_running_as_root() {
        eprintln!(
            "grep_skips_walkdir_errors skipped: requires non-root to validate walkdir permission errors"
        );
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let blocked = dir.path().join("blocked");
    std::fs::create_dir(&blocked).expect("mkdir");
    std::fs::write(blocked.join("b.txt"), "needle\n").expect("write");
    let _chmod_guard = chmod_000_blocks_read_dir(&blocked);

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
    assert!(
        resp.skipped_walk_errors > 0,
        "expected at least one walk error"
    );
}

#[test]
#[cfg(unix)]
fn grep_root_walkdir_error_does_not_leak_absolute_paths() {
    if is_running_as_root() {
        eprintln!(
            "grep_root_walkdir_error_does_not_leak_absolute_paths skipped: requires non-root to validate path redaction"
        );
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");

    let blocked = dir.path().join("blocked");
    std::fs::create_dir(&blocked).expect("mkdir");
    std::fs::write(blocked.join("b.txt"), "needle\n").expect("write");
    let _chmod_guard = chmod_000_blocks_read_dir(&blocked);

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let err = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("blocked/**/*.txt".to_string()),
        },
    )
    .expect_err("should fail");

    match &err {
        omne_fs::Error::WalkDirRoot { path, .. } => {
            assert!(!path.is_absolute());
            assert_eq!(path.as_path(), Path::new("blocked"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let rendered = err.to_string();
    assert!(
        !rendered.contains(&dir.path().display().to_string()),
        "expected error to not contain absolute root path: {rendered}"
    );
}

#[test]
#[cfg(unix)]
fn grep_skips_unreadable_files() {
    if is_running_as_root() {
        eprintln!(
            "grep_skips_unreadable_files skipped: requires non-root to validate file permission errors"
        );
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");
    let unreadable = dir.path().join("b.txt");
    std::fs::write(&unreadable, "needle\n").expect("write");
    let _chmod_guard = chmod_000_blocks_file_read(&unreadable);

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
    assert_eq!(resp.skipped_io_errors, 1);
}

#[test]
fn grep_respects_max_walk_ms_time_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    // Contract: max_walk_ms=0 means "immediate time limit", not "disabled".
    policy.limits.max_walk_ms = Some(0);

    let ctx = Context::new(policy).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert!(resp.truncated);
    assert!(resp.scan_limit_reached);
    assert_eq!(
        resp.scan_limit_reason,
        Some(omne_fs::ops::ScanLimitReason::Time)
    );
}

#[test]
fn grep_redacts_sensitive_match_text() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "API_KEY=abc123 hello\n").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_read_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "API_KEY=".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert!(resp.matches[0].text.contains("***REDACTED***"));
    assert!(!resp.matches[0].text.contains("abc123"));
}

#[test]
fn grep_marks_truncated_when_redaction_output_exceeds_limit() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("huge.txt"), "a".repeat(8_200)).expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.secrets.redact_regexes = vec!["a".to_string()];
    policy.secrets.replacement = "x".repeat(1024);
    policy.limits.max_line_bytes = 1024 * 1024;
    policy.limits.max_results = 1;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "a".to_string(),
            regex: false,
            glob: Some("huge.txt".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("huge.txt"));
    assert_eq!(resp.matches[0].text, "[REDACTION_OUTPUT_LIMIT_EXCEEDED]");
    assert!(resp.matches[0].line_truncated);
}

#[test]
fn grep_skips_non_utf8_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "API_KEY=abc123 hello\n").expect("write");
    std::fs::write(dir.path().join("bin.dat"), [0xff, 0xfe, 0xfd]).expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_read_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "API_KEY=".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.skipped_non_utf8_files, 1);
    assert_eq!(resp.skipped_too_large_files, 0);
}

#[test]
fn grep_skips_too_large_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "API_KEY=abc123 hello\n").expect("write");
    std::fs::write(dir.path().join("large.txt"), "x".repeat(200)).expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_read_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "API_KEY=".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.skipped_non_utf8_files, 0);
    assert_eq!(resp.skipped_too_large_files, 1);
}

#[test]
fn grep_skips_non_utf8_and_too_large_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "API_KEY=abc123 hello\n").expect("write");
    std::fs::write(dir.path().join("large.txt"), "x".repeat(200)).expect("write");
    std::fs::write(dir.path().join("bin.dat"), [0xff, 0xfe, 0xfd]).expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_read_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "API_KEY=".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert!(resp.matches[0].text.contains("***REDACTED***"));
    assert!(!resp.matches[0].text.contains("abc123"));
    assert_eq!(resp.skipped_non_utf8_files, 1);
    assert_eq!(resp.skipped_too_large_files, 1);
}

#[test]
fn grep_honors_max_walk_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "hello\n").expect("write");
    std::fs::write(dir.path().join("b.txt"), "world\n").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_walk_files = 1;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert!(resp.matches.is_empty());
    assert_eq!(resp.scanned_files, 1);
    assert!(resp.scan_limit_reached);
    assert!(resp.truncated);
}

#[test]
fn grep_honors_max_walk_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("sub").join("a.txt"), "hello\n").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_walk_entries = 1;
    // Keep policy valid (files <= entries), and rely on directory-first entry consumption
    // to isolate the Entries cap from the Files cap.
    policy.limits.max_walk_files = 1;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert!(resp.matches.is_empty());
    assert_eq!(resp.scanned_files, 0);
    assert!(resp.scan_limit_reached);
    assert!(resp.truncated);
    assert_eq!(
        resp.scan_limit_reason,
        Some(omne_fs::ops::ScanLimitReason::Entries)
    );
}

#[test]
fn grep_reports_line_truncation() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("long.txt"), "0123456789\n").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_line_bytes = 5;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "0".to_string(),
            regex: false,
            glob: Some("long.txt".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("long.txt"));
    assert_eq!(resp.matches[0].text, "01234");
    assert!(resp.matches[0].line_truncated);
}

#[test]
fn grep_handles_long_single_line_without_unbounded_buffer_growth() {
    let dir = tempfile::tempdir().expect("tempdir");
    let long_line = format!("needle-{}", "a".repeat(256 * 1024));
    std::fs::write(dir.path().join("long.txt"), long_line).expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_line_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("long.txt".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("long.txt"));
    assert!(resp.matches[0].line_truncated);
}

#[test]
fn grep_matches_tail_of_long_line_for_plain_query() {
    let dir = tempfile::tempdir().expect("tempdir");
    let long_line = format!("{}needle-tail\n", "a".repeat(256 * 1024));
    std::fs::write(dir.path().join("long.txt"), long_line).expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_line_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle-tail".to_string(),
            regex: false,
            glob: Some("long.txt".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("long.txt"));
    assert!(resp.matches[0].line_truncated);
}

#[test]
fn grep_matches_tail_of_long_line_for_regex_query() {
    let dir = tempfile::tempdir().expect("tempdir");
    let long_line = format!("{}needle-tail\n", "a".repeat(256 * 1024));
    std::fs::write(dir.path().join("long.txt"), long_line).expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_line_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle-tail$".to_string(),
            regex: true,
            glob: Some("long.txt".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("long.txt"));
    assert!(resp.matches[0].line_truncated);
}

#[test]
fn grep_regex_skips_single_line_above_regex_memory_cap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let long_line = format!("{}needle-tail\n", "a".repeat((8 * 1024 * 1024) + 1));
    std::fs::write(dir.path().join("long.txt"), long_line).expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_read_bytes = 16 * 1024 * 1024;
    policy.limits.max_line_bytes = 64;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle-tail$".to_string(),
            regex: true,
            glob: Some("long.txt".to_string()),
        },
    )
    .expect("grep");

    assert!(resp.matches.is_empty());
    assert_eq!(resp.skipped_too_large_files, 1);
}

#[test]
#[cfg(all(unix, feature = "glob"))]
fn glob_and_grep_include_symlink_files() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("target.txt"), "hello\n").expect("write");
    symlink(dir.path().join("target.txt"), dir.path().join("link.txt")).expect("symlink");

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");

    let glob = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "link.txt".to_string(),
        },
    )
    .expect("glob");
    assert_eq!(glob.matches, vec![PathBuf::from("link.txt")]);

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "hello".to_string(),
            regex: false,
            glob: Some("link.txt".to_string()),
        },
    )
    .expect("grep");
    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("link.txt"));
}

#[test]
#[cfg(all(unix, feature = "glob"))]
fn glob_and_grep_include_symlink_files_when_absolute_paths_are_disallowed() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("target.txt"), "hello\n").expect("write");
    symlink(dir.path().join("target.txt"), dir.path().join("link.txt")).expect("symlink");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.paths.allow_absolute = false;
    let ctx = Context::new(policy).expect("ctx");

    let glob = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "link.txt".to_string(),
        },
    )
    .expect("glob");
    assert_eq!(glob.matches, vec![PathBuf::from("link.txt")]);

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "hello".to_string(),
            regex: false,
            glob: Some("link.txt".to_string()),
        },
    )
    .expect("grep");
    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("link.txt"));
}

#[test]
fn grep_truncation_is_deterministic_under_max_results() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("b.txt"), "needle\n").expect("write");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_results = 1;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
    assert!(resp.truncated);
    assert!(resp.scan_limit_reached);
    assert_eq!(
        resp.scan_limit_reason,
        Some(omne_fs::ops::ScanLimitReason::Results)
    );
}

#[test]
fn grep_truncation_is_deterministic_under_response_byte_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a-long-name.txt"), "needle\n").expect("write");
    std::fs::write(dir.path().join("b-long-name.txt"), "needle\n").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_results = 2;
    policy.limits.max_line_bytes = 16;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a-long-name.txt"));
    assert!(resp.truncated);
    assert!(resp.scan_limit_reached);
    assert_eq!(
        resp.scan_limit_reason,
        Some(omne_fs::ops::ScanLimitReason::ResponseBytes)
    );
}

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn grep_response_budget_accounts_for_lossy_non_utf8_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "needle\n").expect("write");
    let non_utf8_name = OsString::from_vec(vec![0xff, b'.', b't', b'x', b't']);
    std::fs::write(dir.path().join(PathBuf::from(non_utf8_name)), "needle\n").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_results = 2;
    policy.limits.max_line_bytes = 11;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("a.txt"));
    assert!(resp.truncated);
    assert!(resp.scan_limit_reached);
    assert_eq!(
        resp.scan_limit_reason,
        Some(omne_fs::ops::ScanLimitReason::ResponseBytes)
    );
}

#[test]
fn grep_truncates_on_utf8_boundary() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("utf8.txt"), "€€€\n").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_line_bytes = 4;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "€".to_string(),
            regex: false,
            glob: Some("utf8.txt".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("utf8.txt"));
    assert_eq!(resp.matches[0].text, "€");
    assert!(resp.matches[0].line_truncated);
}
