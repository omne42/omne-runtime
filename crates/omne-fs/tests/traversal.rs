mod common;

#[cfg(any(feature = "glob", feature = "grep"))]
use std::path::PathBuf;

#[cfg(any(feature = "glob", feature = "grep"))]
use common::test_policy;
#[cfg(any(feature = "glob", feature = "grep"))]
use omne_fs::ops::Context;
#[cfg(any(feature = "glob", feature = "grep"))]
use policy_meta::WriteScope;

#[cfg(any(feature = "glob", feature = "grep"))]
fn setup_skip_glob_fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("node_modules").join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("keep.txt"), "needle_keep\n").expect("write");
    std::fs::write(
        dir.path().join("node_modules").join("skip.txt"),
        "needle_skip\n",
    )
    .expect("write");
    std::fs::write(
        dir.path().join("node_modules").join("sub").join("deep.txt"),
        "needle_deep\n",
    )
    .expect("write");
    dir
}

#[cfg(feature = "grep")]
fn assert_skip_glob_applies_to_grep_but_not_direct_read(skip_pattern: &str) {
    use omne_fs::ops::{GrepRequest, ReadRequest, grep, read_file};

    let dir = setup_skip_glob_fixture();

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.permissions.read = true;
    policy.permissions.grep = true;
    policy.traversal.skip_globs = vec![skip_pattern.to_string()];
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
    assert_eq!(resp.matches[0].path, PathBuf::from("keep.txt"));
    for blocked in [
        PathBuf::from("node_modules").join("skip.txt"),
        PathBuf::from("node_modules").join("sub").join("deep.txt"),
    ] {
        assert!(
            !resp.matches.iter().any(|m| m.path == blocked),
            "expected traversal.skip_globs to exclude {blocked:?}: {:?}",
            resp.matches
        );
    }
    assert_eq!(resp.scanned_entries, 1);
    assert_eq!(resp.scanned_files, 1);

    let read = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("node_modules").join("skip.txt"),
            start_line: None,
            end_line: None,
        },
    )
    .expect("read");
    assert_eq!(read.content, "needle_skip\n");
}

#[cfg(feature = "glob")]
fn assert_skip_glob_applies_to_glob_paths(skip_pattern: &str) {
    use omne_fs::ops::{GlobRequest, glob_paths};

    let dir = setup_skip_glob_fixture();

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.permissions.read = true;
    policy.permissions.glob = true;
    policy.traversal.skip_globs = vec![skip_pattern.to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "**/*".to_string(),
        },
    )
    .expect("glob");

    for blocked in [
        PathBuf::from("node_modules").join("skip.txt"),
        PathBuf::from("node_modules").join("sub").join("deep.txt"),
    ] {
        assert!(
            !resp.matches.iter().any(|path| path == &blocked),
            "expected traversal.skip_globs to exclude {blocked:?}: {:?}",
            resp.matches
        );
    }
    assert!(
        resp.matches
            .iter()
            .any(|path| path == &PathBuf::from("keep.txt")),
        "expected keep.txt to remain visible in traversal result: {:?}",
        resp.matches
    );
    assert_eq!(resp.scanned_entries, 1);
    assert_eq!(resp.scanned_files, 1);
}

#[test]
#[cfg(feature = "grep")]
fn traversal_skip_globs_support_leading_dot_slash() {
    assert_skip_glob_applies_to_grep_but_not_direct_read("./node_modules/**");
}

#[cfg(any(feature = "glob", feature = "grep"))]
fn assert_skip_glob_pattern_rejected(pattern: &str, expected_message_fragment: &str) {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.traversal.skip_globs = vec![pattern.to_string()];
    let err = Context::new(policy).expect_err("should reject");

    match err {
        omne_fs::Error::InvalidPolicy(message) => {
            assert!(
                message.contains("traversal.skip_globs"),
                "unexpected invalid policy scope for pattern {pattern:?}: {message}"
            );
            assert!(
                message.contains(expected_message_fragment),
                "expected error message to contain {expected_message_fragment:?}, got {message:?}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(any(feature = "glob", feature = "grep"))]
fn traversal_skip_globs_reject_absolute_pattern() {
    assert_skip_glob_pattern_rejected("/node_modules/**", "must not start with '/'");
}

#[test]
#[cfg(windows)]
#[cfg(any(feature = "glob", feature = "grep"))]
fn traversal_skip_globs_reject_windows_drive_absolute_pattern() {
    assert_skip_glob_pattern_rejected(r"C:\node_modules\**", "drive letter prefixes");
}

#[test]
#[cfg(windows)]
#[cfg(any(feature = "glob", feature = "grep"))]
fn traversal_skip_globs_reject_windows_unc_absolute_pattern() {
    assert_skip_glob_pattern_rejected(r"\\server\share\**", "must not start with '/'");
}

#[test]
#[cfg(any(feature = "glob", feature = "grep"))]
fn traversal_skip_globs_reject_parent_prefix_pattern() {
    assert_skip_glob_pattern_rejected("../**/*.txt", "must not contain '..' segments");
}

#[test]
#[cfg(any(feature = "glob", feature = "grep"))]
fn traversal_skip_globs_reject_parent_segment_pattern() {
    assert_skip_glob_pattern_rejected("src/../*.txt", "must not contain '..' segments");
}

#[test]
#[cfg(any(feature = "glob", feature = "grep"))]
fn traversal_skip_globs_reject_empty_or_whitespace_pattern() {
    for pattern in ["", "   "] {
        assert_skip_glob_pattern_rejected(pattern, "glob pattern must not be empty");
    }
}

#[test]
#[cfg(feature = "grep")]
fn traversal_skip_globs_skip_in_traversal_but_allow_direct_read() {
    assert_skip_glob_applies_to_grep_but_not_direct_read("node_modules/**");
}

#[test]
#[cfg(feature = "glob")]
fn traversal_skip_globs_apply_to_glob_paths_with_and_without_leading_dot_slash() {
    for skip_pattern in ["./node_modules/**", "node_modules/**"] {
        assert_skip_glob_applies_to_glob_paths(skip_pattern);
    }
}
