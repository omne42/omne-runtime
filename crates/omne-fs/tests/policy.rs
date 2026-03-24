mod common;

use std::path::PathBuf;

use common::test_policy;
use omne_fs::ops::Context;
use omne_fs::policy::{
    Limits, PathRules, Permissions, Root, RootMode, SandboxPolicy, SecretRules, TraversalRules,
};

type LimitCase = (&'static str, fn(&mut Limits), &'static str);

fn assert_invalid_policy_contains_all(err: omne_fs::Error, expected_parts: &[&str]) {
    match err {
        omne_fs::Error::InvalidPolicy(msg) => {
            for expected in expected_parts {
                assert!(
                    msg.contains(expected),
                    "expected invalid policy message containing {expected:?}, got: {msg}"
                );
            }
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

fn read_only_root(id: impl Into<String>, path: impl Into<PathBuf>) -> Root {
    Root {
        id: id.into(),
        path: path.into(),
        mode: RootMode::ReadOnly,
    }
}

fn policy_with_roots(roots: Vec<Root>) -> SandboxPolicy {
    SandboxPolicy {
        roots,
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
        metadata: Default::default(),
    }
}

fn policy_with_single_root(id: impl Into<String>, path: impl Into<PathBuf>) -> SandboxPolicy {
    policy_with_roots(vec![read_only_root(id, path)])
}

#[test]
fn policy_accepts_valid_configuration() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = test_policy(dir.path(), RootMode::ReadOnly);
    let ctx = Context::new(policy).expect("valid policy should be accepted");
    assert_eq!(ctx.policy().roots.len(), 1);
}

#[test]
fn policy_rejects_duplicate_root_ids() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root_path = dir.path().to_path_buf();
    let policy = policy_with_roots(vec![
        read_only_root("dup", root_path.clone()),
        read_only_root("dup", root_path),
    ]);

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["duplicate root.id", "dup"]);
}

#[test]
fn policy_rejects_root_id_with_trailing_whitespace() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = policy_with_single_root("root ", dir.path());

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(
        err,
        &[
            "root.id must not contain leading/trailing whitespace",
            "root ",
        ],
    );
}

#[test]
fn policy_rejects_root_id_with_leading_whitespace() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = policy_with_single_root(" root", dir.path());

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(
        err,
        &[
            "root.id must not contain leading/trailing whitespace",
            " root",
        ],
    );
}

#[test]
fn policy_rejects_root_id_with_non_space_whitespace() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cases = [
        ("leading tab", "\troot"),
        ("trailing newline", "root\n"),
        ("leading unicode em-space", "\u{2003}root"),
    ];

    for (case_name, root_id) in cases {
        let policy = policy_with_single_root(root_id, dir.path());
        match policy.validate().expect_err("should reject") {
            omne_fs::Error::InvalidPolicy(msg) => {
                assert!(
                    msg.contains("root.id must not contain leading/trailing whitespace"),
                    "case: {case_name}, msg: {msg}"
                );
                assert!(msg.contains("root.id"), "case: {case_name}, msg: {msg}");
            }
            other => panic!("case: {case_name}, unexpected error: {other:?}"),
        }
    }
}

#[test]
fn policy_rejects_root_id_too_long() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = policy_with_single_root("a".repeat(65), dir.path());

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["root.id is too long", "max=64"]);
}

#[test]
fn policy_rejects_root_id_with_invalid_characters() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cases = [
        ("contains space", "root id"),
        ("contains slash", "root/id"),
        ("contains colon", "root:1"),
    ];

    for (case_name, root_id) in cases {
        let policy = policy_with_single_root(root_id, dir.path());
        match policy.validate().expect_err("should reject") {
            omne_fs::Error::InvalidPolicy(msg) => {
                assert!(
                    msg.contains("root.id contains invalid characters"),
                    "case: {case_name}, msg: {msg}"
                );
                assert!(msg.contains(root_id), "case: {case_name}, msg: {msg}");
            }
            other => panic!("case: {case_name}, unexpected error: {other:?}"),
        }
    }
}

#[test]
fn policy_rejects_relative_root_paths() {
    let policy = policy_with_single_root("root", PathBuf::from("relative-root"));

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["root.path must be absolute", "root.id=root"]);
}

#[test]
fn policy_rejects_invalid_redact_regexes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.secrets.redact_regexes = vec!["[".to_string()];

    let err = Context::new(policy).expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["secrets.redact_regexes", "regex"]);
}

#[test]
fn policy_rejects_zero_max_patch_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_patch_bytes = Some(0);

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["limits.max_patch_bytes", "> 0"]);
}

#[test]
fn policy_rejects_zero_max_glob_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_glob_bytes = Some(0);

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["limits.max_glob_bytes", "> 0"]);
}

#[test]
fn policy_rejects_excessive_max_glob_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_glob_bytes = Some(64 * 1024 * 1024 + 1);

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["limits.max_glob_bytes", "<="]);
}

#[test]
fn policy_rejects_max_walk_files_greater_than_entries() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_walk_entries = 10;
    policy.limits.max_walk_files = 11;

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["limits.max_walk_files", "limits.max_walk_entries"]);
}

#[test]
fn policy_rejects_excessive_grep_response_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_results = 100_000;
    policy.limits.max_line_bytes = 8 * 1024;

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["limits.max_results", "limits.max_line_bytes"]);
}

#[test]
fn policy_rejects_excessive_default_glob_response_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_glob_bytes = None;
    policy.limits.max_results = 100_000;
    policy.limits.max_line_bytes = 8 * 1024;

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(
        err,
        &[
            "limits.max_glob_bytes",
            "limits.max_results",
            "limits.max_line_bytes",
        ],
    );
}

#[test]
fn policy_rejects_excessive_list_dir_response_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
    policy.limits.max_glob_bytes = Some(64 * 1024 * 1024);
    policy.limits.max_results = 100_000;
    policy.limits.max_line_bytes = 8 * 1024;

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["list_dir response budget", "must be <="]);
}

#[test]
fn policy_rejects_empty_roots() {
    let policy = SandboxPolicy {
        roots: Vec::new(),
        permissions: Permissions::default(),
        limits: Limits::default(),
        secrets: SecretRules::default(),
        traversal: TraversalRules::default(),
        paths: PathRules::default(),
        metadata: Default::default(),
    };

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["roots", "empty"]);
}

#[test]
fn policy_rejects_empty_root_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let policy = policy_with_single_root(String::new(), dir.path());

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["root.id", "empty"]);
}

#[test]
fn policy_rejects_empty_root_path() {
    let policy = policy_with_single_root("root", PathBuf::new());

    let err = policy.validate().expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["root.path is empty", "root.id=root"]);
}

#[test]
fn policy_rejects_zero_required_limits() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cases: [LimitCase; 6] = [
        (
            "max_read_bytes",
            |limits| limits.max_read_bytes = 0,
            "limits.max_read_bytes",
        ),
        (
            "max_write_bytes",
            |limits| limits.max_write_bytes = 0,
            "limits.max_write_bytes",
        ),
        (
            "max_results",
            |limits| limits.max_results = 0,
            "limits.max_results",
        ),
        (
            "max_walk_files",
            |limits| limits.max_walk_files = 0,
            "limits.max_walk_files",
        ),
        (
            "max_walk_entries",
            |limits| limits.max_walk_entries = 0,
            "limits.max_walk_entries",
        ),
        (
            "max_line_bytes",
            |limits| limits.max_line_bytes = 0,
            "limits.max_line_bytes",
        ),
    ];

    for (case_name, mutate, expected) in cases {
        let mut policy = test_policy(dir.path(), RootMode::ReadOnly);
        mutate(&mut policy.limits);

        match policy.validate().expect_err("should reject") {
            omne_fs::Error::InvalidPolicy(msg) => {
                assert!(msg.contains(expected), "case: {case_name}, msg: {msg}");
                assert!(msg.contains("> 0"), "case: {case_name}, msg: {msg}");
            }
            other => panic!("case {case_name}: unexpected error: {other:?}"),
        }
    }
}

#[test]
fn context_rejects_file_roots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root_file = dir.path().join("root.txt");
    std::fs::write(&root_file, "not a directory").expect("write");

    let policy = policy_with_single_root("root", root_file);

    let err = Context::new(policy).expect_err("should reject");
    assert_invalid_policy_contains_all(err, &["root", "is not a directory"]);
}

#[test]
fn context_rejects_overlapping_roots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let child = dir.path().join("child");
    std::fs::create_dir_all(&child).expect("mkdir");

    let policy = policy_with_roots(vec![
        read_only_root("root_a", dir.path().to_path_buf()),
        read_only_root("root_b", child),
    ]);

    let err = Context::new(policy).expect_err("should reject overlapping roots");
    assert_invalid_policy_contains_all(err, &["overlaps with root", "root_a", "root_b"]);
}

#[test]
fn validate_only_checks_policy_shape_not_filesystem_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing_root = dir.path().join("missing-root");

    let policy = policy_with_single_root("root", missing_root);

    policy
        .validate()
        .expect("validate should stay structural and avoid filesystem IO");
    let err = Context::new(policy).expect_err("context should reject missing roots");
    assert_invalid_policy_contains_all(err, &["failed to canonicalize root", "root"]);
}

#[test]
fn policy_deserialization_rejects_unknown_fields() {
    let cases = [
        (
            "unknown root field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only", "unknown_root": true}],
  "permissions": { "read": true }
}"#,
            "unknown_root",
        ),
        (
            "unknown top-level field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "unknown_top": true
}"#,
            "unknown_top",
        ),
        (
            "unknown permissions field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "permissions": { "read": true, "unknown_permissions": true }
}"#,
            "unknown_permissions",
        ),
        (
            "unknown limits field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "limits": { "unknown_limits": 1 }
}"#,
            "unknown_limits",
        ),
        (
            "unknown secrets field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "secrets": { "unknown_secrets": true }
}"#,
            "unknown_secrets",
        ),
        (
            "unknown traversal field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "traversal": { "unknown_traversal": true }
}"#,
            "unknown_traversal",
        ),
        (
            "unknown paths field",
            r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "paths": { "unknown_paths": true }
}"#,
            "unknown_paths",
        ),
    ];

    for (case_name, raw, unknown_field) in cases {
        let err = serde_json::from_str::<SandboxPolicy>(raw).expect_err("should reject");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field"),
            "case: {case_name}, msg: {msg}"
        );
        assert!(msg.contains(unknown_field), "case: {case_name}, msg: {msg}");
    }
}

#[test]
fn policy_deserialization_sets_traversal_stable_sort_default_true() {
    let raw = r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}]
}"#;

    let policy: SandboxPolicy = serde_json::from_str(raw).expect("should parse");
    assert!(
        policy.traversal.stable_sort,
        "traversal.stable_sort should default to true"
    );
}

#[test]
fn policy_deserialization_allows_disabling_traversal_stable_sort() {
    let raw = r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "traversal": { "stable_sort": false }
}"#;

    let policy: SandboxPolicy = serde_json::from_str(raw).expect("should parse");
    assert!(!policy.traversal.stable_sort);
}

#[test]
fn policy_deserialization_sets_preserve_unix_xattrs_default_true() {
    let raw = r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}]
}"#;

    let policy: SandboxPolicy = serde_json::from_str(raw).expect("should parse");
    assert!(
        policy.limits.preserve_unix_xattrs,
        "limits.preserve_unix_xattrs should default to true"
    );
}

#[test]
fn policy_deserialization_allows_disabling_preserve_unix_xattrs() {
    let raw = r#"{
  "roots": [{"id": "root", "path": "/", "mode": "read_only"}],
  "limits": { "preserve_unix_xattrs": false }
}"#;

    let policy: SandboxPolicy = serde_json::from_str(raw).expect("should parse");
    assert!(!policy.limits.preserve_unix_xattrs);
}

#[cfg(feature = "policy-io")]
#[test]
fn policy_deserialization_rejects_unknown_fields_in_toml() {
    let cases = [
        (
            "unknown root field",
            r#"
[[roots]]
id = "root"
path = "/"
write_scope = "read_only"
unknown_root = true
"#,
            "unknown_root",
        ),
        (
            "unknown top-level field",
            r#"
[[roots]]
id = "root"
path = "/"
write_scope = "read_only"

unknown_top = true
"#,
            "unknown_top",
        ),
        (
            "unknown permissions field",
            r#"
[[roots]]
id = "root"
path = "/"
write_scope = "read_only"

[permissions]
read = true
unknown_permissions = true
"#,
            "unknown_permissions",
        ),
        (
            "unknown limits field",
            r#"
[[roots]]
id = "root"
path = "/"
write_scope = "read_only"

[limits]
unknown_limits = 1
"#,
            "unknown_limits",
        ),
        (
            "unknown secrets field",
            r#"
[[roots]]
id = "root"
path = "/"
write_scope = "read_only"

[secrets]
unknown_secrets = true
"#,
            "unknown_secrets",
        ),
        (
            "unknown traversal field",
            r#"
[[roots]]
id = "root"
path = "/"
write_scope = "read_only"

[traversal]
unknown_traversal = true
"#,
            "unknown_traversal",
        ),
        (
            "unknown paths field",
            r#"
[[roots]]
id = "root"
path = "/"
write_scope = "read_only"

[paths]
unknown_paths = true
"#,
            "unknown_paths",
        ),
    ];

    for (case_name, raw, unknown_field) in cases {
        let err = toml::from_str::<SandboxPolicy>(raw).expect_err("should reject");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field"),
            "case: {case_name}, msg: {msg}"
        );
        assert!(msg.contains(unknown_field), "case: {case_name}, msg: {msg}");
    }
}
