#![cfg(feature = "grep")]

mod common;

use common::test_policy;
use omne_fs::ops::{Context, GrepRequest, grep};
use policy_meta::WriteScope;

#[test]
fn grep_skips_non_utf8_when_invalid_bytes_appear_after_capped_prefix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut first_line = vec![b'a'; (8 * 1024) + 16];
    first_line.extend_from_slice(&[0xf0, 0x28, 0x8c, 0x28]);
    first_line.push(b'\n');
    first_line.extend_from_slice(b"needle\n");
    std::fs::write(dir.path().join("bin_after_cap.txt"), &first_line).expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_line_bytes = 16;
    policy.limits.max_read_bytes = 128 * 1024;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("bin_after_cap.txt".to_string()),
        },
    )
    .expect("grep");

    assert!(resp.matches.is_empty());
    assert_eq!(resp.skipped_non_utf8_files, 1);
}

#[test]
fn grep_skips_non_utf8_when_query_matches_before_invalid_bytes_after_cap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut line = b"needle".to_vec();
    line.resize((8 * 1024) + 16, b'a');
    line.extend_from_slice(&[0xf0, 0x28, 0x8c, 0x28]);
    line.push(b'\n');
    std::fs::write(dir.path().join("bin_after_cap_hit.txt"), &line).expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.limits.max_line_bytes = 16;
    policy.limits.max_read_bytes = 128 * 1024;
    let ctx = Context::new(policy).expect("ctx");

    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("bin_after_cap_hit.txt".to_string()),
        },
    )
    .expect("grep");

    assert!(resp.matches.is_empty());
    assert_eq!(resp.skipped_non_utf8_files, 1);
}
