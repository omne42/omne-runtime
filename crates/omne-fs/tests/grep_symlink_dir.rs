#![cfg(all(feature = "grep", unix))]

mod common;

use std::os::unix::fs::symlink;
use std::path::PathBuf;

use common::test_policy;
use omne_fs::ops::{Context, GrepRequest, grep};
use policy_meta::WriteScope;

#[test]
fn grep_with_glob_skips_symlink_directories_instead_of_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("real")).expect("mkdir");
    std::fs::write(dir.path().join("keep.txt"), "needle\n").expect("write");
    symlink(dir.path().join("real"), dir.path().join("linkdir")).expect("symlink dir");

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let resp = grep(
        &ctx,
        GrepRequest {
            root_id: "root".to_string(),
            query: "needle".to_string(),
            regex: false,
            glob: Some("**/*".to_string()),
        },
    )
    .expect("grep");

    assert_eq!(resp.matches.len(), 1);
    assert_eq!(resp.matches[0].path, PathBuf::from("keep.txt"));
    assert!(resp.skipped_io_errors >= 1);
}
