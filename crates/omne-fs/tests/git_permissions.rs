#![cfg(feature = "git-permissions")]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::test_policy;
use omne_fs::ops::{Context, DeleteRequest, EditRequest, delete, edit_range};
use omne_fs::policy::RootMode;

fn run_git(root: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        output.status.success(),
        "git {:?} failed: status={:?}, stdout={}, stderr={}",
        args,
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_repo_with_file(content: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    run_git(dir.path(), &["init"]);
    run_git(dir.path(), &["config", "user.email", "omne-fs@test.local"]);
    run_git(dir.path(), &["config", "user.name", "omne-fs"]);
    std::fs::write(dir.path().join("file.txt"), content).expect("write");
    run_git(dir.path(), &["add", "file.txt"]);
    run_git(dir.path(), &["commit", "-m", "init"]);
    dir
}

#[test]
fn edit_can_fall_back_to_git_tracked_clean_file_when_disabled_by_policy() {
    let dir = init_repo_with_file("hello\n");
    let mut policy = test_policy(dir.path(), RootMode::WorkspaceWrite);
    policy.permissions.edit = false;
    let ctx = Context::new(policy).expect("ctx");

    let response = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: 1,
            end_line: 1,
            replacement: "HELLO".to_string(),
        },
    )
    .expect("edit");

    assert_eq!(response.path, PathBuf::from("file.txt"));
    assert!(
        std::fs::read_to_string(dir.path().join("file.txt"))
            .expect("read")
            .starts_with("HELLO"),
        "expected edit to modify tracked clean file"
    );
}

#[test]
fn edit_fallback_rejects_dirty_file() {
    let dir = init_repo_with_file("hello\n");
    std::fs::write(dir.path().join("file.txt"), "dirty\n").expect("write dirty");

    let mut policy = test_policy(dir.path(), RootMode::WorkspaceWrite);
    policy.permissions.edit = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = edit_range(
        &ctx,
        EditRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            start_line: 1,
            end_line: 1,
            replacement: "HELLO".to_string(),
        },
    )
    .expect_err("should reject dirty file");

    match err {
        omne_fs::Error::NotPermitted(message) => {
            assert!(
                message.contains("uncommitted changes"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn delete_can_fall_back_to_git_tracked_clean_file_when_disabled_by_policy() {
    let dir = init_repo_with_file("hello\n");
    let mut policy = test_policy(dir.path(), RootMode::WorkspaceWrite);
    policy.permissions.delete = false;
    let ctx = Context::new(policy).expect("ctx");

    let response = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect("delete");

    assert!(response.deleted);
    assert!(!dir.path().join("file.txt").exists());
}

#[test]
fn delete_fallback_rejects_recursive_requests() {
    let dir = init_repo_with_file("hello\n");
    let mut policy = test_policy(dir.path(), RootMode::WorkspaceWrite);
    policy.permissions.delete = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            recursive: true,
            ignore_missing: false,
        },
    )
    .expect_err("should reject recursive delete fallback");

    match err {
        omne_fs::Error::NotPermitted(message) => {
            assert!(
                message.contains("recursive=false"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}
