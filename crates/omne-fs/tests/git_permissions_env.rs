#![cfg(all(feature = "git-permissions", unix))]

mod common;

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use common::test_policy;
use omne_fs::ops::{Context, EditRequest, edit_range};
use policy_meta::WriteScope;

fn run_git_with_program(program: &Path, root: &Path, args: &[&str]) {
    let output = std::process::Command::new(program)
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

fn resolve_git_from_path() -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH should exist while locating git");
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("git");
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("git not found in ambient PATH");
}

fn init_repo_with_file(program: &Path, content: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    run_git_with_program(program, dir.path(), &["init"]);
    run_git_with_program(
        program,
        dir.path(),
        &["config", "user.email", "omne-fs@test.local"],
    );
    run_git_with_program(program, dir.path(), &["config", "user.name", "omne-fs"]);
    fs::write(dir.path().join("file.txt"), content).expect("write");
    run_git_with_program(program, dir.path(), &["add", "file.txt"]);
    run_git_with_program(program, dir.path(), &["commit", "-m", "init"]);
    dir
}

struct ScopedEnvVar {
    name: &'static str,
    previous: Option<OsString>,
}

impl ScopedEnvVar {
    fn set(name: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
        let previous = std::env::var_os(name);
        unsafe {
            std::env::set_var(name, value);
        }
        Self { name, previous }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => unsafe {
                std::env::set_var(self.name, value);
            },
            None => unsafe {
                std::env::remove_var(self.name);
            },
        }
    }
}

fn write_fake_git(dir: &Path, marker: &Path) -> PathBuf {
    let fake_git = dir.join("git");
    let script = format!("#!/bin/sh\nprintf fake > '{}'\nexit 97\n", marker.display());
    fs::write(&fake_git, script).expect("write fake git");
    let mut permissions = fs::metadata(&fake_git)
        .expect("fake git metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_git, permissions).expect("chmod fake git");
    fake_git
}

#[test]
fn git_permission_fallback_ignores_poisoned_path_and_git_env() {
    let git = resolve_git_from_path();
    let dir = init_repo_with_file(&git, "hello\n");
    let fake_dir = tempfile::tempdir().expect("tempdir");
    let marker = fake_dir.path().join("fake-git-ran");
    let _fake_git = write_fake_git(fake_dir.path(), &marker);

    let _path = ScopedEnvVar::set("PATH", fake_dir.path());
    let _git_dir = ScopedEnvVar::set("GIT_DIR", "/definitely/not/the/repo");
    let _git_work_tree = ScopedEnvVar::set("GIT_WORK_TREE", "/definitely/not/the/worktree");

    let mut policy = test_policy(dir.path(), WriteScope::WorkspaceWrite);
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
    .expect("edit should use trusted git instead of poisoned env");

    assert_eq!(response.path, PathBuf::from("file.txt"));
    assert!(
        fs::read_to_string(dir.path().join("file.txt"))
            .expect("read")
            .starts_with("HELLO"),
        "expected edit to modify tracked clean file"
    );
    assert!(
        !marker.exists(),
        "fallback must not invoke git discovered from ambient PATH"
    );
}
