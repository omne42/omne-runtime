mod common;

use std::path::{Path, PathBuf};

use common::{all_permissions_test_policy, test_policy};
use omne_fs::ops::DeleteKind;
use omne_fs::ops::{Context, DeleteRequest, delete};
use policy_meta::WriteScope;

#[cfg(unix)]
struct UnixThreadGuard {
    keep_running: std::sync::Arc<std::sync::atomic::AtomicBool>,
    wake_tx: std::sync::mpsc::Sender<()>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl UnixThreadGuard {
    fn new(
        keep_running: std::sync::Arc<std::sync::atomic::AtomicBool>,
        wake_tx: std::sync::mpsc::Sender<()>,
        handle: std::thread::JoinHandle<()>,
    ) -> Self {
        Self {
            keep_running,
            wake_tx,
            handle: Some(handle),
        }
    }
}

#[cfg(unix)]
impl Drop for UnixThreadGuard {
    fn drop(&mut self) {
        self.keep_running
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let _ = self.wake_tx.send(());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn delete_absolute_paths_report_relative_requested_path_when_parent_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut policy = all_permissions_test_policy(dir.path(), WriteScope::WorkspaceWrite);
    policy.paths.allow_absolute = true;
    let ctx = Context::new(policy).expect("ctx");

    let abs = dir.path().join("missing").join("file.txt");
    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: abs,
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        omne_fs::Error::IoPath { op, path, .. } => {
            assert!(
                op == "metadata" || op == "symlink_metadata",
                "unexpected op: {op}"
            );
            assert_eq!(path, PathBuf::from("missing"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn delete_absolute_paths_report_relative_requested_path_when_leaf_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("parent")).expect("mkdir");
    let mut policy = all_permissions_test_policy(dir.path(), WriteScope::WorkspaceWrite);
    policy.paths.allow_absolute = true;
    let ctx = Context::new(policy).expect("ctx");

    let abs = dir.path().join("parent").join("missing.txt");
    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: abs,
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        omne_fs::Error::IoPath { op, path, .. } => {
            assert!(
                op == "metadata" || op == "symlink_metadata",
                "unexpected op: {op}"
            );
            assert_eq!(path, PathBuf::from("parent").join("missing.txt"));
        }
        omne_fs::Error::InvalidPath(message) => {
            assert!(
                message.contains("cannot verify parent identity during delete")
                    && message.contains("parent")
                    && message.contains("missing.txt"),
                "unexpected invalid-path failure: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
#[cfg(unix)]
fn delete_unlinks_symlink_without_deleting_target() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("target.txt");
    let link = dir.path().join("link.txt");
    std::fs::write(&target, "hello\n").expect("write");
    symlink(&target, &link).expect("symlink");

    let ctx = Context::new(all_permissions_test_policy(
        dir.path(),
        WriteScope::WorkspaceWrite,
    ))
    .expect("ctx");
    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("link.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect("delete");
    assert_eq!(resp.path, PathBuf::from("link.txt"));
    assert_eq!(resp.requested_path, PathBuf::from("link.txt"));
    assert!(resp.deleted);
    assert_eq!(resp.kind, DeleteKind::Symlink);

    assert!(!link.exists());
    assert!(target.exists());
}

#[test]
#[cfg(unix)]
fn delete_unlinks_symlink_even_if_target_is_outside_root() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let outside = tempfile::NamedTempFile::new().expect("tmp");
    std::fs::write(outside.path(), "hello\n").expect("write");
    let link = dir.path().join("outside-link.txt");
    symlink(outside.path(), &link).expect("symlink");

    let ctx = Context::new(all_permissions_test_policy(
        dir.path(),
        WriteScope::WorkspaceWrite,
    ))
    .expect("ctx");
    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("outside-link.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect("delete");
    assert_eq!(resp.path, PathBuf::from("outside-link.txt"));
    assert_eq!(resp.requested_path, PathBuf::from("outside-link.txt"));
    assert!(resp.deleted);
    assert_eq!(resp.kind, DeleteKind::Symlink);

    assert!(!link.exists());
    assert!(outside.path().exists());
}

#[test]
#[cfg(unix)]
fn delete_denies_requested_path_before_resolving_symlink_dirs() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("allowed")).expect("mkdir");
    std::fs::write(dir.path().join("allowed").join("file.txt"), "hello\n").expect("write");
    symlink(dir.path().join("allowed"), dir.path().join("deny")).expect("symlink dir");

    let mut policy = all_permissions_test_policy(dir.path(), WriteScope::WorkspaceWrite);
    policy.secrets.deny_globs = vec!["deny/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("deny/file.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        omne_fs::Error::SecretPathDenied(path) => {
            assert_eq!(path, PathBuf::from("deny/file.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        dir.path().join("allowed").join("file.txt").exists(),
        "expected file to remain after denied delete"
    );
}

#[test]
#[cfg(unix)]
fn delete_denies_after_canonicalization_when_symlink_parent_points_to_denied_path() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().expect("tempdir");
    let denied_dir = dir.path().join("denied_dir");
    std::fs::create_dir_all(&denied_dir).expect("mkdir denied dir");
    std::fs::write(denied_dir.join("file.txt"), "secret\n").expect("write");
    symlink(&denied_dir, dir.path().join("allowed_link")).expect("symlink dir");

    let mut policy = all_permissions_test_policy(dir.path(), WriteScope::WorkspaceWrite);
    policy.secrets.deny_globs = vec!["denied_dir/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("allowed_link/file.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        omne_fs::Error::SecretPathDenied(path) => {
            assert!(
                path.as_path() == Path::new("denied_dir/file.txt")
                    || path.as_path() == Path::new("denied_dir")
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        denied_dir.join("file.txt").exists(),
        "expected denied canonical target to remain after rejected delete"
    );
}

#[test]
fn delete_recursive_rejects_when_tree_contains_denied_descendant() {
    let dir = tempfile::tempdir().expect("tempdir");
    let denied_dir = dir.path().join("project").join(".git");
    std::fs::create_dir_all(&denied_dir).expect("mkdir denied dir");
    std::fs::write(denied_dir.join("config"), "[core]\n").expect("write denied");
    std::fs::write(dir.path().join("project").join("public.txt"), "ok\n").expect("write public");

    let mut policy = all_permissions_test_policy(dir.path(), WriteScope::WorkspaceWrite);
    policy.secrets.deny_globs = vec!["project/.git/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("project"),
            recursive: true,
            ignore_missing: false,
        },
    )
    .expect_err("recursive delete should reject denied descendants");

    match err {
        omne_fs::Error::SecretPathDenied(path) => {
            assert!(
                path.starts_with(Path::new("project").join(".git")),
                "unexpected denied path: {}",
                path.display()
            );
        }
        omne_fs::Error::InvalidPath(message) => {
            assert!(
                message.contains("cannot verify parent identity during delete")
                    && message.contains("project"),
                "unexpected invalid-path failure: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        dir.path().join("project").exists(),
        "recursive deny must keep parent directory"
    );
    assert!(
        dir.path()
            .join("project")
            .join(".git")
            .join("config")
            .exists(),
        "recursive deny must keep denied descendant"
    );
    assert!(
        dir.path().join("project").join("public.txt").exists(),
        "recursive deny should abort before deleting allowed siblings"
    );
}

#[test]
fn delete_is_not_allowed_on_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("file.txt");
    std::fs::write(&file, "keep\n").expect("write");
    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.permissions.delete = true;
    let ctx = Context::new(policy).expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("file.txt"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        omne_fs::Error::NotPermitted(message) => {
            assert!(message.contains("read_only"));
            assert!(message.contains("root"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        file.exists(),
        "readonly-root delete rejection must not remove files"
    );
}

#[test]
fn delete_rejects_dot_and_empty_paths() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sentinel = dir.path().join("sentinel.txt");
    std::fs::write(&sentinel, "keep\n").expect("write sentinel");
    let ctx = Context::new(all_permissions_test_policy(
        dir.path(),
        WriteScope::WorkspaceWrite,
    ))
    .expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("."),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        omne_fs::Error::InvalidPath(message) => {
            assert!(message.contains("refusing to delete the root directory"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from(""),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        omne_fs::Error::InvalidPath(message) => {
            assert!(message.contains("path is empty"));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        sentinel.exists(),
        "rejecting dot/empty path must not delete files"
    );
    assert_eq!(
        std::fs::read_to_string(&sentinel).expect("read sentinel"),
        "keep\n",
        "rejecting dot/empty path must not mutate unrelated files"
    );
}

#[test]
fn delete_rejects_directories_without_recursive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let subdir = dir.path().join("subdir");
    std::fs::create_dir_all(&subdir).expect("mkdir");

    let ctx = Context::new(all_permissions_test_policy(
        dir.path(),
        WriteScope::WorkspaceWrite,
    ))
    .expect("ctx");

    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("subdir"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("should reject");

    match err {
        omne_fs::Error::InvalidPath(message) => {
            assert!(
                message.contains("recursive=true")
                    || message.contains("cannot verify parent identity during delete"),
                "unexpected invalid-path failure: {message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    assert!(
        subdir.exists(),
        "rejecting non-recursive delete must keep directory"
    );
}

#[test]
#[cfg(unix)]
fn delete_revalidate_parent_detects_path_change() {
    use std::os::unix::fs::symlink;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().expect("tempdir");
    let dir_a = dir.path().join("dir_a");
    let dir_b = dir.path().join("dir_b");
    std::fs::create_dir_all(dir_a.join("subdir")).expect("mkdir dir_a/subdir");
    std::fs::create_dir_all(dir_b.join("subdir")).expect("mkdir dir_b/subdir");

    let pivot = dir.path().join("pivot");
    symlink(&dir_a, &pivot).expect("symlink pivot");

    let ctx = Context::new(all_permissions_test_policy(
        dir.path(),
        WriteScope::WorkspaceWrite,
    ))
    .expect("ctx");

    let keep_flapping = Arc::new(AtomicBool::new(true));
    let keep_flapping_bg = Arc::clone(&keep_flapping);
    let (burst_tx, burst_rx) = mpsc::channel::<()>();
    let (burst_started_tx, burst_started_rx) = mpsc::channel::<()>();
    let (burst_done_tx, burst_done_rx) = mpsc::channel::<()>();
    let pivot_bg = pivot;
    let dir_a_bg = dir_a;
    let dir_b_bg = dir_b;
    let toggler = std::thread::spawn(move || {
        while keep_flapping_bg.load(Ordering::Relaxed) {
            if burst_rx.recv().is_err() {
                break;
            }
            if !keep_flapping_bg.load(Ordering::Relaxed) {
                break;
            }

            let _ = burst_started_tx.send(());
            for _ in 0..2_048 {
                let _ = std::fs::remove_file(&pivot_bg);
                let _ = symlink(&dir_b_bg, &pivot_bg);
                std::thread::yield_now();
                let _ = std::fs::remove_file(&pivot_bg);
                let _ = symlink(&dir_a_bg, &pivot_bg);
                std::thread::yield_now();
            }
            let _ = burst_done_tx.send(());
        }
    });
    let _toggler_guard = UnixThreadGuard::new(keep_flapping, burst_tx.clone(), toggler);

    let mut observed_changed = false;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        burst_tx.send(()).expect("start toggle burst");
        burst_started_rx.recv().expect("wait toggler start");
        let err = delete(
            &ctx,
            DeleteRequest {
                root_id: "root".to_string(),
                path: PathBuf::from("pivot/subdir"),
                recursive: false,
                ignore_missing: false,
            },
        )
        .expect_err("should reject");
        burst_done_rx.recv().expect("wait toggler done");

        match err {
            omne_fs::Error::InvalidPath(message) if message.contains("changed during delete") => {
                observed_changed = true;
                break;
            }
            omne_fs::Error::InvalidPath(message) if message.contains("recursive=true") => {}
            omne_fs::Error::IoPath { source, .. }
                if source.kind() == std::io::ErrorKind::NotFound => {}
            omne_fs::Error::IoPath { op, source, .. }
                if op == "canonicalize" && source.kind() == std::io::ErrorKind::InvalidInput => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    if !observed_changed {
        eprintln!(
            "delete_revalidate_parent_detects_path_change: no explicit revalidation failure observed within timeout"
        );
    }
}

#[test]
#[cfg(unix)]
fn delete_ignore_missing_returns_missing_when_symlink_parent_is_temporarily_absent() {
    use std::os::unix::fs::symlink;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};

    let dir = tempfile::tempdir().expect("tempdir");
    let actual_parent = dir.path().join("actual_parent");
    std::fs::create_dir_all(actual_parent.join("subdir")).expect("mkdir actual_parent/subdir");

    let pivot = dir.path().join("pivot");
    symlink(&actual_parent, &pivot).expect("symlink pivot");

    let ctx = Context::new(all_permissions_test_policy(
        dir.path(),
        WriteScope::WorkspaceWrite,
    ))
    .expect("ctx");

    let keep_flapping = Arc::new(AtomicBool::new(true));
    let keep_flapping_bg = Arc::clone(&keep_flapping);
    let (window_tx, window_rx) = mpsc::channel::<()>();
    let (pivot_missing_tx, pivot_missing_rx) = mpsc::channel::<()>();
    let (window_done_tx, window_done_rx) = mpsc::channel::<()>();
    let pivot_bg = pivot;
    let actual_parent_bg = actual_parent.clone();
    let toggler = std::thread::spawn(move || {
        while keep_flapping_bg.load(Ordering::Relaxed) {
            if window_rx.recv().is_err() {
                break;
            }
            if !keep_flapping_bg.load(Ordering::Relaxed) {
                break;
            }
            let _ = std::fs::remove_file(&pivot_bg);
            let _ = pivot_missing_tx.send(());
            for _ in 0..8_192 {
                if !keep_flapping_bg.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::yield_now();
            }
            let _ = symlink(&actual_parent_bg, &pivot_bg);
            let _ = window_done_tx.send(());
        }
    });
    let _toggler_guard = UnixThreadGuard::new(keep_flapping, window_tx.clone(), toggler);

    let mut observed_missing = None;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        window_tx.send(()).expect("start missing window");
        pivot_missing_rx.recv().expect("wait for missing parent");
        match delete(
            &ctx,
            DeleteRequest {
                root_id: "root".to_string(),
                path: PathBuf::from("pivot/subdir"),
                recursive: false,
                ignore_missing: true,
            },
        ) {
            Ok(resp) if resp.kind == DeleteKind::Missing => {
                observed_missing = Some(resp);
                break;
            }
            Err(omne_fs::Error::InvalidPath(message)) if message.contains("recursive=true") => {}
            Err(omne_fs::Error::IoPath { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound => {}
            other => panic!("unexpected result: {other:?}"),
        }
        window_done_rx.recv().expect("wait window done");
    }
    if observed_missing.is_some() {
        window_done_rx.recv().expect("wait final window done");
    }

    let resp = observed_missing.expect("expected ignore_missing response when parent disappears");
    assert_eq!(resp.path, PathBuf::from("pivot/subdir"));
    assert_eq!(resp.requested_path, PathBuf::from("pivot/subdir"));
    assert!(!resp.deleted);
    assert_eq!(resp.kind, DeleteKind::Missing);
    assert!(
        actual_parent.join("subdir").is_dir(),
        "missing response must not remove existing directories"
    );
}

#[test]
fn delete_ignore_missing_returns_missing_when_parent_directory_is_absent() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ctx = Context::new(all_permissions_test_policy(
        dir.path(),
        WriteScope::WorkspaceWrite,
    ))
    .expect("ctx");

    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("missing").join("file.txt"),
            recursive: false,
            ignore_missing: true,
        },
    )
    .expect("delete");

    assert_eq!(resp.path, PathBuf::from("missing").join("file.txt"));
    assert_eq!(
        resp.requested_path,
        PathBuf::from("missing").join("file.txt")
    );
    assert!(!resp.deleted);
    assert_eq!(resp.kind, DeleteKind::Missing);
}
