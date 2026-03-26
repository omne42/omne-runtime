use super::*;
#[test]
fn list_dir_denies_secret_requested_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny").join("sub")).expect("mkdir");

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::ReadOnly);
    let err = list_dir(
        &ctx,
        ListDirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("deny/sub"),
            max_entries: None,
        },
    )
    .expect_err("list_dir should reject denied requested path");
    assert_secret_path_denied(err, PathBuf::from("deny").join("sub"));
}

#[test]
#[cfg(any(unix, windows))]
fn list_dir_denies_after_canonicalization_through_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny").join("sub")).expect("mkdir");
    if !create_symlink_dir_or_skip(&dir.path().join("deny"), &dir.path().join("alias")) {
        return;
    }

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::ReadOnly);
    let err = list_dir(
        &ctx,
        ListDirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("alias/sub"),
            max_entries: None,
        },
    )
    .expect_err("list_dir should reject denied canonical path");
    assert_secret_path_denied(err, PathBuf::from("deny").join("sub"));
}

#[test]
fn stat_denies_secret_requested_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny")).expect("mkdir");
    std::fs::write(dir.path().join("deny").join("secret.txt"), "secret").expect("write");

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::ReadOnly);
    let err = stat(
        &ctx,
        StatRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("deny/secret.txt"),
        },
    )
    .expect_err("stat should reject denied requested path");
    assert_secret_path_denied(err, PathBuf::from("deny").join("secret.txt"));
}

#[test]
#[cfg(any(unix, windows))]
fn stat_denies_after_canonicalization_through_symlink() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny")).expect("mkdir");
    std::fs::write(dir.path().join("deny").join("secret.txt"), "secret").expect("write");
    if !create_symlink_file_or_skip(
        &dir.path().join("deny").join("secret.txt"),
        &dir.path().join("alias.txt"),
    ) {
        return;
    }

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::ReadOnly);
    let err = stat(
        &ctx,
        StatRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("alias.txt"),
        },
    )
    .expect_err("stat should reject denied canonical path");
    assert_secret_path_denied(err, PathBuf::from("deny").join("secret.txt"));
}

#[test]
fn mkdir_denies_secret_requested_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny")).expect("mkdir");

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::WorkspaceWrite);
    let err = mkdir(
        &ctx,
        MkdirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("deny/new_dir"),
            create_parents: false,
            ignore_existing: false,
        },
    )
    .expect_err("mkdir should reject denied requested path");
    assert_secret_path_denied(err, PathBuf::from("deny").join("new_dir"));
}

#[test]
#[cfg(any(unix, windows))]
fn mkdir_denies_after_canonicalization_through_symlink_parent() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny")).expect("mkdir");
    if !create_symlink_dir_or_skip(&dir.path().join("deny"), &dir.path().join("alias_parent")) {
        return;
    }

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::WorkspaceWrite);
    let err = mkdir(
        &ctx,
        MkdirRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("alias_parent/new_dir"),
            create_parents: false,
            ignore_existing: false,
        },
    )
    .expect_err("mkdir should reject denied canonical path");
    assert_secret_path_denied_any(
        err,
        &[PathBuf::from("deny"), PathBuf::from("deny").join("new_dir")],
    );
}

#[test]
fn write_file_denies_secret_requested_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny")).expect("mkdir");

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::WorkspaceWrite);
    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("deny/new.txt"),
            content: "x".to_string(),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("write_file should reject denied requested path");
    assert_secret_path_denied(err, PathBuf::from("deny").join("new.txt"));
}

#[test]
#[cfg(any(unix, windows))]
fn write_file_denies_after_canonicalization_through_symlink_parent() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny")).expect("mkdir");
    if !create_symlink_dir_or_skip(&dir.path().join("deny"), &dir.path().join("alias_parent")) {
        return;
    }

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::WorkspaceWrite);
    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("alias_parent/new.txt"),
            content: "x".to_string(),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("write_file should reject denied canonical path");
    assert_secret_path_denied_any(
        err,
        &[PathBuf::from("deny"), PathBuf::from("deny").join("new.txt")],
    );
}

#[test]
fn move_path_denies_secret_requested_destination_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny")).expect("mkdir");
    std::fs::write(dir.path().join("from.txt"), "source").expect("write");

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::WorkspaceWrite);
    let err = move_path(
        &ctx,
        MovePathRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("from.txt"),
            to: PathBuf::from("deny/out.txt"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("move_path should reject denied requested destination");
    assert_secret_path_denied_any(
        err,
        &[PathBuf::from("deny"), PathBuf::from("deny").join("out.txt")],
    );
    assert!(dir.path().join("from.txt").exists());
}

#[test]
#[cfg(any(unix, windows))]
fn move_path_denies_after_canonicalization_through_symlink_parent() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny")).expect("mkdir");
    std::fs::write(dir.path().join("from.txt"), "source").expect("write");
    if !create_symlink_dir_or_skip(&dir.path().join("deny"), &dir.path().join("alias_parent")) {
        return;
    }

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::WorkspaceWrite);
    let err = move_path(
        &ctx,
        MovePathRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("from.txt"),
            to: PathBuf::from("alias_parent/out.txt"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("move_path should reject denied canonical destination");
    assert_secret_path_denied_any(
        err,
        &[PathBuf::from("deny"), PathBuf::from("deny").join("out.txt")],
    );
    assert!(dir.path().join("from.txt").exists());
}

#[test]
fn copy_file_denies_secret_requested_destination_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny")).expect("mkdir");
    std::fs::write(dir.path().join("from.txt"), "source").expect("write");

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::WorkspaceWrite);
    let err = copy_file(
        &ctx,
        CopyFileRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("from.txt"),
            to: PathBuf::from("deny/out.txt"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("copy_file should reject denied requested destination");
    assert_secret_path_denied(err, PathBuf::from("deny").join("out.txt"));
    assert!(dir.path().join("from.txt").exists());
}

#[test]
#[cfg(any(unix, windows))]
fn copy_file_denies_after_canonicalization_through_symlink_parent() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("deny")).expect("mkdir");
    std::fs::write(dir.path().join("from.txt"), "source").expect("write");
    if !create_symlink_dir_or_skip(&dir.path().join("deny"), &dir.path().join("alias_parent")) {
        return;
    }

    let ctx = ctx_with_deny_glob(dir.path(), WriteScope::WorkspaceWrite);
    let err = copy_file(
        &ctx,
        CopyFileRequest {
            root_id: "root".to_string(),
            from: PathBuf::from("from.txt"),
            to: PathBuf::from("alias_parent/out.txt"),
            overwrite: false,
            create_parents: false,
        },
    )
    .expect_err("copy_file should reject denied canonical destination");
    assert_secret_path_denied_any(
        err,
        &[PathBuf::from("deny"), PathBuf::from("deny").join("out.txt")],
    );
    assert!(dir.path().join("from.txt").exists());
}

#[test]
fn delete_deletes_dirs_recursively_and_ignores_missing() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
    std::fs::write(dir.path().join("sub").join("a.txt"), "hi").expect("write");

    let ctx = Context::new(test_policy(dir.path(), WriteScope::WorkspaceWrite)).expect("ctx");
    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            recursive: true,
            ignore_missing: false,
        },
    )
    .expect("delete");

    assert_eq!(resp.path, PathBuf::from("sub"));
    assert_eq!(resp.requested_path, PathBuf::from("sub"));
    assert!(resp.deleted);
    assert_eq!(resp.kind, DeleteKind::Dir);
    assert!(!dir.path().join("sub").exists());

    let resp = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("missing"),
            recursive: false,
            ignore_missing: true,
        },
    )
    .expect("delete");
    assert_eq!(resp.path, PathBuf::from("missing"));
    assert_eq!(resp.requested_path, PathBuf::from("missing"));
    assert!(!resp.deleted);
    assert_eq!(resp.kind, DeleteKind::Missing);
}

#[test]
fn delete_rejects_directory_without_recursive() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");

    let mut policy = test_policy(dir.path(), WriteScope::WorkspaceWrite);
    policy.permissions.delete = true;
    let ctx = Context::new(policy).expect("ctx");
    let err = delete(
        &ctx,
        DeleteRequest {
            root_id: "root".to_string(),
            path: PathBuf::from("sub"),
            recursive: false,
            ignore_missing: false,
        },
    )
    .expect_err("delete should reject non-recursive directory delete");

    assert_eq!(err.code(), omne_fs::Error::CODE_INVALID_PATH);
    assert!(matches!(err, omne_fs::Error::InvalidPath(_)));
    assert!(dir.path().join("sub").is_dir());
}

#[test]
fn delete_rejects_readonly_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("file.txt"), "keep").expect("write");

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
    .expect_err("delete should reject readonly root");

    assert_not_permitted(err, "delete");
    assert!(dir.path().join("file.txt").exists());
}
