use super::common::all_permissions_test_policy;
use super::*;

fn assert_root_not_found(err: omne_fs::Error, expected_root_id: &str) {
    match err {
        omne_fs::Error::RootNotFound(root_id) => assert_eq!(root_id, expected_root_id),
        other => panic!("unexpected error: {other:?}"),
    }
}

fn assert_missing_root<T: std::fmt::Debug>(result: Result<T, omne_fs::Error>, op: &str) {
    let err = result.expect_err(&format!("{op} should reject missing root"));
    assert_root_not_found(err, "missing");
}

const MISSING_ROOT_ID: &str = "missing";

struct MissingRootFixture {
    _dir: tempfile::TempDir,
    ctx: Context,
    file_path: PathBuf,
    from: PathBuf,
    to: PathBuf,
}

fn setup_missing_root_fixture() -> MissingRootFixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    let from = dir.path().join("from.txt");
    let to = dir.path().join("to.txt");
    std::fs::write(&file_path, "hello\n").expect("write file");
    std::fs::write(&from, "from\n").expect("write from");
    std::fs::write(&to, "to\n").expect("write to");
    let ctx = Context::new(all_permissions_test_policy(
        dir.path(),
        WriteScope::WorkspaceWrite,
    ))
    .expect("ctx");

    MissingRootFixture {
        _dir: dir,
        ctx,
        file_path,
        from,
        to,
    }
}

fn assert_missing_root_side_effects(fixture: &MissingRootFixture) {
    assert_eq!(
        std::fs::read_to_string(&fixture.file_path).expect("read file after missing root rejects"),
        "hello\n"
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.from).expect("read from after missing root rejects"),
        "from\n"
    );
    assert_eq!(
        std::fs::read_to_string(&fixture.to).expect("read to after missing root rejects"),
        "to\n"
    );
    let sub_dir = fixture
        .file_path
        .parent()
        .expect("fixture root dir")
        .join("sub");
    assert!(
        !sub_dir.exists(),
        "missing root mkdir must not create target directory"
    );
}

#[test]
fn missing_root_with_disabled_write_permission_reports_not_permitted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "hello\n").expect("write baseline");

    let mut policy = all_permissions_test_policy(dir.path(), WriteScope::WorkspaceWrite);
    policy.permissions.write = false;
    let ctx = Context::new(policy).expect("ctx");

    let err = write_file(
        &ctx,
        WriteFileRequest {
            root_id: MISSING_ROOT_ID.to_string(),
            path: PathBuf::from("file.txt"),
            content: "updated\n".to_string(),
            overwrite: true,
            create_parents: false,
        },
    )
    .expect_err("should reject");

    assert_not_permitted(err, "write", NotPermittedReason::DisabledByPolicy);
    assert_eq!(
        std::fs::read_to_string(&file_path).expect("read after deny"),
        "hello\n",
        "disabled write permission must reject before missing-root handling"
    );
}

#[test]
fn missing_root_with_readonly_root_reports_root_not_found() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("file.txt");
    std::fs::write(&file_path, "hello\n").expect("write baseline");

    let policy = all_permissions_test_policy(dir.path(), WriteScope::ReadOnly);
    let ctx = Context::new(policy).expect("ctx");

    assert_missing_root(
        write_file(
            &ctx,
            WriteFileRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                content: "updated\n".to_string(),
                overwrite: true,
                create_parents: false,
            },
        ),
        "write",
    );
    assert_eq!(
        std::fs::read_to_string(&file_path).expect("read after deny"),
        "hello\n",
        "missing root must be reported before readonly root rejection"
    );
}

#[test]
fn root_not_found_is_reported_for_read() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        read_file(
            &fixture.ctx,
            ReadRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                start_line: None,
                end_line: None,
            },
        ),
        "read",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_write() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        write_file(
            &fixture.ctx,
            WriteFileRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                content: "updated\n".to_string(),
                overwrite: true,
                create_parents: false,
            },
        ),
        "write",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
#[cfg(feature = "glob")]
fn root_not_found_is_reported_for_glob() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        glob_paths(
            &fixture.ctx,
            GlobRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                pattern: "**/*.txt".to_string(),
            },
        ),
        "glob",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
#[cfg(not(feature = "glob"))]
fn root_not_found_is_reported_for_glob() {
    let fixture = setup_missing_root_fixture();
    let err = glob_paths(
        &fixture.ctx,
        GlobRequest {
            root_id: MISSING_ROOT_ID.to_string(),
            pattern: "**/*.txt".to_string(),
        },
    )
    .expect_err("glob should reject missing root");
    assert_not_permitted_with_tokens(
        err,
        "glob",
        &["not supported", "feature 'glob' is disabled"],
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
#[cfg(feature = "grep")]
fn root_not_found_is_reported_for_grep() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        grep(
            &fixture.ctx,
            GrepRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                query: "hello".to_string(),
                regex: false,
                glob: None,
            },
        ),
        "grep",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
#[cfg(not(feature = "grep"))]
fn root_not_found_is_reported_for_grep() {
    let fixture = setup_missing_root_fixture();
    let err = grep(
        &fixture.ctx,
        GrepRequest {
            root_id: MISSING_ROOT_ID.to_string(),
            query: "hello".to_string(),
            regex: false,
            glob: None,
        },
    )
    .expect_err("grep should reject missing root");
    assert_not_permitted_with_tokens(
        err,
        "grep",
        &["not supported", "feature 'grep' is disabled"],
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_list_dir() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        list_dir(
            &fixture.ctx,
            ListDirRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("."),
                max_entries: None,
            },
        ),
        "list_dir",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_stat() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        stat(
            &fixture.ctx,
            StatRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
            },
        ),
        "stat",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_edit() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        edit_range(
            &fixture.ctx,
            EditRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                start_line: 1,
                end_line: 1,
                replacement: "HELLO".to_string(),
            },
        ),
        "edit",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
#[cfg(feature = "patch")]
fn root_not_found_is_reported_for_patch() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        apply_unified_patch(
            &fixture.ctx,
            PatchRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                patch: "x".to_string(),
            },
        ),
        "patch",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_mkdir() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        mkdir(
            &fixture.ctx,
            MkdirRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("sub"),
                create_parents: true,
                ignore_existing: false,
            },
        ),
        "mkdir",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_delete() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        delete(
            &fixture.ctx,
            DeleteRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                path: PathBuf::from("file.txt"),
                recursive: false,
                ignore_missing: false,
            },
        ),
        "delete",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_move() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        move_path(
            &fixture.ctx,
            MovePathRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                from: PathBuf::from("from.txt"),
                to: PathBuf::from("to.txt"),
                overwrite: true,
                create_parents: false,
            },
        ),
        "move",
    );
    assert_missing_root_side_effects(&fixture);
}

#[test]
fn root_not_found_is_reported_for_copy() {
    let fixture = setup_missing_root_fixture();
    assert_missing_root(
        copy_file(
            &fixture.ctx,
            CopyFileRequest {
                root_id: MISSING_ROOT_ID.to_string(),
                from: PathBuf::from("from.txt"),
                to: PathBuf::from("to.txt"),
                overwrite: true,
                create_parents: false,
            },
        ),
        "copy_file",
    );
    assert_missing_root_side_effects(&fixture);
}
