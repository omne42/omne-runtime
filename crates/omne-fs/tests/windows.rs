#![cfg(windows)]

mod common;

use std::path::PathBuf;

use common::test_policy;
use omne_fs::ops::{Context, ReadRequest, read_file};
use omne_fs::policy::SandboxPolicy;
use policy_meta::WriteScope;

#[cfg(feature = "glob")]
use omne_fs::ops::{GlobRequest, glob_paths};

fn toggle_drive_letter_case(path: &std::path::Path) -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Component, Prefix};

    fn toggle_ascii_letter(ch: char) -> Option<char> {
        if !ch.is_ascii_alphabetic() {
            return None;
        }
        Some(if ch.is_ascii_lowercase() {
            ch.to_ascii_uppercase()
        } else {
            ch.to_ascii_lowercase()
        })
    }

    let mut components = path.components();
    let prefix = match components.next()? {
        Component::Prefix(prefix) => prefix,
        _ => return None,
    };
    match prefix.kind() {
        Prefix::Disk(_) | Prefix::VerbatimDisk(_) => {}
        _ => return None,
    }

    let mut prefix_units: Vec<u16> = prefix.as_os_str().encode_wide().collect();
    let (idx, toggled) = prefix_units.iter().enumerate().find_map(|(idx, unit)| {
        char::from_u32(u32::from(*unit))
            .and_then(toggle_ascii_letter)
            .map(|toggled| (idx, toggled))
    })?;
    let toggled_u16 = u16::try_from(u32::from(toggled)).ok()?;
    prefix_units[idx] = toggled_u16;

    let mut rebuilt = PathBuf::from(OsString::from_wide(&prefix_units));
    rebuilt.push(components.as_path());
    Some(rebuilt)
}

fn assert_invalid_path_contains(err: omne_fs::Error, expected_substring: &str) {
    match err {
        omne_fs::Error::InvalidPath(msg) => {
            assert!(
                msg.contains(expected_substring),
                "unexpected InvalidPath msg: {msg}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn deny_globs_apply_to_absolute_paths_even_when_parent_is_missing() {
    let dir = tempfile::tempdir().expect("tempdir");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.paths.allow_absolute = true;
    policy.secrets.deny_globs = vec!["missing/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let abs = dir.path().join("missing").join("file.txt");
    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: abs,
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        omne_fs::Error::SecretPathDenied(path) => {
            assert_eq!(path, PathBuf::from("missing").join("file.txt"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn resolve_path_rejects_drive_relative_paths() {
    use std::path::Path;

    let dir = tempfile::tempdir().expect("tempdir");
    let policy = SandboxPolicy::single_root("root", dir.path(), WriteScope::ReadOnly);
    let err = policy
        .resolve_path_checked("root", Path::new("C:foo"))
        .expect_err("should reject");

    assert_invalid_path_contains(err, "drive-relative paths are not supported");
}

#[test]
fn resolve_path_rejects_colon_paths_on_windows() {
    use std::path::Path;

    let dir = tempfile::tempdir().expect("tempdir");
    let policy = SandboxPolicy::single_root("root", dir.path(), WriteScope::ReadOnly);
    let err = policy
        .resolve_path_checked("root", Path::new("file.txt::$DATA"))
        .expect_err("should reject");

    assert_invalid_path_contains(err, "':' is not allowed on Windows");
}

#[test]
fn deny_globs_match_backslash_separators() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::write(dir.path().join(".git").join("config"), "secret").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.secrets.deny_globs = vec![".git/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");
    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from(r".git\config"),
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        omne_fs::Error::SecretPathDenied(path) => {
            assert_eq!(path, PathBuf::from(".git").join("config"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn deny_globs_are_case_insensitive_on_windows() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::write(dir.path().join(".git").join("config"), "secret").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.secrets.deny_globs = vec![".GIT/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");
    let err = read_file(
        &ctx,
        ReadRequest {
            root_id: "root".to_string(),
            path: PathBuf::from(r".git\config"),
            start_line: None,
            end_line: None,
        },
    )
    .expect_err("should reject");

    match err {
        omne_fs::Error::SecretPathDenied(path) => {
            assert_eq!(path, PathBuf::from(".git").join("config"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn windows_prefix_matching_matrix_is_case_insensitive() {
    use std::path::Path;

    let cases = [
        ("drive", r"C:\Root\Missing\file.txt", r"c:\root"),
        (
            "verbatim-drive",
            r"\\?\C:\Root\Missing\file.txt",
            r"c:\root",
        ),
        (
            "unc",
            r"\\server\share\Root\Missing\file.txt",
            r"\\SERVER\SHARE\root",
        ),
        (
            "verbatim-unc",
            r"\\?\UNC\Server\Share\Root\Missing\file.txt",
            r"\\server\share\root",
        ),
    ];

    for (name, full, prefix) in cases {
        let full = Path::new(full);
        let prefix = Path::new(prefix);
        let expected = PathBuf::from("Missing").join("file.txt");

        assert!(
            omne_fs::path_utils::starts_with_case_insensitive(full, prefix),
            "starts_with_case_insensitive failed for case {name}"
        );
        assert_eq!(
            omne_fs::path_utils::strip_prefix_case_insensitive(full, prefix),
            Some(expected),
            "strip_prefix_case_insensitive failed for case {name}"
        );
    }

    let negative_cases = [
        ("drive-boundary", r"C:\rooted\file.txt", r"C:\root"),
        (
            "unc-share-boundary",
            r"\\server\sharex\root\a.txt",
            r"\\server\share\root",
        ),
        (
            "verbatim-unc-share-boundary",
            r"\\?\UNC\Server\ShareX\Root\a.txt",
            r"\\server\share\root",
        ),
        ("shorter-full", r"C:\root", r"C:\root\sub"),
    ];

    for (name, full, prefix) in negative_cases {
        let full = Path::new(full);
        let prefix = Path::new(prefix);

        assert!(
            !omne_fs::path_utils::starts_with_case_insensitive(full, prefix),
            "starts_with_case_insensitive should be false for case {name}"
        );
        assert_eq!(
            omne_fs::path_utils::strip_prefix_case_insensitive(full, prefix),
            None,
            "strip_prefix_case_insensitive should be None for case {name}"
        );
    }
}

#[test]
#[cfg(feature = "glob")]
fn glob_patterns_are_case_insensitive_on_windows() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.txt"), "a\n").expect("write");

    let ctx = Context::new(test_policy(dir.path(), WriteScope::ReadOnly)).expect("ctx");
    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "A.TXT".to_string(),
        },
    )
    .expect("glob");

    assert_eq!(resp.matches, vec![PathBuf::from("a.txt")]);
}

#[test]
#[cfg(feature = "glob")]
fn traversal_skip_globs_are_case_insensitive_on_windows() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::create_dir_all(dir.path().join(".git")).expect("mkdir");
    std::fs::write(dir.path().join(".git").join("config"), "secret").expect("write");
    std::fs::write(dir.path().join("keep.txt"), "ok").expect("write");

    let mut policy = test_policy(dir.path(), WriteScope::ReadOnly);
    policy.traversal.skip_globs = vec![".GIT/**".to_string()];
    let ctx = Context::new(policy).expect("ctx");

    let resp = glob_paths(
        &ctx,
        GlobRequest {
            root_id: "root".to_string(),
            pattern: "**/*".to_string(),
        },
    )
    .expect("glob");

    let blocked = PathBuf::from(".git/config");
    assert!(
        !resp.matches.iter().any(|path| path == &blocked),
        "expected traversal.skip_globs to exclude .git/config: {:?}",
        resp.matches
    );
    assert!(
        resp.matches
            .iter()
            .any(|path| path == &PathBuf::from("keep.txt")),
        "expected keep.txt to remain visible in traversal result: {:?}",
        resp.matches
    );
}
