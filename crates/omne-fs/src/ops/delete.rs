#[cfg(test)]
use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteRequest {
    pub root_id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub recursive: bool,
    #[serde(default)]
    pub ignore_missing: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeleteKind {
    File,
    Dir,
    Symlink,
    Other,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub path: PathBuf,
    pub requested_path: PathBuf,
    pub deleted: bool,
    #[serde(rename = "type")]
    pub kind: DeleteKind,
}

fn missing_response(requested_path: &Path) -> DeleteResponse {
    let requested_path = requested_path.to_path_buf();
    DeleteResponse {
        path: requested_path.clone(),
        requested_path,
        deleted: false,
        kind: DeleteKind::Missing,
    }
}

fn ensure_recursive_delete_allows_descendants(
    ctx: &Context,
    target_abs: &Path,
    target_relative: &Path,
    ignore_missing: bool,
) -> Result<()> {
    let max_walk_entries = u64::try_from(ctx.policy.limits.max_walk_entries).unwrap_or(u64::MAX);
    let max_walk = ctx.policy.limits.max_walk_ms.map(Duration::from_millis);
    let started = Instant::now();
    let mut scanned_entries: u64 = 0;
    delete_directory_checked(
        ctx,
        target_abs,
        target_relative,
        ignore_missing,
        &started,
        max_walk,
        max_walk_entries,
        &mut scanned_entries,
    )
}

#[allow(clippy::too_many_arguments)]
fn delete_directory_checked(
    ctx: &Context,
    dir_abs: &Path,
    dir_relative: &Path,
    ignore_missing: bool,
    started: &Instant,
    max_walk: Option<Duration>,
    max_walk_entries: u64,
    scanned_entries: &mut u64,
) -> Result<()> {
    loop {
        ensure_recursive_delete_scan_within_budget(
            dir_relative,
            *scanned_entries,
            max_walk_entries,
            started,
            max_walk,
        )?;
        let entries = match fs::read_dir(dir_abs) {
            Ok(entries) => entries,
            Err(err) if ignore_missing && err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(err) => return Err(Error::io_path("read_dir", dir_relative, err)),
        };

        for entry in entries {
            *scanned_entries = scanned_entries.saturating_add(1);
            ensure_recursive_delete_scan_within_budget(
                dir_relative,
                *scanned_entries,
                max_walk_entries,
                started,
                max_walk,
            )?;
            let entry = entry.map_err(|err| Error::io_path("read_dir", dir_relative, err))?;
            let child_name = entry.file_name();
            let child_relative = dir_relative.join(&child_name);
            if ctx.redactor.is_path_denied(&child_relative) {
                return Err(Error::SecretPathDenied(child_relative));
            }

            let child_type = entry
                .file_type()
                .map_err(|err| Error::io_path("file_type", &child_relative, err))?;
            let child_abs = dir_abs.join(&child_name);
            if child_type.is_dir() {
                delete_directory_checked(
                    ctx,
                    &child_abs,
                    &child_relative,
                    ignore_missing,
                    started,
                    max_walk,
                    max_walk_entries,
                    scanned_entries,
                )?;
                continue;
            }

            let delete_result = if child_type.is_symlink() {
                unlink_symlink(&child_abs)
            } else {
                fs::remove_file(&child_abs)
            };
            match delete_result {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    let op = if child_type.is_symlink() {
                        "unlink_symlink"
                    } else {
                        "remove_file"
                    };
                    return Err(Error::io_path(op, &child_relative, err));
                }
            }
        }

        run_before_recursive_remove_dir_hook(dir_abs);
        match fs::remove_dir(dir_abs) {
            Ok(()) => return Ok(()),
            Err(err) if ignore_missing && err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(());
            }
            Err(err) if err.kind() == std::io::ErrorKind::DirectoryNotEmpty => continue,
            Err(err) => return Err(Error::io_path("remove_dir", dir_relative, err)),
        }
    }
}

#[cfg(test)]
type RecursiveDeleteHook = Box<dyn Fn(&Path) + Send + Sync + 'static>;

#[cfg(test)]
fn recursive_delete_hook_slot() -> &'static Mutex<Option<RecursiveDeleteHook>> {
    static SLOT: OnceLock<Mutex<Option<RecursiveDeleteHook>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn install_recursive_delete_hook(hook: RecursiveDeleteHook) {
    *recursive_delete_hook_slot()
        .lock()
        .expect("recursive delete hook lock") = Some(hook);
}

#[cfg(test)]
fn clear_recursive_delete_hook() {
    *recursive_delete_hook_slot()
        .lock()
        .expect("recursive delete hook lock") = None;
}

#[cfg(test)]
fn run_before_recursive_remove_dir_hook(path: &Path) {
    if let Some(hook) = recursive_delete_hook_slot()
        .lock()
        .expect("recursive delete hook lock")
        .as_ref()
    {
        hook(path);
    }
}

#[cfg(not(test))]
fn run_before_recursive_remove_dir_hook(_path: &Path) {}

#[cfg(test)]
#[inline]
fn target_relative_with_suffix<'a>(target_relative: &'a Path, suffix: &'a Path) -> Cow<'a, Path> {
    if suffix.as_os_str().is_empty() {
        return Cow::Borrowed(target_relative);
    }
    if target_relative == Path::new(".") {
        return Cow::Borrowed(suffix);
    }
    Cow::Owned(target_relative.join(suffix))
}

#[cfg(test)]
#[inline]
fn child_relative_prefix(target_relative: &Path, dir_suffix: &Path) -> PathBuf {
    if target_relative == Path::new(".") {
        return dir_suffix.to_path_buf();
    }

    let mut joined = target_relative.to_path_buf();
    if !dir_suffix.as_os_str().is_empty() {
        joined.push(dir_suffix);
    }
    joined
}

#[cfg(test)]
#[inline]
fn target_relative_child<'a>(
    target_relative: &Path,
    dir_suffix: &Path,
    child_name: &'a std::ffi::OsStr,
) -> Cow<'a, Path> {
    if target_relative == Path::new(".") && dir_suffix.as_os_str().is_empty() {
        return Cow::Borrowed(Path::new(child_name));
    }

    if target_relative == Path::new(".") {
        return Cow::Owned(dir_suffix.join(child_name));
    }

    let mut joined = target_relative.to_path_buf();
    if !dir_suffix.as_os_str().is_empty() {
        joined.push(dir_suffix);
    }
    joined.push(child_name);
    Cow::Owned(joined)
}

fn ensure_recursive_delete_scan_within_budget(
    current_relative_dir: &Path,
    scanned_entries: u64,
    max_walk_entries: u64,
    started: &Instant,
    max_walk: Option<Duration>,
) -> Result<()> {
    if scanned_entries > max_walk_entries {
        return Err(Error::NotPermitted(format!(
            "recursive delete pre-scan exceeded limits.max_walk_entries while scanning {} ({scanned_entries} > {max_walk_entries})",
            current_relative_dir.display()
        )));
    }
    if let Some(limit) = max_walk
        && started.elapsed() >= limit
    {
        return Err(Error::NotPermitted(format!(
            "recursive delete pre-scan exceeded limits.max_walk_ms while scanning {} (>= {} ms)",
            current_relative_dir.display(),
            limit.as_millis()
        )));
    }
    Ok(())
}

fn unlink_symlink(target: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        match fs::remove_file(target) {
            Ok(()) => Ok(()),
            // On Windows, directory symlinks/junctions require remove_dir semantics.
            Err(remove_file_err) => match fs::remove_dir(target) {
                Ok(()) => Ok(()),
                Err(_) => Err(remove_file_err),
            },
        }
    }

    #[cfg(not(windows))]
    {
        fs::remove_file(target)
    }
}

#[cfg(any(unix, windows))]
fn ensure_delete_identity_verification_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_delete_identity_verification_supported() -> Result<()> {
    Err(Error::InvalidPath(
        "delete is unsupported on this platform: cannot verify file identity".to_string(),
    ))
}

fn revalidate_parent_before_delete(
    ctx: &Context,
    request: &DeleteRequest,
    requested_parent: &Path,
    canonical_parent: &Path,
    canonical_parent_meta: &super::io::DirectoryIdentity,
    requested_path: &Path,
) -> Result<Option<DeleteResponse>> {
    match ctx.ensure_dir_under_root(&request.root_id, requested_parent, false) {
        Ok(rechecked_parent) => {
            if !crate::path_utils::paths_equal_case_insensitive(&rechecked_parent, canonical_parent)
            {
                Err(Error::InvalidPath(format!(
                    "path {} changed during delete; refusing to continue",
                    requested_path.display()
                )))
            } else {
                let rechecked_parent_meta = match fs::symlink_metadata(&rechecked_parent) {
                    Ok(meta) => meta,
                    Err(err)
                        if request.ignore_missing && err.kind() == std::io::ErrorKind::NotFound =>
                    {
                        return Ok(Some(missing_response(requested_path)));
                    }
                    Err(err) => {
                        return Err(Error::io_path("symlink_metadata", requested_parent, err));
                    }
                };
                let _ = rechecked_parent_meta;
                canonical_parent_meta.ensure_verified(
                    &rechecked_parent,
                    requested_parent,
                    || {
                        Error::InvalidPath(
                            "parent identity changed during delete; refusing to continue"
                                .to_string(),
                        )
                    },
                    || {
                        Error::InvalidPath(
                            "cannot verify parent identity during delete; refusing to continue"
                                .to_string(),
                        )
                    },
                )?;
                Ok(None)
            }
        }
        Err(Error::IoPath { source, .. })
            if request.ignore_missing && source.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(Some(missing_response(requested_path)))
        }
        Err(err) => Err(err),
    }
}

fn revalidate_target_before_delete(
    target: &Path,
    relative: &Path,
    target_identity: &super::io::PathIdentity,
) -> Result<()> {
    target_identity.ensure_verified(
        target,
        relative,
        || {
            Error::InvalidPath(
                "target identity changed during delete; refusing to continue".to_string(),
            )
        },
        || {
            Error::InvalidPath(
                "cannot verify target identity during delete; refusing to continue".to_string(),
            )
        },
    )
}

pub fn delete(ctx: &Context, request: DeleteRequest) -> Result<DeleteResponse> {
    let defer_permission_to_git_fallback =
        !ctx.policy.permissions.delete && ctx.git_permission_fallback_enabled();
    if defer_permission_to_git_fallback {
        ctx.ensure_can_write(&request.root_id, "delete")?;
    } else {
        ctx.ensure_write_operation_allowed(
            &request.root_id,
            ctx.policy.permissions.delete,
            "delete",
        )?;
    }
    ensure_delete_identity_verification_supported()?;

    let resolved =
        super::resolve::resolve_path_in_root_lexically(ctx, &request.root_id, &request.path)?;
    let canonical_root = resolved.canonical_root;
    let requested_path = resolved.requested_path;

    let file_name = super::path_validation::ensure_non_root_leaf(
        &requested_path,
        &request.path,
        super::path_validation::LeafOp::Delete,
    )?;

    let requested_parent = requested_path.parent().unwrap_or_else(|| Path::new(""));
    let requested_relative = requested_parent.join(file_name);
    // First check blocks secret paths in the original user-supplied location.
    if ctx.redactor.is_path_denied(&requested_relative) {
        return Err(Error::SecretPathDenied(requested_relative));
    }

    let canonical_parent =
        match ctx.ensure_dir_under_root(&request.root_id, requested_parent, false) {
            Ok(path) => path,
            Err(Error::IoPath { source, .. })
                if request.ignore_missing && source.kind() == std::io::ErrorKind::NotFound =>
            {
                // If the parent directory doesn't exist, the target doesn't exist either.
                return Ok(missing_response(&requested_path));
            }
            Err(err) => return Err(err),
        };
    let relative_parent = crate::path_utils::strip_prefix_case_insensitive_normalized(
        &canonical_parent,
        canonical_root,
    )
    .ok_or_else(|| Error::OutsideRoot {
        root_id: request.root_id.clone(),
        path: requested_path.clone(),
    })?;
    let canonical_parent_meta =
        match super::io::DirectoryIdentity::capture(&canonical_parent, &relative_parent, || {
            Error::InvalidPath(format!(
                "parent path {} is not a directory",
                relative_parent.display()
            ))
        }) {
            Ok(meta) => meta,
            Err(Error::IoPath { source, .. })
                if request.ignore_missing && source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(missing_response(&requested_path));
            }
            Err(err) => return Err(err),
        };
    let relative = relative_parent.join(file_name);

    // Second check blocks secret paths after canonicalization resolves symlinks.
    if ctx.redactor.is_path_denied(&relative) {
        return Err(Error::SecretPathDenied(relative));
    }
    if defer_permission_to_git_fallback {
        ctx.ensure_git_revertible_write_allowed(
            &request.root_id,
            &relative,
            "delete",
            request.recursive,
        )?;
    }

    let target = canonical_parent.join(file_name);
    if !crate::path_utils::starts_with_case_insensitive_normalized(&target, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

    if let Some(response) = revalidate_parent_before_delete(
        ctx,
        &request,
        requested_parent,
        &canonical_parent,
        &canonical_parent_meta,
        &requested_path,
    )? {
        return Ok(response);
    }

    let target_identity = match super::io::PathIdentity::capture(&target, &relative) {
        Ok(identity) => identity,
        Err(Error::IoPath { source, .. })
            if source.kind() == std::io::ErrorKind::NotFound && request.ignore_missing =>
        {
            return Ok(missing_response(&requested_path));
        }
        Err(err) => return Err(err),
    };

    let file_type = target_identity.metadata().file_type();
    let kind = if file_type.is_file() {
        DeleteKind::File
    } else if file_type.is_dir() {
        DeleteKind::Dir
    } else if file_type.is_symlink() {
        DeleteKind::Symlink
    } else {
        DeleteKind::Other
    };

    let ensure_parent_stable_or_missing = || {
        revalidate_parent_before_delete(
            ctx,
            &request,
            requested_parent,
            &canonical_parent,
            &canonical_parent_meta,
            &requested_path,
        )
    };
    let ensure_target_stable_or_missing = || -> Result<Option<DeleteResponse>> {
        match fs::symlink_metadata(&target) {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing => {
                return Ok(Some(missing_response(&requested_path)));
            }
            Err(err) => return Err(Error::io_path("symlink_metadata", &relative, err)),
        }
        revalidate_target_before_delete(&target, &relative, &target_identity)?;
        Ok(None)
    };

    if file_type.is_dir() {
        if !request.recursive {
            return Err(Error::InvalidPath(
                "path is a directory; set recursive=true to delete directories".to_string(),
            ));
        }

        if let Some(response) = ensure_parent_stable_or_missing()? {
            return Ok(response);
        }
        if let Some(response) = ensure_target_stable_or_missing()? {
            return Ok(response);
        }
        ensure_recursive_delete_allows_descendants(
            ctx,
            &target,
            &relative,
            request.ignore_missing,
        )?;
    } else {
        if let Some(response) = ensure_parent_stable_or_missing()? {
            return Ok(response);
        }
        if let Some(response) = ensure_target_stable_or_missing()? {
            return Ok(response);
        }

        let delete_non_dir_result = if file_type.is_symlink() {
            unlink_symlink(&target)
        } else {
            fs::remove_file(&target)
        };
        if let Err(err) = delete_non_dir_result {
            if err.kind() == std::io::ErrorKind::NotFound && request.ignore_missing {
                return Ok(missing_response(&requested_path));
            }
            let op = if file_type.is_symlink() {
                "unlink_symlink"
            } else {
                "remove_file"
            };
            return Err(Error::io_path(op, &relative, err));
        }
    }

    Ok(DeleteResponse {
        path: relative,
        requested_path,
        deleted: true,
        kind,
    })
}

#[cfg(test)]
mod recursive_scan_tests {
    use std::path::Path;
    use std::time::{Duration, Instant};

    use super::{
        child_relative_prefix, ensure_recursive_delete_scan_within_budget, target_relative_child,
        target_relative_with_suffix,
    };
    use crate::error::Error;

    #[test]
    fn recursive_scan_budget_rejects_entry_limit_overflow() {
        let err = ensure_recursive_delete_scan_within_budget(
            Path::new("public"),
            11,
            10,
            &Instant::now(),
            None,
        )
        .expect_err("must reject scans over max_walk_entries");
        match err {
            Error::NotPermitted(msg) => assert!(msg.contains("limits.max_walk_entries")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn recursive_scan_budget_rejects_elapsed_time_limit() {
        let started = Instant::now();
        let err = ensure_recursive_delete_scan_within_budget(
            Path::new("public"),
            0,
            10,
            &started,
            Some(Duration::from_millis(0)),
        )
        .expect_err("must reject scans over max_walk_ms");
        match err {
            Error::NotPermitted(msg) => assert!(msg.contains("limits.max_walk_ms")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn target_relative_suffix_joins_for_non_root_target() {
        let joined = target_relative_with_suffix(Path::new("root/subtree"), Path::new("a/b"));
        assert_eq!(joined, Path::new("root/subtree/a/b"));
    }

    #[test]
    fn target_relative_suffix_avoids_dot_prefix() {
        let joined = target_relative_with_suffix(Path::new("."), Path::new("a/b"));
        assert_eq!(joined, Path::new("a/b"));
    }

    #[test]
    fn target_relative_child_avoids_dot_prefix_for_root_target() {
        let joined =
            target_relative_child(Path::new("."), Path::new(""), std::ffi::OsStr::new("x.txt"));
        assert_eq!(joined, Path::new("x.txt"));
    }

    #[test]
    fn target_relative_child_joins_nested_suffix_for_non_root_target() {
        let joined = target_relative_child(
            Path::new("root/subtree"),
            Path::new("a/b"),
            std::ffi::OsStr::new("x.txt"),
        );
        assert_eq!(joined, Path::new("root/subtree/a/b/x.txt"));
    }

    #[test]
    fn child_relative_prefix_avoids_dot_prefix_for_root_target() {
        let prefix = child_relative_prefix(Path::new("."), Path::new("a/b"));
        assert_eq!(prefix, Path::new("a/b"));
    }

    #[test]
    fn child_relative_prefix_joins_nested_suffix_for_non_root_target() {
        let prefix = child_relative_prefix(Path::new("root/subtree"), Path::new("a/b"));
        assert_eq!(prefix, Path::new("root/subtree/a/b"));
    }
}

#[cfg(test)]
mod recursive_delete_commit_tests {
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use policy_meta::WriteScope;

    use super::{
        DeleteRequest, clear_recursive_delete_hook, delete, install_recursive_delete_hook,
    };
    use crate::ops::Context;
    use crate::policy::SandboxPolicy;

    fn permissive_policy(root: &Path) -> SandboxPolicy {
        let mut policy =
            SandboxPolicy::single_root("root", root.to_path_buf(), WriteScope::WorkspaceWrite);
        policy.permissions.read = true;
        policy.permissions.glob = true;
        policy.permissions.grep = true;
        policy.permissions.list_dir = true;
        policy.permissions.stat = true;
        policy.permissions.edit = true;
        policy.permissions.patch = true;
        policy.permissions.delete = true;
        policy.permissions.mkdir = true;
        policy.permissions.write = true;
        policy.permissions.move_path = true;
        policy.permissions.copy_file = true;
        policy.secrets.deny_globs = vec!["sub/secrets/**".to_string()];
        policy
    }

    struct HookGuard;

    impl Drop for HookGuard {
        fn drop(&mut self) {
            clear_recursive_delete_hook();
        }
    }

    #[test]
    fn recursive_delete_rechecks_newly_added_denied_content_before_final_remove() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("sub")).expect("mkdir");
        let ctx = Context::new(permissive_policy(dir.path())).expect("ctx");
        let inserted = Arc::new(AtomicBool::new(false));
        let inserted_bg = Arc::clone(&inserted);
        let target = dir.path().join("sub");
        let target_for_hook = target.clone();
        install_recursive_delete_hook(Box::new(move |path| {
            if path == target_for_hook && !inserted_bg.swap(true, Ordering::SeqCst) {
                std::fs::create_dir_all(path.join("secrets")).expect("mkdir secrets");
                std::fs::write(path.join("secrets").join("token.txt"), "secret")
                    .expect("write secret");
            }
        }));
        let _hook_guard = HookGuard;

        let err = delete(
            &ctx,
            DeleteRequest {
                root_id: "root".to_string(),
                path: PathBuf::from("sub"),
                recursive: true,
                ignore_missing: false,
            },
        )
        .expect_err("denied content inserted before final remove should fail closed");

        match err {
            crate::error::Error::SecretPathDenied(path) => {
                assert!(
                    path == PathBuf::from("sub").join("secrets")
                        || path == PathBuf::from("sub").join("secrets").join("token.txt")
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            target.exists(),
            "target directory must remain after deny failure"
        );
        assert!(
            target.join("secrets").join("token.txt").exists(),
            "newly added denied content must not be deleted"
        );
    }
}

#[cfg(test)]
mod identity_tests {
    use std::fs;
    use std::path::Path;

    use super::{DeleteRequest, revalidate_parent_before_delete, revalidate_target_before_delete};
    use crate::error::Error;

    #[test]
    fn delete_parent_revalidation_rejects_unverifiable_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let parent = dir.path().join("parent");
        fs::create_dir(&parent).expect("create parent");
        let canonical_parent = parent.canonicalize().expect("canonicalize parent");
        let metadata = fs::symlink_metadata(&canonical_parent).expect("metadata");
        let identity = crate::ops::io::DirectoryIdentity::unverifiable_for_tests(metadata);
        let ctx = crate::ops::Context::new(crate::policy::SandboxPolicy::single_root(
            "root",
            dir.path(),
            policy_meta::WriteScope::WorkspaceWrite,
        ))
        .expect("ctx");

        let err = revalidate_parent_before_delete(
            &ctx,
            &DeleteRequest {
                root_id: "root".to_string(),
                path: Path::new("parent/file.txt").to_path_buf(),
                recursive: false,
                ignore_missing: false,
            },
            Path::new("parent"),
            &canonical_parent,
            &identity,
            Path::new("parent/file.txt"),
        )
        .expect_err("unverifiable parent identity must fail closed");
        match err {
            Error::InvalidPath(message) => assert_eq!(
                message,
                "cannot verify parent identity during delete; refusing to continue"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn delete_target_revalidation_rejects_unverifiable_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("file.txt");
        fs::write(&target, "hello").expect("write file");
        let metadata = fs::symlink_metadata(&target).expect("metadata");
        let identity = crate::ops::io::PathIdentity::unverifiable_for_tests(metadata);

        let err = revalidate_target_before_delete(&target, Path::new("file.txt"), &identity)
            .expect_err("unverifiable target identity must fail closed");
        match err {
            Error::InvalidPath(message) => assert_eq!(
                message,
                "cannot verify target identity during delete; refusing to continue"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
