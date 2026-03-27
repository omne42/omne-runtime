use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

#[cfg(any(unix, windows))]
fn ensure_create_missing_identity_verification_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_create_missing_identity_verification_supported() -> Result<()> {
    Err(Error::InvalidPath(
        "create_parents is unsupported on this platform: cannot verify parent directory identity"
            .to_string(),
    ))
}

fn outside_root_error(root_id: &str, relative: &Path) -> Error {
    Error::OutsideRoot {
        root_id: root_id.to_string(),
        path: relative.to_path_buf(),
    }
}

fn ensure_canonical_under_root(
    canonical: &Path,
    canonical_root: &Path,
    root_id: &str,
    relative: &Path,
) -> Result<()> {
    if crate::path_utils::starts_with_case_insensitive_normalized(canonical, canonical_root) {
        return Ok(());
    }
    Err(outside_root_error(root_id, relative))
}

fn canonicalize_checked(
    path: &Path,
    relative: &Path,
    canonical_root: &Path,
    root_id: &str,
) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .map_err(|err| Error::io_path("canonicalize", relative, err))?;
    ensure_canonical_under_root(&canonical, canonical_root, root_id, relative)?;
    Ok(canonical)
}

fn canonical_relative_checked(
    canonical: &Path,
    canonical_root: &Path,
    root_id: &str,
    relative: &Path,
) -> Result<PathBuf> {
    ensure_canonical_under_root(canonical, canonical_root, root_id, relative)?;
    crate::path_utils::strip_prefix_case_insensitive_normalized(canonical, canonical_root)
        .ok_or_else(|| {
            Error::InvalidPath(format!(
                "failed to derive root-relative path from canonical path {}",
                canonical.display()
            ))
        })
}

fn reject_secret_canonical_path(
    ctx: &super::super::Context,
    canonical: &Path,
    canonical_root: &Path,
    root_id: &str,
    relative: &Path,
) -> Result<()> {
    let relative_path = canonical_relative_checked(canonical, canonical_root, root_id, relative)?;
    ctx.reject_secret_path(relative_path)?;
    Ok(())
}

fn ensure_rechecked_parent_matches_expected(
    canonical_parent: &Path,
    canonical_root: &Path,
    root_id: &str,
    parent_relative: &Path,
) -> Result<()> {
    let canonical_relative =
        canonical_relative_checked(canonical_parent, canonical_root, root_id, parent_relative)?;
    if crate::path_utils::paths_equal_case_insensitive_normalized(
        &canonical_relative,
        parent_relative,
    ) {
        return Ok(());
    }

    Err(Error::InvalidPath(format!(
        "parent path {} changed during operation",
        parent_relative.display()
    )))
}

struct ParentVerificationContext<'a> {
    path: &'a Path,
    relative: &'a Path,
    expected_meta: &'a super::super::io::DirectoryIdentity,
    canonical_root: &'a Path,
    root_id: &'a str,
}

fn cleanup_created_dir(
    parent_ctx: &ParentVerificationContext<'_>,
    next: &Path,
    relative: &Path,
    created_meta: &super::super::io::DirectoryIdentity,
    validation_err: &Error,
) -> Result<()> {
    verify_parent_identity(parent_ctx)?;
    created_meta.ensure_verified(
        next,
        relative,
        || {
            Error::InvalidPath(format!(
                "path {} changed before cleanup after validation failure: {validation_err}",
                relative.display()
            ))
        },
        || {
            Error::InvalidPath(format!(
                "path {} identity could not be verified before cleanup after validation failure: {validation_err}",
                relative.display()
            ))
        },
    )?;
    fs::remove_dir(next).map_err(|cleanup_err| {
        let cleanup_context = std::io::Error::new(
            cleanup_err.kind(),
            format!(
                "directory post-create validation failed ({validation_err}); cleanup failed: {cleanup_err}"
            ),
        );
        Error::io_path("remove_dir", relative, cleanup_context)
    })
}

fn capture_parent_identity(
    parent: &Path,
    parent_relative: &Path,
) -> Result<super::super::io::DirectoryIdentity> {
    super::super::io::DirectoryIdentity::capture(parent, parent_relative, || {
        Error::InvalidPath(format!(
            "parent path {} changed during operation",
            parent_relative.display()
        ))
    })
}

fn verify_parent_identity(parent_ctx: &ParentVerificationContext<'_>) -> Result<()> {
    match parent_ctx
        .expected_meta
        .verify(parent_ctx.path, parent_ctx.relative, || {
            Error::InvalidPath(format!(
                "parent path {} changed during operation",
                parent_ctx.relative.display()
            ))
        })? {
        super::super::io::MetadataIdentityCheck::Verified => Ok(()),
        super::super::io::MetadataIdentityCheck::Unverifiable => {
            let canonical_parent = canonicalize_checked(
                parent_ctx.path,
                parent_ctx.relative,
                parent_ctx.canonical_root,
                parent_ctx.root_id,
            )?;
            ensure_rechecked_parent_matches_expected(
                &canonical_parent,
                parent_ctx.canonical_root,
                parent_ctx.root_id,
                parent_ctx.relative,
            )
        }
    }
}

fn handle_existing_component(
    next: &Path,
    meta: &fs::Metadata,
    relative: &Path,
    canonical_root: &Path,
    root_id: &str,
    canonicalize_existing_dirs: bool,
) -> Result<PathBuf> {
    if meta.file_type().is_symlink() {
        let canonical = canonicalize_checked(next, relative, canonical_root, root_id)?;
        let canonical_meta =
            fs::metadata(&canonical).map_err(|err| Error::io_path("metadata", relative, err))?;
        if !canonical_meta.is_dir() {
            return Err(Error::InvalidPath(format!(
                "path component {} is not a directory",
                relative.display()
            )));
        }
        return Ok(canonical);
    }

    if meta.is_dir() {
        if canonicalize_existing_dirs {
            return canonicalize_checked(next, relative, canonical_root, root_id);
        }
        ensure_canonical_under_root(next, canonical_root, root_id, relative)?;
        return Ok(next.to_path_buf());
    }

    Err(Error::InvalidPath(format!(
        "path component {} is not a directory",
        relative.display()
    )))
}

fn validate_relative_component<'a>(
    relative: &Path,
    component: Component<'a>,
) -> Result<Option<&'a OsStr>> {
    match component {
        Component::CurDir => Ok(None),
        Component::ParentDir => Err(Error::InvalidPath(format!(
            "invalid path {}: '..' segments are not allowed",
            relative.display()
        ))),
        Component::Normal(segment) => Ok(Some(segment)),
        _ => Err(Error::InvalidPath(format!(
            "invalid path segment in {}",
            relative.display()
        ))),
    }
}

pub(super) fn ensure_dir_under_root(
    ctx: &super::super::Context,
    root_id: &str,
    relative: &Path,
    create_missing: bool,
) -> Result<PathBuf> {
    let canonical_root = ctx.canonical_root(root_id)?;
    if create_missing {
        ensure_create_missing_identity_verification_supported()?;
    }
    let mut current = canonical_root.to_path_buf();
    let mut current_relative = PathBuf::new();

    for component in relative.components() {
        let Some(segment) = validate_relative_component(relative, component)? else {
            continue;
        };
        current_relative.push(segment);
        let next_relative = current_relative.as_path();
        let parent_relative = next_relative.parent().unwrap_or_else(|| Path::new(""));
        let parent_meta_snapshot = if create_missing {
            Some(capture_parent_identity(&current, parent_relative)?)
        } else {
            None
        };
        let next = current.join(segment);
        let mut created_meta: Option<super::super::io::DirectoryIdentity> = None;
        let parent_ctx =
            parent_meta_snapshot
                .as_ref()
                .map(|expected_meta| ParentVerificationContext {
                    path: &current,
                    relative: parent_relative,
                    expected_meta,
                    canonical_root,
                    root_id,
                });

        let resolved_current = match fs::symlink_metadata(&next) {
            Ok(meta) => handle_existing_component(
                &next,
                &meta,
                next_relative,
                canonical_root,
                root_id,
                !create_missing,
            )?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if !create_missing {
                    return Err(Error::io_path("symlink_metadata", next_relative, err));
                }
                let expected_parent_meta = match parent_meta_snapshot.as_ref() {
                    Some(meta) => meta,
                    None => {
                        return Err(Error::InvalidPath(
                            "internal error: missing parent identity snapshot".to_string(),
                        ));
                    }
                };
                let verified_parent_ctx = parent_ctx
                    .as_ref()
                    .expect("create_missing always populates parent verification context");
                debug_assert!(std::ptr::eq(
                    verified_parent_ctx.expected_meta,
                    expected_parent_meta
                ));
                verify_parent_identity(verified_parent_ctx)?;
                reject_secret_canonical_path(ctx, &next, canonical_root, root_id, next_relative)?;
                let created_now = match fs::create_dir(&next) {
                    Ok(()) => true,
                    Err(create_err) if create_err.kind() == std::io::ErrorKind::AlreadyExists => {
                        false
                    }
                    Err(create_err) => {
                        return Err(Error::io_path("create_dir", next_relative, create_err));
                    }
                };
                let mut post_create_meta =
                    Some(fs::symlink_metadata(&next).map_err(|meta_err| {
                        Error::io_path("symlink_metadata", next_relative, meta_err)
                    })?);
                if created_now {
                    let created_identity = super::super::io::DirectoryIdentity::from_metadata(
                        &next,
                        post_create_meta.take().ok_or_else(|| {
                            Error::InvalidPath(
                                "internal error: missing post-create metadata snapshot".to_string(),
                            )
                        })?,
                        || {
                            Error::InvalidPath(format!(
                                "path component {} is not a directory",
                                next_relative.display()
                            ))
                        },
                    )?;
                    created_meta = Some(created_identity);
                }
                if let Err(err) = verify_parent_identity(verified_parent_ctx) {
                    if let Some(created_meta) = created_meta.as_ref() {
                        cleanup_created_dir(
                            verified_parent_ctx,
                            &next,
                            next_relative,
                            created_meta,
                            &err,
                        )?;
                    }
                    return Err(err);
                }

                let post_create_meta = created_meta
                    .as_ref()
                    .map(super::super::io::DirectoryIdentity::metadata)
                    .or(post_create_meta.as_ref())
                    .ok_or_else(|| {
                        Error::InvalidPath(
                            "internal error: missing post-create metadata snapshot".to_string(),
                        )
                    })?;
                match handle_existing_component(
                    &next,
                    post_create_meta,
                    next_relative,
                    canonical_root,
                    root_id,
                    !create_missing,
                ) {
                    Ok(canonical) => canonical,
                    Err(err) => {
                        if let (Some(created_meta), Some(parent_ctx)) =
                            (created_meta.as_ref(), parent_ctx.as_ref())
                        {
                            cleanup_created_dir(
                                parent_ctx,
                                &next,
                                next_relative,
                                created_meta,
                                &err,
                            )?;
                        }
                        return Err(err);
                    }
                }
            }
            Err(err) => return Err(Error::io_path("symlink_metadata", next_relative, err)),
        };
        if let Err(err) = reject_secret_canonical_path(
            ctx,
            &resolved_current,
            canonical_root,
            root_id,
            next_relative,
        ) {
            if let (Some(created_meta), Some(parent_ctx)) =
                (created_meta.as_ref(), parent_ctx.as_ref())
            {
                cleanup_created_dir(parent_ctx, &next, next_relative, created_meta, &err)?;
            }
            return Err(err);
        }
        current = resolved_current;
    }

    Ok(current)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::error::Error;

    use super::ensure_rechecked_parent_matches_expected;

    #[test]
    fn rechecked_parent_matches_expected_relative_path() {
        ensure_rechecked_parent_matches_expected(
            Path::new("/root/parent"),
            Path::new("/root"),
            "root",
            Path::new("parent"),
        )
        .expect("rechecked parent should still match expected relative path");
    }

    #[test]
    fn rechecked_parent_rejects_changed_relative_path() {
        let err = ensure_rechecked_parent_matches_expected(
            Path::new("/root/other"),
            Path::new("/root"),
            "root",
            Path::new("parent"),
        )
        .expect_err("rechecked parent should reject a substituted path");
        assert!(
            matches!(err, Error::InvalidPath(message) if message.contains("changed during operation"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn rechecked_parent_is_case_insensitive_on_windows() {
        ensure_rechecked_parent_matches_expected(
            Path::new(r"C:\Root\Parent"),
            Path::new(r"c:\root"),
            "root",
            Path::new("parent"),
        )
        .expect("Windows recheck should preserve case-insensitive parent matches");
    }
}
