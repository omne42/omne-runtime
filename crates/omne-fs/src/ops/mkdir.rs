use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

fn ensure_target_dir_within_root(
    root_id: &str,
    canonical_root: &Path,
    target: &Path,
    relative: &Path,
    requested_path: &Path,
) -> Result<()> {
    let canonical_target = target
        .canonicalize()
        .map_err(|err| Error::io_path("canonicalize", relative, err))?;
    if !crate::path_utils::starts_with_case_insensitive(&canonical_target, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: root_id.to_string(),
            path: requested_path.to_path_buf(),
        });
    }
    Ok(())
}

fn ensure_parent_dir_unchanged(
    canonical_parent: &Path,
    relative_parent: &Path,
    expected_parent_meta: &super::io::DirectoryIdentity,
) -> Result<()> {
    expected_parent_meta.ensure_verified(
        canonical_parent,
        relative_parent,
        || {
            Error::InvalidPath(format!(
                "parent path {} changed during operation",
                relative_parent.display()
            ))
        },
        || {
            Error::InvalidPath(format!(
                "parent path {} identity could not be verified during operation",
                relative_parent.display()
            ))
        },
    )
}

fn ensure_created_target_dir_unchanged(
    target: &Path,
    relative: &Path,
    created_target_meta: &super::io::DirectoryIdentity,
) -> Result<()> {
    created_target_meta.ensure_verified(
        target,
        relative,
        || {
            Error::InvalidPath(format!(
                "path {} changed before cleanup",
                relative.display()
            ))
        },
        || {
            Error::InvalidPath(format!(
                "path {} identity unavailable before cleanup",
                relative.display()
            ))
        },
    )
}

fn cleanup_created_target_dir(
    canonical_parent: &Path,
    relative_parent: &Path,
    expected_parent_meta: &super::io::DirectoryIdentity,
    target: &Path,
    relative: &Path,
    created_target_meta: &super::io::DirectoryIdentity,
    validation_err: &Error,
) -> Result<()> {
    ensure_parent_dir_unchanged(canonical_parent, relative_parent, expected_parent_meta)?;
    ensure_created_target_dir_unchanged(target, relative, created_target_meta)?;
    fs::remove_dir(target).map_err(|cleanup_err| {
        let cleanup_context = std::io::Error::new(
            cleanup_err.kind(),
            format!(
                "mkdir post-create validation failed ({validation_err}); cleanup failed: {cleanup_err}"
            ),
        );
        Error::io_path("remove_dir", relative, cleanup_context)
    })
}

struct MkdirPathContext<'a> {
    canonical_parent: &'a Path,
    relative_parent: &'a Path,
    expected_parent_meta: &'a super::io::DirectoryIdentity,
    root_id: &'a str,
    canonical_root: &'a Path,
    target: &'a Path,
    relative: &'a Path,
    requested_path: &'a Path,
}

fn handle_existing_target_dir(
    context: &MkdirPathContext<'_>,
    existing_meta: &fs::Metadata,
    ignore_existing: bool,
) -> Result<MkdirResponse> {
    if existing_meta.file_type().is_symlink() {
        return Err(Error::InvalidPath(
            "refusing to create directory through symlink".to_string(),
        ));
    }
    if existing_meta.is_dir() {
        ensure_parent_dir_unchanged(
            context.canonical_parent,
            context.relative_parent,
            context.expected_parent_meta,
        )?;
        ensure_target_dir_within_root(
            context.root_id,
            context.canonical_root,
            context.target,
            context.relative,
            context.requested_path,
        )?;
        if ignore_existing {
            return Ok(MkdirResponse {
                path: context.relative.to_path_buf(),
                requested_path: context.requested_path.to_path_buf(),
                created: false,
            });
        }
        return Err(Error::InvalidPath("directory exists".to_string()));
    }
    Err(Error::InvalidPath(
        "path exists and is not a directory".to_string(),
    ))
}

fn preview_parent_dir_under_root(
    ctx: &Context,
    root_id: &str,
    requested_parent: &Path,
    canonical_root: &Path,
) -> Result<Option<PathBuf>> {
    let mut current = canonical_root.to_path_buf();
    let mut current_relative = PathBuf::new();
    let mut components = requested_parent.components().peekable();
    while let Some(component) = components.next() {
        let segment = match component {
            Component::CurDir => continue,
            Component::Normal(segment) => segment,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(Error::InvalidPath(format!(
                    "invalid path {}: unsupported parent directory reference",
                    requested_parent.display()
                )));
            }
        };
        current_relative.push(segment);
        let next = current.join(segment);
        match fs::symlink_metadata(&next) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || meta.is_dir() {
                    current = next
                        .canonicalize()
                        .map_err(|err| Error::io_path("canonicalize", &current_relative, err))?;
                    if !crate::path_utils::starts_with_case_insensitive_normalized(
                        &current,
                        canonical_root,
                    ) {
                        return Err(Error::OutsideRoot {
                            root_id: root_id.to_string(),
                            path: requested_parent.to_path_buf(),
                        });
                    }
                    let canonical_relative =
                        crate::path_utils::strip_prefix_case_insensitive_normalized(
                            &current,
                            canonical_root,
                        )
                        .ok_or_else(|| {
                            Error::InvalidPath(format!(
                                "failed to derive canonical parent path for {}",
                                requested_parent.display()
                            ))
                        })?;
                    ctx.reject_secret_path(canonical_relative)?;
                    continue;
                }
                return Err(Error::InvalidPath(format!(
                    "path component {} is not a directory",
                    current_relative.display()
                )));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                current.push(segment);
                for remaining in components {
                    if let Component::Normal(remaining) = remaining {
                        current.push(remaining);
                    }
                }
                let relative_parent = crate::path_utils::strip_prefix_case_insensitive_normalized(
                    &current,
                    canonical_root,
                )
                .ok_or_else(|| Error::OutsideRoot {
                    root_id: root_id.to_string(),
                    path: requested_parent.to_path_buf(),
                })?;
                return Ok(Some(relative_parent));
            }
            Err(err) => return Err(Error::io_path("symlink_metadata", &current_relative, err)),
        }
    }

    let relative_parent =
        crate::path_utils::strip_prefix_case_insensitive_normalized(&current, canonical_root)
            .ok_or_else(|| Error::OutsideRoot {
                root_id: root_id.to_string(),
                path: requested_parent.to_path_buf(),
            })?;
    Ok(Some(relative_parent))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MkdirRequest {
    pub root_id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub create_parents: bool,
    #[serde(default)]
    pub ignore_existing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MkdirResponse {
    pub path: PathBuf,
    pub requested_path: PathBuf,
    pub created: bool,
}

pub fn mkdir(ctx: &Context, request: MkdirRequest) -> Result<MkdirResponse> {
    ctx.ensure_write_operation_allowed(&request.root_id, ctx.policy.permissions.mkdir, "mkdir")?;

    let resolved =
        super::resolve::resolve_path_in_root_lexically(ctx, &request.root_id, &request.path)?;
    let canonical_root = resolved.canonical_root;
    let requested_path = resolved.requested_path;

    let dir_name = super::path_validation::ensure_non_root_leaf(
        &requested_path,
        &request.path,
        super::path_validation::LeafOp::Mkdir,
    )?;

    let requested_parent = requested_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""));
    let requested_relative = requested_parent.join(dir_name);
    if ctx.redactor.is_path_denied(&requested_relative) {
        return Err(Error::SecretPathDenied(requested_relative));
    }

    let preview_relative_parent =
        match ctx.ensure_dir_under_root(&request.root_id, requested_parent, false) {
            Ok(canonical_parent) => crate::path_utils::strip_prefix_case_insensitive_normalized(
                &canonical_parent,
                canonical_root,
            )
            .ok_or_else(|| Error::OutsideRoot {
                root_id: request.root_id.clone(),
                path: requested_path.clone(),
            })?,
            Err(Error::IoPath { source, .. })
                if request.create_parents && source.kind() == std::io::ErrorKind::NotFound =>
            {
                preview_parent_dir_under_root(
                    ctx,
                    &request.root_id,
                    requested_parent,
                    canonical_root,
                )?
                .ok_or_else(|| Error::InvalidPath("failed to preview parent directory".to_string()))?
            }
            Err(err) => return Err(err),
        };
    let preview_relative = preview_relative_parent.join(dir_name);
    if ctx.redactor.is_path_denied(&preview_relative) {
        return Err(Error::SecretPathDenied(preview_relative));
    }

    let canonical_parent =
        ctx.ensure_dir_under_root(&request.root_id, requested_parent, request.create_parents)?;

    if !crate::path_utils::starts_with_case_insensitive_normalized(
        &canonical_parent,
        canonical_root,
    ) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

    let relative_parent = crate::path_utils::strip_prefix_case_insensitive_normalized(
        &canonical_parent,
        canonical_root,
    )
    .ok_or_else(|| Error::OutsideRoot {
        root_id: request.root_id.clone(),
        path: requested_path.clone(),
    })?;
    let canonical_parent_meta =
        super::io::DirectoryIdentity::capture(&canonical_parent, &relative_parent, || {
            Error::InvalidPath(format!(
                "parent path {} changed during operation",
                relative_parent.display()
            ))
        })?;
    let relative = relative_parent.join(dir_name);

    let target = canonical_parent.join(dir_name);
    if !crate::path_utils::starts_with_case_insensitive_normalized(&target, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

    ensure_parent_dir_unchanged(&canonical_parent, &relative_parent, &canonical_parent_meta)?;
    let path_context = MkdirPathContext {
        canonical_parent: &canonical_parent,
        relative_parent: &relative_parent,
        expected_parent_meta: &canonical_parent_meta,
        root_id: &request.root_id,
        canonical_root,
        target: &target,
        relative: &relative,
        requested_path: &requested_path,
    };

    match fs::symlink_metadata(&target) {
        Ok(meta) => handle_existing_target_dir(&path_context, &meta, request.ignore_existing),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            ensure_parent_dir_unchanged(
                &canonical_parent,
                &relative_parent,
                &canonical_parent_meta,
            )?;
            if let Err(err) = fs::create_dir(&target) {
                if err.kind() == std::io::ErrorKind::AlreadyExists {
                    ensure_parent_dir_unchanged(
                        &canonical_parent,
                        &relative_parent,
                        &canonical_parent_meta,
                    )?;
                    let existing = fs::symlink_metadata(&target).map_err(|meta_err| {
                        Error::io_path("symlink_metadata", &relative, meta_err)
                    })?;
                    return handle_existing_target_dir(
                        &path_context,
                        &existing,
                        request.ignore_existing,
                    );
                }
                return Err(Error::io_path("create_dir", &relative, err));
            }
            ensure_parent_dir_unchanged(
                &canonical_parent,
                &relative_parent,
                &canonical_parent_meta,
            )?;
            let created_target_meta =
                super::io::DirectoryIdentity::capture(&target, &relative, || {
                    Error::InvalidPath(format!(
                        "path {} changed during operation",
                        relative.display()
                    ))
                })?;
            if let Err(validation_err) = ensure_target_dir_within_root(
                &request.root_id,
                canonical_root,
                &target,
                &relative,
                &requested_path,
            ) {
                cleanup_created_target_dir(
                    &canonical_parent,
                    &relative_parent,
                    &canonical_parent_meta,
                    &target,
                    &relative,
                    &created_target_meta,
                    &validation_err,
                )?;
                return Err(validation_err);
            }
            Ok(MkdirResponse {
                path: relative,
                requested_path,
                created: true,
            })
        }
        Err(err) => Err(Error::io_path("symlink_metadata", &relative, err)),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::ensure_parent_dir_unchanged;
    use crate::error::Error;

    #[test]
    fn parent_identity_must_fail_closed_when_verification_is_unavailable() {
        let dir = tempdir().expect("tempdir");
        let parent = dir.path().join("parent");
        std::fs::create_dir(&parent).expect("create parent");
        let metadata = std::fs::symlink_metadata(&parent).expect("parent metadata");
        let identity = super::super::io::DirectoryIdentity::unverifiable_for_tests(metadata);

        let err = ensure_parent_dir_unchanged(&parent, std::path::Path::new("parent"), &identity)
            .expect_err("unverifiable parent identity must fail closed");
        assert!(
            matches!(err, Error::InvalidPath(message) if message.contains("identity could not be verified"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn parent_identity_verification_uses_directory_handle_when_available() {
        let dir = tempdir().expect("tempdir");
        let metadata = std::fs::symlink_metadata(dir.path()).expect("parent metadata");
        let identity =
            super::super::io::DirectoryIdentity::from_metadata(dir.path(), metadata, || {
                Error::InvalidPath("not a directory".to_string())
            })
            .expect("identity");

        ensure_parent_dir_unchanged(dir.path(), std::path::Path::new(""), &identity)
            .expect("handle-backed identity verification should succeed");
    }
}
