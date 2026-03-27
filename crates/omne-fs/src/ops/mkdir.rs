use std::fs;
use std::path::Path;
use std::path::PathBuf;

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
    let current_parent_meta = fs::symlink_metadata(canonical_parent)
        .map_err(|err| Error::io_path("symlink_metadata", relative_parent, err))?;
    match expected_parent_meta.verify_metadata(&current_parent_meta, || {
        Error::InvalidPath(format!(
            "parent path {} changed during operation",
            relative_parent.display()
        ))
    })? {
        super::io::MetadataIdentityCheck::Verified => Ok(()),
        super::io::MetadataIdentityCheck::Unverifiable => Err(Error::InvalidPath(format!(
            "parent path {} identity could not be verified during operation",
            relative_parent.display()
        ))),
    }
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
    let current_target_meta = fs::symlink_metadata(target)
        .map_err(|err| Error::io_path("symlink_metadata", relative, err))?;
    match created_target_meta.verify_metadata(&current_target_meta, || {
        Error::InvalidPath(format!(
            "path {} changed before cleanup",
            relative.display()
        ))
    })? {
        super::io::MetadataIdentityCheck::Verified => {}
        super::io::MetadataIdentityCheck::Unverifiable => {
            return Err(Error::InvalidPath(format!(
                "path {} identity unavailable before cleanup",
                relative.display()
            )));
        }
    }
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

    if ctx.redactor.is_path_denied(&relative) {
        return Err(Error::SecretPathDenied(relative));
    }

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
}
