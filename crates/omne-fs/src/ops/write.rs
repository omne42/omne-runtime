use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, PartialEq, Eq)]
struct ParentIdentity(same_file::Handle);

fn parent_identity_from_path(
    canonical_parent: &Path,
    relative_parent: &Path,
) -> Result<ParentIdentity> {
    same_file::Handle::from_path(canonical_parent)
        .map(ParentIdentity)
        .map_err(|_| {
            Error::InvalidPath(format!(
                "cannot verify parent identity for path {} on this filesystem",
                relative_parent.display()
            ))
        })
}

fn capture_parent_identity(
    canonical_parent: &Path,
    relative_parent: &Path,
) -> Result<ParentIdentity> {
    let meta = fs::symlink_metadata(canonical_parent)
        .map_err(|err| Error::io_path("symlink_metadata", relative_parent, err))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "parent path {} changed during operation",
            relative_parent.display()
        )));
    }
    parent_identity_from_path(canonical_parent, relative_parent)
}

struct WriteCommitContext<'ctx> {
    canonical_parent: &'ctx Path,
    relative_parent: &'ctx Path,
    expected_parent_identity: &'ctx ParentIdentity,
    relative: &'ctx Path,
    target: &'ctx Path,
    bytes: &'ctx [u8],
    permissions: Option<fs::Permissions>,
}

fn commit_write<F>(
    context: WriteCommitContext<'_>,
    overwrite: bool,
    map_rename_error: F,
) -> Result<()>
where
    F: FnOnce(super::io::RenameReplaceError) -> Error,
{
    verify_parent_identity(
        context.canonical_parent,
        context.relative_parent,
        context.expected_parent_identity,
    )?;
    let mut tmp_file = super::io::StagedTempFile::new(context.canonical_parent, context.relative)?;
    tmp_file.write_all(context.relative, context.bytes)?;
    if let Some(perms) = &context.permissions {
        tmp_file.set_permissions(context.relative, perms.clone())?;
    }
    // One post-write (and post-permission-copy) sync is sufficient before atomic rename.
    // This avoids an extra flush on overwrite paths without weakening durability behavior.
    tmp_file.sync_all(context.relative)?;
    verify_parent_identity(
        context.canonical_parent,
        context.relative_parent,
        context.expected_parent_identity,
    )?;
    verify_temp_path_identity(&tmp_file, context.relative)?;
    tmp_file.commit_replace(context.target, overwrite, map_rename_error)?;
    Ok(())
}

fn verify_temp_path_identity(tmp_file: &super::io::StagedTempFile, relative: &Path) -> Result<()> {
    match super::io::file_matches_path(tmp_file.as_file(), tmp_file.path()) {
        Some(true) => Ok(()),
        Some(false) => Err(Error::InvalidPath(format!(
            "temporary write file changed during commit for path {}",
            relative.display()
        ))),
        None => Err(Error::InvalidPath(format!(
            "cannot verify temporary write file identity for path {}",
            relative.display()
        ))),
    }
}

fn verify_parent_identity(
    canonical_parent: &Path,
    relative_parent: &Path,
    expected_parent_identity: &ParentIdentity,
) -> Result<()> {
    let current_parent_meta = fs::symlink_metadata(canonical_parent)
        .map_err(|err| Error::io_path("symlink_metadata", relative_parent, err))?;
    if current_parent_meta.file_type().is_symlink() || !current_parent_meta.is_dir() {
        return Err(Error::InvalidPath(format!(
            "parent path {} changed during operation",
            relative_parent.display()
        )));
    }
    let current_parent_identity = parent_identity_from_path(canonical_parent, relative_parent)?;
    if current_parent_identity != *expected_parent_identity {
        return Err(Error::InvalidPath(format!(
            "parent path {} changed during operation",
            relative_parent.display()
        )));
    }
    Ok(())
}

fn ensure_existing_target_writable(target: &Path, relative: &Path) -> Result<fs::Permissions> {
    super::io::ensure_regular_file_writable(target, relative).map(|meta| meta.permissions())
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
pub struct WriteFileRequest {
    pub root_id: String,
    pub path: PathBuf,
    pub content: String,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub create_parents: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriteFileResponse {
    pub path: PathBuf,
    pub requested_path: PathBuf,
    pub bytes_written: u64,
    /// Best-effort preflight observation. Concurrent writers may still turn an
    /// apparent create into a replace before commit.
    pub created: bool,
}

pub fn write_file(ctx: &Context, request: WriteFileRequest) -> Result<WriteFileResponse> {
    ctx.ensure_write_operation_allowed(&request.root_id, ctx.policy.permissions.write, "write")?;

    let resolved =
        super::resolve::resolve_path_in_root_lexically(ctx, &request.root_id, &request.path)?;
    let canonical_root = resolved.canonical_root;
    let requested_path = resolved.requested_path;

    let bytes_written = u64::try_from(request.content.len()).map_err(|_| Error::FileTooLarge {
        path: requested_path.clone(),
        size_bytes: u64::MAX,
        max_bytes: ctx.policy.limits.max_write_bytes,
    })?;
    if bytes_written > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: requested_path,
            size_bytes: bytes_written,
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    let file_name = super::path_validation::ensure_non_root_leaf(
        &requested_path,
        &request.path,
        super::path_validation::LeafOp::Write,
    )?;

    let requested_parent = requested_path.parent().unwrap_or_else(|| Path::new(""));
    let requested_relative = requested_parent.join(file_name);
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
                .ok_or_else(|| {
                    Error::InvalidPath("failed to preview parent directory".to_string())
                })?
            }
            Err(err) => return Err(err),
        };
    let preview_relative = preview_relative_parent.join(file_name);
    if ctx.redactor.is_path_denied(&preview_relative) {
        return Err(Error::SecretPathDenied(preview_relative));
    }

    let canonical_parent =
        ctx.ensure_dir_under_root(&request.root_id, requested_parent, request.create_parents)?;

    let relative_parent = crate::path_utils::strip_prefix_case_insensitive_normalized(
        &canonical_parent,
        canonical_root,
    )
    .ok_or_else(|| Error::OutsideRoot {
        root_id: request.root_id.clone(),
        path: requested_path.clone(),
    })?;
    let parent_identity = capture_parent_identity(&canonical_parent, &relative_parent)?;
    let relative = relative_parent.join(file_name);

    let target = canonical_parent.join(file_name);
    if !crate::path_utils::starts_with_case_insensitive_normalized(&target, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_path,
        });
    }

    let existing = match fs::symlink_metadata(&target) {
        Ok(meta) => Some(meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(Error::io_path("metadata", &relative, err)),
    };

    if let Some(meta) = existing {
        let file_type = meta.file_type();
        if file_type.is_dir() {
            return Err(Error::InvalidPath(
                "destination exists and is a directory".to_string(),
            ));
        }
        if file_type.is_symlink() {
            return Err(Error::InvalidPath(format!(
                "path {} is a symlink",
                relative.display()
            )));
        }
        if !file_type.is_file() {
            return Err(Error::InvalidPath(
                "destination exists and is not a regular file".to_string(),
            ));
        }

        if !request.overwrite {
            return Err(Error::InvalidPath("file exists".to_string()));
        }
        let permissions = ensure_existing_target_writable(&target, &relative)?;

        let commit_context = WriteCommitContext {
            canonical_parent: &canonical_parent,
            relative_parent: &relative_parent,
            expected_parent_identity: &parent_identity,
            relative: &relative,
            target: &target,
            bytes: request.content.as_bytes(),
            permissions: Some(permissions),
        };
        commit_write(commit_context, true, |err| match err {
            super::io::RenameReplaceError::Io(err) => Error::io_path("rename", &relative, err),
            super::io::RenameReplaceError::CommittedButUnsynced(err) => {
                Error::committed_but_unsynced("rename", &relative, err)
            }
        })?;
        return Ok(WriteFileResponse {
            path: relative,
            requested_path,
            bytes_written,
            created: false,
        });
    }

    let commit_context = WriteCommitContext {
        canonical_parent: &canonical_parent,
        relative_parent: &relative_parent,
        expected_parent_identity: &parent_identity,
        relative: &relative,
        target: &target,
        bytes: request.content.as_bytes(),
        permissions: None,
    };
    commit_write(commit_context, request.overwrite, |err| match err {
        super::io::RenameReplaceError::Io(err) => {
            if !request.overwrite && super::io::is_destination_exists_rename_error(&err) {
                return Error::InvalidPath("file exists".to_string());
            }
            if err.kind() == std::io::ErrorKind::Unsupported && !request.overwrite {
                return Error::InvalidPath(
                    "create without overwrite is unsupported on this platform".to_string(),
                );
            }
            Error::io_path("rename", &relative, err)
        }
        super::io::RenameReplaceError::CommittedButUnsynced(err) => {
            Error::committed_but_unsynced("rename", &relative, err)
        }
    })?;

    Ok(WriteFileResponse {
        path: relative,
        requested_path,
        bytes_written,
        created: true,
    })
}
