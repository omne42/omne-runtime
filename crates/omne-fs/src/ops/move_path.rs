use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

fn revalidate_parent_before_move(
    ctx: &Context,
    root_id: &str,
    requested_parent: &Path,
    expected_parent: &Path,
    expected_parent_meta: &super::io::DirectoryIdentity,
    requested_path: &Path,
    side: &str,
) -> Result<PathBuf> {
    let rechecked_parent = ctx.ensure_dir_under_root(root_id, requested_parent, false)?;
    if !crate::path_utils::paths_equal_case_insensitive(&rechecked_parent, expected_parent) {
        return Err(Error::InvalidPath(format!(
            "{side} path {} changed during move; refusing to continue",
            requested_path.display()
        )));
    }

    expected_parent_meta.verify_best_effort(&rechecked_parent, requested_parent, || {
        Error::InvalidPath(format!(
            "{side} parent identity changed during move; refusing to continue"
        ))
    })?;

    Ok(rechecked_parent)
}

#[cfg(any(unix, windows))]
fn ensure_move_identity_verification_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_move_identity_verification_supported() -> Result<()> {
    Err(Error::InvalidPath(
        "move is unsupported on this platform: cannot verify file identity".to_string(),
    ))
}

fn capture_parent_identity(
    parent: &Path,
    parent_relative: &Path,
    side: &str,
) -> Result<super::io::DirectoryIdentity> {
    super::io::DirectoryIdentity::capture(parent, parent_relative, || {
        Error::InvalidPath(format!(
            "{side} parent path {} is not a directory",
            parent_relative.display()
        ))
    })
}

fn revalidate_source_before_move(
    source: &Path,
    source_relative: &Path,
    expected_source_identity: &super::io::PathIdentity,
) -> Result<()> {
    let current_source_meta = fs::symlink_metadata(source)
        .map_err(|err| Error::io_path("symlink_metadata", source_relative, err))?;
    match expected_source_identity.verify_metadata(&current_source_meta, || {
        Error::InvalidPath("source identity changed during move; refusing to continue".to_string())
    })? {
        super::io::MetadataIdentityCheck::Verified => {}
        super::io::MetadataIdentityCheck::Unverifiable => {
            // Best-effort fallback for filesystems that do not expose stable file IDs.
            // The source path has already been lexically/canonically revalidated.
        }
    }
    Ok(())
}

fn validate_destination_before_move(
    source_identity: &super::io::PathIdentity,
    destination: &Path,
    destination_relative: &Path,
    overwrite: bool,
) -> Result<bool> {
    let destination_meta = match fs::symlink_metadata(destination) {
        Ok(meta) => Some(meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(Error::io_path(
                "symlink_metadata",
                destination_relative,
                err,
            ));
        }
    };

    if let Some(dest_meta) = &destination_meta {
        if matches!(source_identity.matches_metadata(dest_meta), Some(true)) {
            return Ok(true);
        }
        if dest_meta.is_dir() {
            return Err(Error::InvalidPath(
                "destination exists and is a directory".to_string(),
            ));
        }
        if !overwrite {
            return Err(Error::InvalidPath("destination exists".to_string()));
        }
        if source_identity.metadata().is_dir() {
            return Err(Error::InvalidPath(
                "refusing to overwrite an existing destination with a directory".to_string(),
            ));
        }
    }

    Ok(false)
}

fn validate_directory_move_target(source: &Path, destination: &Path) -> Result<()> {
    let normalized_source = crate::path_utils::normalized_for_boundary(source);
    let normalized_destination = crate::path_utils::normalized_for_boundary(destination);
    if normalized_destination.as_ref() != normalized_source.as_ref()
        && crate::path_utils::starts_with_case_insensitive_normalized(
            normalized_destination.as_ref(),
            normalized_source.as_ref(),
        )
    {
        return Err(Error::InvalidPath(
            "refusing to move a directory into its own subdirectory".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MovePathRequest {
    pub root_id: String,
    pub from: PathBuf,
    pub to: PathBuf,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub create_parents: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MovePathResponse {
    pub from: PathBuf,
    pub to: PathBuf,
    pub requested_from: PathBuf,
    pub requested_to: PathBuf,
    pub moved: bool,
    #[serde(rename = "type")]
    pub kind: String,
}

pub fn move_path(ctx: &Context, request: MovePathRequest) -> Result<MovePathResponse> {
    ctx.ensure_write_operation_allowed(&request.root_id, ctx.policy.permissions.move_path, "move")?;
    ensure_move_identity_verification_supported()?;

    let mut paths = super::transfer::resolve_transfer_paths(
        ctx,
        &request.root_id,
        &request.from,
        &request.to,
        request.create_parents,
        "move",
    )?;
    let canonical_root = paths.canonical_root;
    let requested_from = paths.requested_from.clone();
    let requested_to = paths.requested_to.clone();
    let from_name = paths.from_name.clone();
    let to_name: OsString = paths.to_name.clone();
    let from_parent_rel = paths.from_parent_relative.clone();
    let to_parent_rel = paths.to_parent_relative.clone();
    let from_parent = paths.from_parent.clone();
    let from_parent_meta = capture_parent_identity(&from_parent, &from_parent_rel, "source")?;
    let source = paths.source.clone();
    let mut from_relative = paths.from_relative.clone();

    let source_meta = fs::symlink_metadata(&source)
        .map_err(|err| Error::io_path("symlink_metadata", &from_relative, err))?;
    let source_identity = super::io::PathIdentity::from_metadata(source_meta);
    let kind = if source_identity.metadata().file_type().is_file() {
        "file"
    } else if source_identity.metadata().file_type().is_dir() {
        "dir"
    } else if source_identity.metadata().file_type().is_symlink() {
        "symlink"
    } else {
        "other"
    };

    let destination =
        super::transfer::prepare_transfer_destination(ctx, &request.root_id, &mut paths)?;
    let to_parent = destination.parent;
    let to_parent_meta = capture_parent_identity(&to_parent, &to_parent_rel, "destination")?;
    let mut to_relative = destination.relative;
    let destination = destination.path;

    if !crate::path_utils::starts_with_case_insensitive_normalized(&source, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_from,
        });
    }
    if !crate::path_utils::starts_with_case_insensitive_normalized(&destination, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_to,
        });
    }

    if crate::path_utils::paths_equal_case_insensitive_normalized(&source, &destination) {
        return Ok(MovePathResponse {
            from: from_relative,
            to: to_relative,
            requested_from,
            requested_to,
            moved: false,
            kind: kind.to_string(),
        });
    }

    if source_identity.metadata().is_dir() {
        validate_directory_move_target(&source, &destination)?;
    }

    if validate_destination_before_move(
        &source_identity,
        &destination,
        &to_relative,
        request.overwrite,
    )? {
        return Ok(MovePathResponse {
            from: from_relative,
            to: to_relative,
            requested_from,
            requested_to,
            moved: false,
            kind: kind.to_string(),
        });
    }

    let rechecked_from_parent = revalidate_parent_before_move(
        ctx,
        &request.root_id,
        &from_parent_rel,
        &from_parent,
        &from_parent_meta,
        &requested_from,
        "source",
    )?;
    let rechecked_to_parent = revalidate_parent_before_move(
        ctx,
        &request.root_id,
        &to_parent_rel,
        &to_parent,
        &to_parent_meta,
        &requested_to,
        "destination",
    )?;
    let rechecked_from_relative_parent =
        crate::path_utils::strip_prefix_case_insensitive_normalized(
            &rechecked_from_parent,
            canonical_root,
        )
        .ok_or_else(|| Error::OutsideRoot {
            root_id: request.root_id.clone(),
            path: requested_from.clone(),
        })?;
    from_relative = rechecked_from_relative_parent.join(&from_name);
    let rechecked_to_relative_parent = crate::path_utils::strip_prefix_case_insensitive_normalized(
        &rechecked_to_parent,
        canonical_root,
    )
    .ok_or_else(|| Error::OutsideRoot {
        root_id: request.root_id.clone(),
        path: requested_to.clone(),
    })?;
    to_relative = rechecked_to_relative_parent.join(&to_name);
    if ctx.redactor.is_path_denied(&from_relative) {
        return Err(Error::SecretPathDenied(from_relative));
    }
    if ctx.redactor.is_path_denied(&to_relative) {
        return Err(Error::SecretPathDenied(to_relative));
    }
    revalidate_source_before_move(&source, &from_relative, &source_identity)?;
    if validate_destination_before_move(
        &source_identity,
        &destination,
        &to_relative,
        request.overwrite,
    )? {
        return Ok(MovePathResponse {
            from: from_relative,
            to: to_relative,
            requested_from,
            requested_to,
            moved: false,
            kind: kind.to_string(),
        });
    }

    let replace_existing = request.overwrite;
    super::io::rename_replace(&source, &destination, replace_existing).map_err(
        |err| match err {
            super::io::RenameReplaceError::Io(err) => {
                if !replace_existing && super::io::is_destination_exists_rename_error(&err) {
                    return Error::InvalidPath("destination exists".to_string());
                }
                if !replace_existing && err.kind() == std::io::ErrorKind::Unsupported {
                    return Error::InvalidPath(
                        "overwrite=false move is unsupported on this platform".to_string(),
                    );
                }
                let source_missing = matches!(
                    fs::symlink_metadata(&source),
                    Err(source_err) if source_err.kind() == std::io::ErrorKind::NotFound
                );
                if source_missing {
                    return Error::io_path("rename", &from_relative, err);
                }
                let rename_context = PathBuf::from(format!(
                    "{} -> {}",
                    from_relative.display(),
                    to_relative.display()
                ));
                Error::io_path("rename", rename_context, err)
            }
            super::io::RenameReplaceError::CommittedButUnsynced(err) => {
                let rename_context = PathBuf::from(format!(
                    "{} -> {}",
                    from_relative.display(),
                    to_relative.display()
                ));
                Error::committed_but_unsynced("rename", rename_context, err)
            }
        },
    )?;

    Ok(MovePathResponse {
        from: from_relative,
        to: to_relative,
        requested_from,
        requested_to,
        moved: true,
        kind: kind.to_string(),
    })
}
