use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyFileRequest {
    pub root_id: String,
    pub from: PathBuf,
    pub to: PathBuf,
    #[serde(default)]
    pub overwrite: bool,
    #[serde(default)]
    pub create_parents: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopyFileResponse {
    pub from: PathBuf,
    pub to: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_from: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_to: Option<PathBuf>,
    pub copied: bool,
    pub bytes: u64,
}

struct TempCopy {
    staged: super::io::StagedTempFile,
    bytes: u64,
}

pub fn copy_file(ctx: &Context, request: CopyFileRequest) -> Result<CopyFileResponse> {
    ctx.ensure_write_operation_allowed(
        &request.root_id,
        ctx.policy.permissions.copy_file,
        "copy_file",
    )?;
    let mut paths = super::transfer::resolve_transfer_paths(
        ctx,
        &request.root_id,
        &request.from,
        &request.to,
        request.create_parents,
        "copy",
    )?;

    let (mut input, source_meta) =
        super::io::open_regular_file_for_read(&paths.source, &paths.from_relative)?;
    let source_identity = super::io::PathIdentity::from_metadata(source_meta);

    ensure_destination_parent_identity_verification_supported()?;
    let destination =
        super::transfer::prepare_transfer_destination(ctx, &request.root_id, &mut paths)?;
    if crate::path_utils::paths_equal_case_insensitive_normalized(&paths.source, &destination.path)
    {
        return Ok(noop_response(
            paths.from_relative,
            destination.relative,
            paths.requested_from,
            paths.requested_to,
        ));
    }

    let destination_meta = match fs::symlink_metadata(&destination.path) {
        Ok(meta) => Some(meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(Error::io_path("metadata", &destination.relative, err));
        }
    };
    if let Some(meta) = &destination_meta {
        if matches!(source_identity.matches_metadata(meta), Some(true)) {
            return Ok(noop_response(
                paths.from_relative,
                destination.relative,
                paths.requested_from,
                paths.requested_to,
            ));
        }
        if source_identity.metadata().len() > ctx.policy.limits.max_write_bytes {
            return Err(Error::FileTooLarge {
                path: paths.from_relative.clone(),
                size_bytes: source_identity.metadata().len(),
                max_bytes: ctx.policy.limits.max_write_bytes,
            });
        }
        if meta.is_dir() {
            return Err(Error::InvalidPath(
                "destination exists and is a directory".to_string(),
            ));
        }
        if !meta.is_file() {
            return Err(Error::InvalidPath(
                "destination exists and is not a regular file".to_string(),
            ));
        }
        if !request.overwrite {
            return Err(Error::InvalidPath("destination exists".to_string()));
        }
    } else if source_identity.metadata().len() > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: paths.from_relative.clone(),
            size_bytes: source_identity.metadata().len(),
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    let destination_parent_meta =
        capture_destination_parent_identity(&destination.parent, &destination.relative)?;
    verify_destination_parent_identity(
        &destination.parent,
        &destination_parent_meta,
        &destination.relative,
    )?;
    let temp_copy = copy_to_temp(
        &mut input,
        &destination.parent,
        &destination_parent_meta,
        &paths.from_relative,
        &destination.relative,
        ctx.policy.limits.max_write_bytes,
    )?;
    let bytes = temp_copy.bytes;
    commit_replace(
        temp_copy,
        &destination.path,
        &destination.parent,
        &destination_parent_meta,
        &destination.relative,
        request.overwrite,
        source_identity.metadata(),
    )?;

    Ok(CopyFileResponse {
        from: paths.from_relative,
        to: destination.relative,
        requested_from: Some(paths.requested_from),
        requested_to: Some(paths.requested_to),
        copied: true,
        bytes,
    })
}

fn copy_to_temp(
    input: &mut fs::File,
    destination_parent: &Path,
    expected_parent_meta: &super::io::DirectoryIdentity,
    from_relative: &Path,
    to_effective_relative: &Path,
    max_write_bytes: u64,
) -> Result<TempCopy> {
    let mut staged = super::io::StagedTempFile::new(destination_parent, to_effective_relative)?;
    verify_destination_parent_identity(
        destination_parent,
        expected_parent_meta,
        to_effective_relative,
    )?;

    let limit = max_write_bytes.saturating_add(1);
    let bytes = std::io::copy(&mut input.take(limit), staged.as_file_mut())
        .map_err(|err| Error::io_path("copy", to_effective_relative, err))?;
    if bytes > max_write_bytes {
        return Err(Error::FileTooLarge {
            path: from_relative.to_path_buf(),
            size_bytes: bytes,
            max_bytes: max_write_bytes,
        });
    }

    Ok(TempCopy { staged, bytes })
}

fn commit_replace(
    temp_copy: TempCopy,
    destination: &Path,
    destination_parent: &Path,
    expected_parent_meta: &super::io::DirectoryIdentity,
    to_effective_relative: &Path,
    overwrite: bool,
    source_meta: &fs::Metadata,
) -> Result<()> {
    let mut staged = temp_copy.staged;
    staged.set_permissions(to_effective_relative, source_meta.permissions())?;
    staged.sync_all(to_effective_relative)?;

    verify_destination_parent_identity(
        destination_parent,
        expected_parent_meta,
        to_effective_relative,
    )?;
    verify_temp_path_identity(staged.as_file(), staged.path(), to_effective_relative)?;
    staged.commit_replace(destination, overwrite, |err| match err {
        super::io::RenameReplaceError::Io(err) => {
            if !overwrite && super::io::is_destination_exists_rename_error(&err) {
                return Error::InvalidPath("destination exists".to_string());
            }
            if !overwrite && err.kind() == std::io::ErrorKind::Unsupported {
                return Error::InvalidPath(
                    "overwrite=false copy is unsupported on this platform".to_string(),
                );
            }
            Error::io_path("rename", to_effective_relative, err)
        }
        super::io::RenameReplaceError::CommittedButUnsynced(err) => {
            Error::committed_but_unsynced("rename", to_effective_relative, err)
        }
    })?;
    Ok(())
}

fn temp_path_changed_error(to_effective_relative: &Path) -> Error {
    Error::InvalidPath(format!(
        "temporary copy file changed during commit for path {}",
        to_effective_relative.display()
    ))
}

fn verify_temp_path_identity(
    temp_file: &fs::File,
    temp_path: &Path,
    to_effective_relative: &Path,
) -> Result<()> {
    let temp_path_meta = fs::symlink_metadata(temp_path)
        .map_err(|err| Error::io_path("symlink_metadata", to_effective_relative, err))?;
    if !temp_path_meta.is_file() {
        return Err(temp_path_changed_error(to_effective_relative));
    }
    match super::io::file_matches_path(temp_file, temp_path) {
        Some(true) => Ok(()),
        Some(false) => Err(temp_path_changed_error(to_effective_relative)),
        None => Err(Error::InvalidPath(format!(
            "cannot verify temporary copy file identity for path {}",
            to_effective_relative.display()
        ))),
    }
}

#[cfg(any(unix, windows))]
fn ensure_destination_parent_identity_verification_supported() -> Result<()> {
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn ensure_destination_parent_identity_verification_supported() -> Result<()> {
    Err(Error::InvalidPath(
        "copy_file is unsupported on this platform: cannot verify destination parent identity"
            .to_string(),
    ))
}

fn capture_destination_parent_identity(
    destination_parent: &Path,
    to_effective_relative: &Path,
) -> Result<super::io::DirectoryIdentity> {
    super::io::DirectoryIdentity::capture(destination_parent, to_effective_relative, || {
        Error::InvalidPath("destination parent directory is not a directory".to_string())
    })
}

fn verify_destination_parent_identity(
    destination_parent: &Path,
    expected_parent_meta: &super::io::DirectoryIdentity,
    to_effective_relative: &Path,
) -> Result<()> {
    expected_parent_meta.verify_best_effort(destination_parent, to_effective_relative, || {
        Error::InvalidPath("destination parent directory changed during copy".to_string())
    })
}

fn noop_response(
    from: PathBuf,
    to: PathBuf,
    requested_from: PathBuf,
    requested_to: PathBuf,
) -> CopyFileResponse {
    CopyFileResponse {
        from,
        to,
        requested_from: Some(requested_from),
        requested_to: Some(requested_to),
        copied: false,
        bytes: 0,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::Path;

    use super::verify_temp_path_identity;
    use crate::error::Error;

    #[test]
    fn temp_path_identity_check_detects_replaced_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let tmp = tempfile::Builder::new()
            .prefix(".omne-fs.")
            .suffix(".tmp")
            .tempfile_in(dir.path())
            .expect("create temp file");
        let (file, path) = tmp.into_parts();
        let temp_path = path.to_path_buf();

        std::fs::remove_file(&temp_path).expect("unlink temp path");
        std::fs::write(&temp_path, b"replacement").expect("write replacement");

        let err = verify_temp_path_identity(&file, &temp_path, Path::new("dst.txt"))
            .expect_err("replaced temp path must be rejected");
        match err {
            Error::InvalidPath(msg) => assert!(msg.contains("temporary copy file changed")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
