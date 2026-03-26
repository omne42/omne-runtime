use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::{Context, io::FileIdentity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatRequest {
    pub root_id: String,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatKind {
    File,
    Dir,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatResponse {
    pub path: PathBuf,
    pub requested_path: PathBuf,
    #[serde(rename = "type")]
    pub kind: StatKind,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_ms: Option<u64>,
    pub readonly: bool,
}

fn system_time_to_millis(value: std::time::SystemTime) -> Option<u64> {
    value
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
}

fn metadata_time_to_millis(value: std::io::Result<std::time::SystemTime>) -> Option<u64> {
    value.ok().and_then(system_time_to_millis)
}

fn file_identity_from_path(path: &Path) -> Option<FileIdentity> {
    FileIdentity::from_path(path)
}

fn revalidate_path_stability(
    ctx: &Context,
    request: &StatRequest,
    canonical_path: &Path,
    relative_path: &Path,
    requested_path: &Path,
    expected_identity: FileIdentity,
) -> Result<fs::Metadata> {
    let (rechecked_canonical, rechecked_relative, rechecked_requested) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    if rechecked_canonical != canonical_path
        || rechecked_relative != relative_path
        || rechecked_requested != requested_path
    {
        return Err(Error::InvalidPath(format!(
            "path {} changed during operation",
            relative_path.display()
        )));
    }

    let rechecked_meta = fs::symlink_metadata(canonical_path)
        .map_err(|err| Error::io_path("symlink_metadata", requested_path, err))?;
    if rechecked_meta.file_type().is_symlink() {
        return Err(Error::InvalidPath(format!(
            "path {} changed during operation",
            relative_path.display()
        )));
    }

    match file_identity_from_path(canonical_path) {
        Some(actual_identity) if actual_identity == expected_identity => {}
        Some(_) => {
            return Err(Error::InvalidPath(format!(
                "path {} changed during operation",
                relative_path.display()
            )));
        }
        None => {
            return Err(Error::InvalidPath(format!(
                "cannot verify identity for path {} on this platform",
                relative_path.display()
            )));
        }
    }

    Ok(rechecked_meta)
}

pub fn stat(ctx: &Context, request: StatRequest) -> Result<StatResponse> {
    ctx.ensure_policy_permission(ctx.policy.permissions.stat, "stat")?;

    let (path, relative, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let meta = fs::symlink_metadata(&path)
        .map_err(|err| Error::io_path("symlink_metadata", &requested_path, err))?;
    // This only detects final-component symlink races; it is not full TOCTOU protection.
    if meta.file_type().is_symlink() {
        return Err(Error::InvalidPath(format!(
            "path {} changed during operation",
            relative.display()
        )));
    }

    let expected_identity = file_identity_from_path(&path).ok_or_else(|| {
        Error::InvalidPath(format!(
            "cannot verify identity for path {} on this platform",
            relative.display()
        ))
    })?;

    // Re-resolve after metadata read to narrow the path-rebinding window on parent components.
    let stable_meta = revalidate_path_stability(
        ctx,
        &request,
        &path,
        &relative,
        &requested_path,
        expected_identity,
    )?;

    let kind = if stable_meta.is_file() {
        StatKind::File
    } else if stable_meta.is_dir() {
        StatKind::Dir
    } else {
        StatKind::Other
    };

    let size_bytes = if stable_meta.is_file() {
        stable_meta.len()
    } else {
        0
    };

    // Time fields are best-effort metadata; stat should not fail if a filesystem cannot provide them.
    let modified_ms = metadata_time_to_millis(stable_meta.modified());
    let accessed_ms = metadata_time_to_millis(stable_meta.accessed());
    let created_ms = metadata_time_to_millis(stable_meta.created());
    let readonly = stable_meta.permissions().readonly();

    Ok(StatResponse {
        path: relative,
        requested_path,
        kind,
        size_bytes,
        modified_ms,
        accessed_ms,
        created_ms,
        readonly,
    })
}
