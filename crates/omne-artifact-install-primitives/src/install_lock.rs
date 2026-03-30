use std::path::{Path, PathBuf};

use omne_fs_primitives::{AdvisoryLockGuard, lock_advisory_file_in_ambient_root};

use crate::artifact_download::ArtifactInstallError;

pub(crate) const INSTALL_LOCK_SUFFIX: &str = ".lock";

pub(crate) fn lock_install_destination(
    destination: &Path,
    lock_prefix: &str,
    install_kind: &str,
) -> Result<AdvisoryLockGuard, ArtifactInstallError> {
    let lock_root = destination.parent().unwrap_or_else(|| Path::new("."));
    let lock_file = install_lock_file_name(destination, lock_prefix);
    lock_advisory_file_in_ambient_root(
        lock_root,
        install_kind,
        &lock_file,
        "artifact install lock file",
    )
    .map_err(|err| {
        ArtifactInstallError::install(format!(
            "failed to lock install destination `{}`: {err}",
            destination.display()
        ))
    })
}

pub(crate) fn install_lock_file_name(destination: &Path, lock_prefix: &str) -> PathBuf {
    let label = destination
        .file_name()
        .map(|name| sanitize_lock_component(&name.to_string_lossy()))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "artifact".to_string());
    PathBuf::from(format!("{lock_prefix}{label}{INSTALL_LOCK_SUFFIX}"))
}

pub(crate) fn sanitize_lock_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => ch,
            _ => '_',
        })
        .collect()
}
