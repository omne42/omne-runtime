use std::path::{Path, PathBuf};

use omne_fs_primitives::{AdvisoryLockGuard, lock_advisory_file_in_root};

use crate::artifact_download::ArtifactInstallError;

pub(crate) const INSTALL_LOCK_SUFFIX: &str = ".lock";

pub(crate) fn lock_install_destination(
    destination: &Path,
    lock_prefix: &str,
    install_kind: &str,
) -> Result<AdvisoryLockGuard, ArtifactInstallError> {
    let lock_root = destination.parent().unwrap_or_else(|| Path::new("."));
    let lock_file = install_lock_file_name(destination, lock_prefix);
    lock_advisory_file_in_root(
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

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{install_lock_file_name, lock_install_destination};

    #[cfg(unix)]
    #[test]
    fn lock_install_destination_rejects_symlinked_existing_ancestor() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let outside = temp.path().join("outside");
        let linked_parent = temp.path().join("linked-parent");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        symlink(&outside, &linked_parent).expect("create symlink parent");
        let destination = linked_parent.join("tool");
        let lock_file = install_lock_file_name(&destination, ".binary-install-");

        let error = lock_install_destination(&destination, ".binary-install-", "binary install")
            .expect_err("symlinked ancestor should fail");

        assert!(
            error
                .to_string()
                .contains("failed to lock install destination"),
            "unexpected error: {error}"
        );
        assert!(!outside.join(&lock_file).exists());
    }
}
