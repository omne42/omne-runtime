use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

mod dir_ops;

pub(super) fn derive_requested_path(
    root_id: &str,
    root_path: &Path,
    canonical_root: &Path,
    resolved: &Path,
) -> Result<PathBuf> {
    let normalized_resolved = crate::path_utils::normalized_for_boundary(resolved);
    let normalized_root_path = crate::path_utils::normalized_for_boundary(root_path);
    let normalized_canonical_root = crate::path_utils::normalized_for_boundary(canonical_root);

    let relative_requested = crate::path_utils::strip_prefix_case_insensitive_normalized(
        normalized_resolved.as_ref(),
        normalized_root_path.as_ref(),
    )
    .or_else(|| {
        crate::path_utils::strip_prefix_case_insensitive_normalized(
            normalized_resolved.as_ref(),
            normalized_canonical_root.as_ref(),
        )
    })
    .ok_or_else(|| outside_root_error(root_id, normalized_resolved.as_ref()))?;

    // `relative_requested` comes from stripping a normalized prefix from a normalized path, so
    // it is already lexically normalized. Only map empty path to "." for API stability.
    if relative_requested.as_os_str().is_empty() {
        Ok(PathBuf::from("."))
    } else {
        Ok(relative_requested)
    }
}

pub(super) struct ResolvedPath<'ctx> {
    pub(super) resolved: PathBuf,
    pub(super) requested_path: PathBuf,
    pub(super) canonical_root: &'ctx Path,
}

fn outside_root_error(root_id: &str, requested_path: &Path) -> Error {
    Error::OutsideRoot {
        root_id: root_id.to_string(),
        path: requested_path.to_path_buf(),
    }
}

// INVARIANT:
// - `requested_path` must be root-relative and already lexically normalized.
// - Absolute paths, prefixes, or parent traversal are rejected as `OutsideRoot`.
fn classify_notfound_escape(
    root_id: &str,
    canonical_root: &Path,
    requested_path: &Path,
) -> Result<()> {
    let mut current = canonical_root.to_path_buf();
    let mut traversed_relative = PathBuf::new();
    for component in requested_path.components() {
        let segment = match component {
            Component::CurDir => continue,
            Component::Normal(segment) => segment,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(outside_root_error(root_id, requested_path));
            }
        };

        traversed_relative.push(segment);
        current.push(segment);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(Error::io_path("symlink_metadata", &traversed_relative, err)),
        };

        if metadata.file_type().is_symlink() {
            let symlink_target = fs::read_link(&current)
                .map_err(|err| Error::io_path("read_link", &traversed_relative, err))?;
            let resolved_target = if symlink_target.is_absolute() {
                symlink_target
            } else {
                current
                    .parent()
                    .unwrap_or(current.as_path())
                    .join(symlink_target)
            };
            let resolved_target =
                crate::path_utils_internal::normalize_path_lexical(&resolved_target);
            if !crate::path_utils::starts_with_case_insensitive_normalized(
                &resolved_target,
                canonical_root,
            ) {
                return Err(outside_root_error(root_id, requested_path));
            }

            current = match resolved_target.canonicalize() {
                Ok(canonical) => canonical,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(err) => return Err(Error::io_path("canonicalize", &traversed_relative, err)),
            };
            if !crate::path_utils::starts_with_case_insensitive_normalized(&current, canonical_root)
            {
                return Err(outside_root_error(root_id, requested_path));
            }
        }
    }

    Ok(())
}

// IMPORTANT DESIGN NOTE:
//
// This module uses lexical + canonical-path checks over path strings and canonicalization, not a
// full directory-fd descriptor chain (`openat`/capability walk).
//
// We intentionally keep this local-first model because `omne-fs` targets local usage and
// policy-layer enforcement with manageable cross-platform complexity. A full descriptor-chain
// confinement model is stronger against TOCTOU but is currently outside this crate's hard
// guarantees and maintenance envelope.
//
// Therefore:
// - treat these checks as best-effort root-bounded validation,
// - do not interpret them as OS-sandbox-equivalent confinement,
// - use OS sandboxing/containerization for adversarial local-process threat models.
pub(super) fn resolve_path_in_root_lexically<'ctx>(
    ctx: &'ctx super::Context,
    root_id: &str,
    path: &Path,
) -> Result<ResolvedPath<'ctx>> {
    let resolved = ctx.policy.resolve_path_checked(root_id, path)?;
    let declared_root = ctx.declared_root(root_id)?;
    let canonical_root = ctx.canonical_root(root_id)?;
    let requested_path = derive_requested_path(root_id, declared_root, canonical_root, &resolved)
        .map_err(|err| match err {
        Error::OutsideRoot { .. } => {
            let normalized_requested = crate::path_utils_internal::normalize_path_lexical(path);
            outside_root_error(root_id, &normalized_requested)
        }
        other => other,
    })?;
    let requested_path = ctx.reject_secret_path(requested_path)?;

    Ok(ResolvedPath {
        resolved,
        requested_path,
        canonical_root,
    })
}

impl super::Context {
    // NOTE: Same design constraints as above apply. This function is intentionally path-based for
    // local-first ergonomics; it is not a full descriptor-chain confinement primitive.
    pub(super) fn canonical_path_in_root(
        &self,
        root_id: &str,
        path: &Path,
    ) -> Result<(PathBuf, PathBuf, PathBuf)> {
        let ResolvedPath {
            resolved,
            requested_path,
            canonical_root,
        } = resolve_path_in_root_lexically(self, root_id, path)?;

        // `resolve_path_checked` is lexical-only. We still must canonicalize here to resolve
        // symlinks against filesystem state before enforcing canonical root boundaries.
        let canonical = match resolved.canonicalize() {
            Ok(canonical) => canonical,
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    classify_notfound_escape(root_id, canonical_root, &requested_path)?;
                } else {
                    // Keep OutsideRoot highest-priority, but preserve non-escape diagnostics.
                    match classify_notfound_escape(root_id, canonical_root, &requested_path) {
                        Err(classified @ Error::OutsideRoot { .. }) => return Err(classified),
                        Err(_) => {}
                        Ok(()) => {}
                    }
                }
                return Err(Error::io_path("canonicalize", requested_path, err));
            }
        };
        if !crate::path_utils::starts_with_case_insensitive_normalized(&canonical, canonical_root) {
            return Err(Error::OutsideRoot {
                root_id: root_id.to_string(),
                path: requested_path,
            });
        }
        let relative =
            crate::path_utils::strip_prefix_case_insensitive_normalized(&canonical, canonical_root)
                .ok_or_else(|| {
                    Error::InvalidPath(format!(
                        "failed to derive root-relative path from canonical target {}",
                        canonical.display()
                    ))
                })?;
        let relative = if relative.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            relative
        };
        let relative = self.reject_secret_path(relative)?;
        Ok((canonical, relative, requested_path))
    }

    pub(super) fn ensure_dir_under_root(
        &self,
        root_id: &str,
        relative: &Path,
        create_missing: bool,
    ) -> Result<PathBuf> {
        dir_ops::ensure_dir_under_root(self, root_id, relative, create_missing)
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::classify_notfound_escape;
    #[cfg(unix)]
    use crate::error::Error;

    #[test]
    fn classify_notfound_escape_allows_missing_descendant_inside_root() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(root.path().join("nested")).expect("create nested dir");
        let canonical_root = root.path().canonicalize().expect("canonical root");

        let result =
            classify_notfound_escape("root", &canonical_root, Path::new("nested/missing.txt"));
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn classify_notfound_escape_rejects_symlink_escape_before_missing_tail() {
        let root = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape"))
            .expect("create symlink");
        let canonical_root = root.path().canonicalize().expect("canonical root");

        let err =
            classify_notfound_escape("root", &canonical_root, Path::new("escape/missing.txt"))
                .expect_err("should reject outside-root escape");
        assert!(
            matches!(err, Error::OutsideRoot { .. }),
            "unexpected error: {err:?}"
        );
    }
}
