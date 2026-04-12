use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use crate::error::{Error, Result};

use super::Context;

pub(super) struct ResolvedTransferPaths<'ctx> {
    pub(super) canonical_root: &'ctx Path,
    pub(super) requested_from: PathBuf,
    pub(super) requested_to: PathBuf,
    pub(super) from_name: OsString,
    pub(super) from_parent_relative: PathBuf,
    pub(super) from_parent: PathBuf,
    pub(super) from_relative: PathBuf,
    pub(super) source: PathBuf,
    pub(super) to_name: OsString,
    pub(super) to_parent_relative: PathBuf,
    pub(super) to_parent: Option<PathBuf>,
}

pub(super) struct PreparedTransferDestination {
    pub(super) parent: PathBuf,
    pub(super) relative: PathBuf,
    pub(super) path: PathBuf,
}

fn requested_transfer_destination_relative(paths: &ResolvedTransferPaths<'_>) -> PathBuf {
    Path::new(&paths.to_parent_relative).join(Path::new(&paths.to_name))
}

fn preview_parent_dir_under_root(
    root_id: &str,
    requested_parent: &Path,
    canonical_root: &Path,
) -> Result<PathBuf> {
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
        match std::fs::symlink_metadata(&next) {
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
                    match remaining {
                        Component::CurDir => {}
                        Component::Normal(remaining) => current.push(remaining),
                        Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                            return Err(Error::InvalidPath(format!(
                                "invalid path {}: unsupported parent directory reference",
                                requested_parent.display()
                            )));
                        }
                    }
                }
                return Ok(current);
            }
            Err(err) => return Err(Error::io_path("symlink_metadata", &current_relative, err)),
        }
    }

    Ok(current)
}

pub(super) fn resolve_transfer_paths<'ctx>(
    ctx: &'ctx Context,
    root_id: &str,
    from: &Path,
    to: &Path,
    create_parents: bool,
    op_name: &'static str,
) -> Result<ResolvedTransferPaths<'ctx>> {
    let from_resolved = super::resolve::resolve_path_in_root_lexically(ctx, root_id, from)?;
    let to_resolved = super::resolve::resolve_path_in_root_lexically(ctx, root_id, to)?;

    let canonical_root = from_resolved.canonical_root;
    if to_resolved.canonical_root != canonical_root {
        return Err(Error::InvalidPath(
            "from/to roots resolved inconsistently".to_string(),
        ));
    }

    let requested_from = from_resolved.requested_path;
    let requested_to = to_resolved.requested_path;
    if requested_from == Path::new(".") || requested_to == Path::new(".") {
        return Err(Error::InvalidPath(format!(
            "refusing to {op_name} the root directory"
        )));
    }

    let from_name = requested_from
        .file_name()
        .ok_or_else(|| {
            Error::InvalidPath(format!("invalid from path {:?}: missing file name", from))
        })?
        .to_os_string();
    let to_name = requested_to
        .file_name()
        .ok_or_else(|| Error::InvalidPath(format!("invalid to path {:?}: missing file name", to)))?
        .to_os_string();

    let from_parent_relative = requested_from
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf();
    let to_parent_relative = requested_to
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .to_path_buf();

    let from_parent = ctx.ensure_dir_under_root(root_id, &from_parent_relative, false)?;
    let to_parent = match ctx.ensure_dir_under_root(root_id, &to_parent_relative, false) {
        Ok(path) => Some(path),
        Err(Error::IoPath { source, .. })
            if create_parents && source.kind() == std::io::ErrorKind::NotFound =>
        {
            None
        }
        Err(err) => return Err(err),
    };

    let from_relative_parent =
        crate::path_utils::strip_prefix_case_insensitive_normalized(&from_parent, canonical_root)
            .ok_or_else(|| Error::OutsideRoot {
            root_id: root_id.to_string(),
            path: requested_from.clone(),
        })?;
    let from_relative = from_relative_parent.join(&from_name);
    if ctx.redactor.is_path_denied(&from_relative) {
        return Err(Error::SecretPathDenied(from_relative));
    }

    let source = from_parent.join(&from_name);
    if !crate::path_utils::starts_with_case_insensitive_normalized(&source, canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: root_id.to_string(),
            path: requested_from.clone(),
        });
    }

    Ok(ResolvedTransferPaths {
        canonical_root,
        requested_from,
        requested_to,
        from_name,
        from_parent_relative,
        from_parent,
        from_relative,
        source,
        to_name,
        to_parent_relative,
        to_parent,
    })
}

pub(super) fn prepare_transfer_destination(
    ctx: &Context,
    root_id: &str,
    paths: &mut ResolvedTransferPaths<'_>,
) -> Result<PreparedTransferDestination> {
    let requested_relative = requested_transfer_destination_relative(paths);
    if ctx.redactor.is_path_denied(&requested_relative) {
        return Err(Error::SecretPathDenied(requested_relative));
    }

    let preview_relative_parent =
        match ctx.ensure_dir_under_root(root_id, &paths.to_parent_relative, false) {
            Ok(canonical_parent) => crate::path_utils::strip_prefix_case_insensitive_normalized(
                &canonical_parent,
                paths.canonical_root,
            )
            .ok_or_else(|| Error::OutsideRoot {
                root_id: root_id.to_string(),
                path: paths.requested_to.clone(),
            })?,
            Err(Error::IoPath { source, .. })
                if paths.to_parent.is_none() && source.kind() == std::io::ErrorKind::NotFound =>
            {
                let preview_parent = preview_parent_dir_under_root(
                    root_id,
                    &paths.to_parent_relative,
                    paths.canonical_root,
                )?;
                crate::path_utils::strip_prefix_case_insensitive_normalized(
                    &preview_parent,
                    paths.canonical_root,
                )
                .ok_or_else(|| Error::OutsideRoot {
                    root_id: root_id.to_string(),
                    path: paths.requested_to.clone(),
                })?
            }
            Err(err) => return Err(err),
        };
    let preview_relative = preview_relative_parent.join(Path::new(&paths.to_name));
    if ctx.redactor.is_path_denied(&preview_relative) {
        return Err(Error::SecretPathDenied(preview_relative));
    }

    if paths.to_parent.is_none() {
        paths.to_parent =
            Some(ctx.ensure_dir_under_root(root_id, &paths.to_parent_relative, true)?);
    }

    let to_parent = paths.to_parent.take().ok_or_else(|| {
        Error::InvalidPath("failed to prepare destination parent directory".to_string())
    })?;

    let to_relative_parent = crate::path_utils::strip_prefix_case_insensitive_normalized(
        &to_parent,
        paths.canonical_root,
    )
    .ok_or_else(|| Error::OutsideRoot {
        root_id: root_id.to_string(),
        path: paths.requested_to.clone(),
    })?;
    let to_name = Path::new(&paths.to_name);
    let relative = to_relative_parent.join(to_name);
    if ctx.redactor.is_path_denied(&relative) {
        return Err(Error::SecretPathDenied(relative));
    }

    let path = to_parent.join(to_name);
    if !crate::path_utils::starts_with_case_insensitive_normalized(&path, paths.canonical_root) {
        return Err(Error::OutsideRoot {
            root_id: root_id.to_string(),
            path: paths.requested_to.clone(),
        });
    }

    Ok(PreparedTransferDestination {
        parent: to_parent,
        relative,
        path,
    })
}
