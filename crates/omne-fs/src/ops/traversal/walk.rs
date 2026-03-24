use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::time::Instant;

use walkdir::WalkDir;

use crate::error::{Error, Result};

use super::super::{Context, ScanLimitReason};
use super::{
    TRAVERSAL_GLOB_PROBE_NAME, TraversalDiagnostics, TraversalFile, TraversalOpenMode,
    TraversalWalkOptions,
};

fn resolve_walk_root_for_traversal(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    walk_root: &Path,
) -> Result<PathBuf> {
    let relative_walk_root =
        crate::path_utils::strip_prefix_case_insensitive_normalized(walk_root, root_path)
            .ok_or_else(|| {
                Error::InvalidPath("derived traversal root escapes selected root".to_string())
            })?;
    let relative_walk_root = if relative_walk_root.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        relative_walk_root
    };
    if relative_walk_root == Path::new(".") {
        return Ok(root_path.to_path_buf());
    }
    let requested_walk_root = root_path.join(&relative_walk_root);

    match ctx.canonical_path_in_root(root_id, &relative_walk_root) {
        Ok((canonical, _, _)) => {
            if crate::path_utils::paths_equal_case_insensitive_normalized(
                &canonical,
                &requested_walk_root,
            ) {
                return Ok(canonical);
            }
            // Preserve alias paths for file/symlink roots so pattern matching sees the
            // requested path (e.g. "link.txt"), not only the canonical target path.
            match std::fs::symlink_metadata(&requested_walk_root) {
                Ok(meta) if !meta.is_dir() => Ok(requested_walk_root),
                Ok(_) => Ok(canonical),
                Err(_) => Ok(canonical),
            }
        }
        Err(Error::IoPath {
            op: "canonicalize",
            source,
            ..
        }) if source.kind() == std::io::ErrorKind::NotFound => Ok(requested_walk_root),
        Err(Error::OutsideRoot { .. }) | Err(Error::SecretPathDenied(_)) => Err(
            Error::InvalidPath("derived traversal root escapes selected root".to_string()),
        ),
        Err(err) => Err(err),
    }
}

fn walkdir_root_error(root_path: &Path, walk_root: &Path, err: walkdir::Error) -> Error {
    let relative =
        crate::path_utils::strip_prefix_case_insensitive_normalized(walk_root, root_path)
            .filter(|relative| !relative.as_os_str().is_empty())
            .unwrap_or_else(|| PathBuf::from("."));

    let source = err
        .io_error()
        .and_then(|io| {
            io.raw_os_error()
                .map(std::io::Error::from_raw_os_error)
                .or_else(|| Some(std::io::Error::from(io.kind())))
        })
        .unwrap_or_else(|| {
            std::io::Error::other("walkdir root traversal failed without io error detail")
        });

    Error::WalkDirRoot {
        path: relative,
        source,
    }
}

#[inline]
fn is_entry_denied_or_skipped(
    ctx: &Context,
    relative: &Path,
    is_dir: bool,
    probe_path_scratch: &mut PathBuf,
) -> bool {
    if ctx.redactor.is_path_denied(relative) || ctx.is_traversal_path_skipped(relative) {
        return true;
    }
    if !is_dir {
        return false;
    }

    if relative == Path::new(".") {
        let probe = Path::new(TRAVERSAL_GLOB_PROBE_NAME);
        return ctx.redactor.is_path_denied(probe) || ctx.is_traversal_path_skipped(probe);
    }

    probe_path_scratch.clear();
    probe_path_scratch.push(relative);
    probe_path_scratch.push(TRAVERSAL_GLOB_PROBE_NAME);
    ctx.redactor.is_path_denied(probe_path_scratch.as_path())
        || ctx.is_traversal_path_skipped(probe_path_scratch.as_path())
}

pub(super) fn walkdir_traversal_iter<'a>(
    ctx: &'a Context,
    root_path: &'a Path,
    walk_root: &'a Path,
) -> impl Iterator<Item = walkdir::Result<walkdir::DirEntry>> + 'a {
    let has_path_filters = ctx.has_traversal_path_filters();
    let walkdir = WalkDir::new(walk_root)
        .follow_root_links(false)
        .follow_links(false);
    let walkdir = if ctx.policy.traversal.stable_sort {
        walkdir.sort_by_file_name()
    } else {
        walkdir
    };
    let mut probe_path_scratch = PathBuf::new();
    walkdir.into_iter().filter_entry(move |entry| {
        if entry.depth() == 0 {
            return true;
        }
        if !has_path_filters {
            return true;
        }
        let is_dir = entry.file_type().is_dir();
        let relative = match entry.path().strip_prefix(root_path) {
            Ok(relative) => std::borrow::Cow::Borrowed(relative),
            Err(_) => {
                #[cfg(windows)]
                {
                    let relative = crate::path_utils::strip_prefix_case_insensitive_normalized(
                        entry.path(),
                        root_path,
                    );
                    debug_assert!(
                        relative.is_some(),
                        "walkdir yielded a path outside the selected root"
                    );
                    let Some(relative) = relative else {
                        return false;
                    };
                    std::borrow::Cow::Owned(relative)
                }
                #[cfg(not(windows))]
                {
                    debug_assert!(
                        crate::path_utils::strip_prefix_case_insensitive_normalized(
                            entry.path(),
                            root_path,
                        )
                        .is_some(),
                        "walkdir yielded a path outside the selected root"
                    );
                    return false;
                }
            }
        };

        !is_entry_denied_or_skipped(ctx, relative.as_ref(), is_dir, &mut probe_path_scratch)
    })
}

#[derive(Debug)]
enum WalkEntryAction {
    Continue,
    Break,
    Entry(walkdir::DirEntry),
}

fn consume_walk_entry(diag: &mut TraversalDiagnostics, max_walk_entries: u64) -> bool {
    if diag.scanned_entries() >= max_walk_entries {
        diag.mark_limit_reached(ScanLimitReason::Entries);
        return false;
    }
    diag.inc_scanned_entries();
    true
}

fn classify_walkdir_entry(
    entry: walkdir::Result<walkdir::DirEntry>,
    root_path: &Path,
    walk_root: &Path,
    diag: &mut TraversalDiagnostics,
    max_walk_entries: u64,
) -> Result<WalkEntryAction> {
    match entry {
        Ok(entry) => {
            if entry.depth() > 0 && !consume_walk_entry(diag, max_walk_entries) {
                return Ok(WalkEntryAction::Break);
            }
            Ok(WalkEntryAction::Entry(entry))
        }
        Err(err) => {
            if err.depth() == 0 {
                return Err(walkdir_root_error(root_path, walk_root, err));
            }
            if !consume_walk_entry(diag, max_walk_entries) {
                return Ok(WalkEntryAction::Break);
            }
            diag.inc_skipped_walk_errors();
            Ok(WalkEntryAction::Continue)
        }
    }
}

fn relative_from_walk_entry<'a>(
    entry: &'a walkdir::DirEntry,
    root_path: &'a Path,
    diag: &mut TraversalDiagnostics,
) -> Option<Cow<'a, Path>> {
    if let Ok(relative) = entry.path().strip_prefix(root_path) {
        return Some(Cow::Borrowed(relative));
    }

    #[cfg(windows)]
    {
        let relative =
            crate::path_utils::strip_prefix_case_insensitive_normalized(entry.path(), root_path);
        if relative.is_none() {
            diag.inc_skipped_walk_errors();
        }
        relative.map(Cow::Owned)
    }

    #[cfg(not(windows))]
    {
        debug_assert!(
            crate::path_utils::strip_prefix_case_insensitive_normalized(entry.path(), root_path)
                .is_some(),
            "walkdir yielded a path outside the selected root"
        );
        diag.inc_skipped_walk_errors();
        None
    }
}

fn resolve_entry_traversal_file(
    ctx: &Context,
    root_id: &str,
    relative: Cow<'_, Path>,
    is_symlink: bool,
    open_mode: TraversalOpenMode,
    diag: &mut TraversalDiagnostics,
) -> Result<Option<TraversalFile>> {
    #[derive(Clone, Copy)]
    enum ResolvePhase {
        Canonicalize,
        Open,
    }

    fn classify_resolve_error(
        err: Error,
        phase: ResolvePhase,
        is_symlink: bool,
        diag: &mut TraversalDiagnostics,
    ) -> Result<()> {
        match err {
            Error::OutsideRoot { .. } | Error::SecretPathDenied(_) => {
                diag.inc_skipped_walk_errors();
                Ok(())
            }
            Error::IoPath {
                op: "canonicalize",
                source,
                ..
            } if matches!(phase, ResolvePhase::Canonicalize)
                && source.kind() == std::io::ErrorKind::NotFound =>
            {
                if is_symlink {
                    diag.inc_skipped_dangling_symlink_targets();
                } else {
                    diag.inc_skipped_io_errors();
                }
                Ok(())
            }
            Error::IoPath {
                source, op: "open", ..
            } if matches!(phase, ResolvePhase::Open)
                && source.kind() == std::io::ErrorKind::NotFound =>
            {
                if is_symlink {
                    diag.inc_skipped_dangling_symlink_targets();
                } else {
                    diag.inc_skipped_io_errors();
                }
                Ok(())
            }
            Error::InvalidPath(_) if matches!(phase, ResolvePhase::Open) => {
                diag.inc_skipped_io_errors();
                Ok(())
            }
            Error::IoPath { .. } | Error::Io(_) => {
                diag.inc_skipped_io_errors();
                Ok(())
            }
            err => Err(err),
        }
    }

    // Fast path for glob-style traversal:
    // - `open_mode == None` means we only return relative paths (no file open/read).
    // - Non-symlink entries are already root-relative from walkdir + strip_prefix.
    // - Keep canonical revalidation for symlinks and read modes to preserve boundary checks.
    if matches!(open_mode, TraversalOpenMode::None) && !is_symlink {
        let relative = relative.into_owned();
        return Ok(Some(TraversalFile {
            path: None,
            relative_path: relative,
            opened_file: None,
        }));
    }

    let (canonical, _canonical_relative, _requested_path) =
        match ctx.canonical_path_in_root(root_id, relative.as_ref()) {
            Ok(ok) => ok,
            Err(err) => {
                classify_resolve_error(err, ResolvePhase::Canonicalize, is_symlink, diag)?;
                return Ok(None);
            }
        };

    let opened_file = if matches!(open_mode, TraversalOpenMode::ReadFile) {
        match super::super::io::open_regular_file_for_read(&canonical, relative.as_ref()) {
            Ok(opened_file) => Some(opened_file),
            Err(err) => {
                classify_resolve_error(err, ResolvePhase::Open, is_symlink, diag)?;
                return Ok(None);
            }
        }
    } else {
        None
    };

    Ok(Some(TraversalFile {
        path: Some(canonical),
        relative_path: relative.into_owned(),
        opened_file,
    }))
}

fn traversal_file_from_entry(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    entry: &walkdir::DirEntry,
    open_mode: TraversalOpenMode,
    diag: &mut TraversalDiagnostics,
) -> Result<Option<TraversalFile>> {
    let Some(relative) = relative_from_walk_entry(entry, root_path, diag) else {
        return Ok(None);
    };
    // Deny/skip filtering is already applied in `walkdir_traversal_iter.filter_entry`.

    resolve_entry_traversal_file(
        ctx,
        root_id,
        relative,
        entry.file_type().is_symlink(),
        open_mode,
        diag,
    )
}

pub(super) fn walk_traversal_files(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    walk_root: &Path,
    options: TraversalWalkOptions,
    started: &Instant,
    mut on_file: impl FnMut(
        TraversalFile,
        &mut TraversalDiagnostics,
    ) -> Result<std::ops::ControlFlow<()>>,
) -> Result<TraversalDiagnostics> {
    let walk_root = resolve_walk_root_for_traversal(ctx, root_id, root_path, walk_root)?;

    let mut diag = TraversalDiagnostics::default();
    let max_walk_entries = u64::try_from(ctx.policy.limits.max_walk_entries).unwrap_or(u64::MAX);
    let max_walk_files = u64::try_from(ctx.policy.limits.max_walk_files).unwrap_or(u64::MAX);

    for entry in walkdir_traversal_iter(ctx, root_path, &walk_root) {
        if options
            .max_walk
            .is_some_and(|limit| started.elapsed() >= limit)
        {
            diag.mark_limit_reached(ScanLimitReason::Time);
            break;
        }

        let entry = match classify_walkdir_entry(
            entry,
            root_path,
            &walk_root,
            &mut diag,
            max_walk_entries,
        )? {
            WalkEntryAction::Continue => continue,
            WalkEntryAction::Break => break,
            WalkEntryAction::Entry(entry) => entry,
        };

        let file_type = entry.file_type();
        if !(file_type.is_file() || file_type.is_symlink()) {
            continue;
        }
        if diag.scanned_files() >= max_walk_files {
            diag.mark_limit_reached(ScanLimitReason::Files);
            break;
        }
        diag.inc_scanned_files();

        let Some(file) = traversal_file_from_entry(
            ctx,
            root_id,
            root_path,
            &entry,
            options.open_mode,
            &mut diag,
        )?
        else {
            continue;
        };

        match on_file(file, &mut diag)? {
            std::ops::ControlFlow::Continue(()) => {}
            std::ops::ControlFlow::Break(()) => break,
        }
    }

    Ok(diag)
}
