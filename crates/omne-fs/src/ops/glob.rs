use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::{Context, ScanLimitReason};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobRequest {
    pub root_id: String,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobResponse {
    pub matches: Vec<PathBuf>,
    pub truncated: bool,
    #[serde(default)]
    pub scanned_files: u64,
    #[serde(default)]
    pub scan_limit_reached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan_limit_reason: Option<ScanLimitReason>,
    /// Elapsed wall-clock time spent in this call (milliseconds).
    #[serde(default)]
    pub elapsed_ms: u64,
    #[serde(default)]
    pub scanned_entries: u64,
    #[serde(default)]
    pub skipped_walk_errors: u64,
    #[serde(default)]
    pub skipped_io_errors: u64,
    #[serde(default)]
    pub skipped_dangling_symlink_targets: u64,
}

#[cfg(feature = "glob")]
use std::time::{Duration, Instant};

#[cfg(feature = "glob")]
use super::traversal::{
    TRAVERSAL_GLOB_PROBE_NAME, TraversalDiagnostics, TraversalOpenMode, TraversalWalkOptions,
    compile_glob, derive_safe_traversal_prefix, elapsed_ms, globset_is_match, walk_traversal_files,
};

#[cfg(feature = "glob")]
fn initial_match_capacity(max_results: usize) -> usize {
    const MAX_INITIAL_MATCH_CAPACITY: usize = 1024;
    max_results.min(MAX_INITIAL_MATCH_CAPACITY)
}

#[cfg(feature = "glob")]
fn max_glob_response_bytes(limits: &crate::policy::Limits) -> usize {
    limits
        .max_glob_bytes
        .unwrap_or_else(|| limits.max_results.saturating_mul(limits.max_line_bytes))
}

#[cfg(feature = "glob")]
#[inline]
fn estimated_path_response_bytes(path: &std::path::Path) -> usize {
    // Response payloads serialize paths as lossy UTF-8 strings; budget accounting
    // must use the same representation to avoid under-counting non-UTF8 paths.
    path.to_string_lossy().len()
}

#[cfg(feature = "glob")]
fn build_glob_response(
    mut matches: Vec<PathBuf>,
    diag: TraversalDiagnostics,
    started: &Instant,
    stable_sort: bool,
    sorted_hint: bool,
) -> GlobResponse {
    maybe_sort_glob_matches(&mut matches, stable_sort, sorted_hint);
    GlobResponse {
        matches,
        truncated: diag.truncated(),
        scanned_files: diag.scanned_files(),
        scan_limit_reached: diag.scan_limit_reached(),
        scan_limit_reason: diag.scan_limit_reason(),
        elapsed_ms: elapsed_ms(started),
        scanned_entries: diag.scanned_entries(),
        skipped_walk_errors: diag.skipped_walk_errors(),
        skipped_io_errors: diag.skipped_io_errors(),
        skipped_dangling_symlink_targets: diag.skipped_dangling_symlink_targets(),
    }
}

#[cfg(feature = "glob")]
fn maybe_sort_glob_matches(matches: &mut [PathBuf], stable_sort: bool, sorted_hint: bool) {
    if !stable_sort || matches.len() <= 1 || sorted_hint {
        return;
    }
    matches.sort_unstable();
}

#[cfg(feature = "glob")]
#[cfg(test)]
fn matches_sorted_by_path(matches: &[PathBuf]) -> bool {
    matches.windows(2).all(|pair| pair[0] <= pair[1])
}

#[cfg(all(test, feature = "glob"))]
mod tests {
    use std::path::PathBuf;

    use super::{matches_sorted_by_path, maybe_sort_glob_matches};

    #[test]
    fn match_order_detects_sorted_input() {
        let matches = vec![
            PathBuf::from("a"),
            PathBuf::from("a.txt"),
            PathBuf::from("b.txt"),
        ];
        assert!(matches_sorted_by_path(&matches));
    }

    #[test]
    fn match_order_detects_unsorted_input() {
        let matches = vec![PathBuf::from("b.txt"), PathBuf::from("a.txt")];
        assert!(!matches_sorted_by_path(&matches));
    }

    #[test]
    fn maybe_sort_glob_matches_respects_stable_sort_enabled() {
        let mut matches = vec![PathBuf::from("b.txt"), PathBuf::from("a.txt")];
        maybe_sort_glob_matches(&mut matches, true, false);
        assert_eq!(
            matches,
            vec![PathBuf::from("a.txt"), PathBuf::from("b.txt")]
        );
    }

    #[test]
    fn maybe_sort_glob_matches_skips_sort_when_stable_sort_disabled() {
        let mut matches = vec![PathBuf::from("b.txt"), PathBuf::from("a.txt")];
        maybe_sort_glob_matches(&mut matches, false, false);
        assert_eq!(
            matches,
            vec![PathBuf::from("b.txt"), PathBuf::from("a.txt")]
        );
    }

    #[test]
    fn maybe_sort_glob_matches_keeps_sorted_input_intact() {
        let mut matches = vec![PathBuf::from("a.txt"), PathBuf::from("b.txt")];
        maybe_sort_glob_matches(&mut matches, true, true);
        assert_eq!(
            matches,
            vec![PathBuf::from("a.txt"), PathBuf::from("b.txt")]
        );
    }
}

#[cfg(not(feature = "glob"))]
pub fn glob_paths(ctx: &Context, request: GlobRequest) -> Result<GlobResponse> {
    let _ = ctx;
    let _ = request;
    Err(Error::NotPermitted(
        "glob is not supported: crate feature 'glob' is disabled".to_string(),
    ))
}

#[cfg(feature = "glob")]
pub fn glob_paths(ctx: &Context, request: GlobRequest) -> Result<GlobResponse> {
    ctx.ensure_policy_permission(ctx.policy.permissions.glob, "glob")?;
    let started = Instant::now();
    let max_walk = ctx.policy.limits.max_walk_ms.map(Duration::from_millis);
    let root_path = ctx.canonical_root(&request.root_id)?;
    let matcher = compile_glob(&request.pattern)?;
    let max_response_bytes = max_glob_response_bytes(&ctx.policy.limits);

    let mut matches =
        Vec::<PathBuf>::with_capacity(initial_match_capacity(ctx.policy.limits.max_results));
    let stable_sort = ctx.policy.traversal.stable_sort;
    let mut matches_sorted = true;
    let mut response_bytes = 0usize;
    let mut diag = TraversalDiagnostics::default();
    let has_path_filters = ctx.has_traversal_path_filters();
    let walk_root_storage = match derive_safe_traversal_prefix(&request.pattern) {
        Some(prefix) => {
            let walk_root = root_path.join(&prefix);
            if has_path_filters {
                let prefix_denied_or_skipped =
                    ctx.redactor.is_path_denied(&prefix) || ctx.is_traversal_path_skipped(&prefix);
                if prefix_denied_or_skipped {
                    return Ok(build_glob_response(
                        matches,
                        diag,
                        &started,
                        stable_sort,
                        matches_sorted,
                    ));
                }

                // Avoid unnecessary filesystem probes when deny/skip already short-circuits.
                let probe_denied_or_skipped = match std::fs::symlink_metadata(&walk_root) {
                    Ok(meta) if meta.is_dir() => {
                        let probe = prefix.join(TRAVERSAL_GLOB_PROBE_NAME);
                        ctx.redactor.is_path_denied(&probe) || ctx.is_traversal_path_skipped(&probe)
                    }
                    Ok(_) | Err(_) => false,
                };
                if probe_denied_or_skipped {
                    return Ok(build_glob_response(
                        matches,
                        diag,
                        &started,
                        stable_sort,
                        matches_sorted,
                    ));
                }
            }
            Some(walk_root)
        }
        None => None,
    };
    let walk_root = walk_root_storage.as_deref().unwrap_or(root_path);
    diag = match walk_traversal_files(
        ctx,
        &request.root_id,
        root_path,
        walk_root,
        TraversalWalkOptions {
            open_mode: TraversalOpenMode::None,
            max_walk,
        },
        &started,
        |file, diag| {
            if globset_is_match(&matcher, &file.relative_path) {
                if matches.len() >= ctx.policy.limits.max_results {
                    diag.mark_limit_reached(ScanLimitReason::Results);
                    return Ok(std::ops::ControlFlow::Break(()));
                }
                let path_bytes = estimated_path_response_bytes(file.relative_path.as_path());
                if response_bytes.saturating_add(path_bytes) > max_response_bytes {
                    diag.mark_limit_reached(ScanLimitReason::ResponseBytes);
                    return Ok(std::ops::ControlFlow::Break(()));
                }
                response_bytes = response_bytes.saturating_add(path_bytes);
                if stable_sort
                    && matches_sorted
                    && matches
                        .last()
                        .is_some_and(|prev| prev.as_path() > file.relative_path.as_path())
                {
                    matches_sorted = false;
                }
                matches.push(file.relative_path);
            }
            Ok(std::ops::ControlFlow::Continue(()))
        },
    ) {
        Ok(diag) => diag,
        Err(Error::WalkDirRoot { path, source })
            if source.kind() == std::io::ErrorKind::NotFound
                && path.as_path() != std::path::Path::new(".") =>
        {
            return Ok(build_glob_response(
                matches,
                diag,
                &started,
                stable_sort,
                matches_sorted,
            ));
        }
        Err(err) => return Err(err),
    };

    Ok(build_glob_response(
        matches,
        diag,
        &started,
        stable_sort,
        matches_sorted,
    ))
}
