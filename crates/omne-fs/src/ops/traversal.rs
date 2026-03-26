use std::path::{Path, PathBuf};

#[cfg(any(feature = "glob", feature = "grep"))]
use std::fs;
#[cfg(any(feature = "glob", feature = "grep"))]
use std::time::Instant;
#[cfg(all(windows, any(feature = "glob", feature = "grep")))]
use std::{cell::RefCell, ffi::OsString};

#[cfg(any(feature = "glob", feature = "grep"))]
use globset::GlobSet;

#[cfg(any(feature = "glob", feature = "grep"))]
use crate::error::Result;

#[cfg(any(feature = "glob", feature = "grep"))]
use super::Context;
#[cfg(any(feature = "glob", feature = "grep"))]
use super::ScanLimitReason;

#[cfg(all(windows, any(feature = "glob", feature = "grep")))]
thread_local! {
    static GLOB_NORMALIZED_WIDE_BUF: RefCell<Vec<u16>> = const { RefCell::new(Vec::new()) };
}

#[cfg(any(
    all(windows, any(feature = "glob", feature = "grep")),
    all(test, any(feature = "glob", feature = "grep"))
))]
fn shrink_reusable_vec<T>(buf: &mut Vec<T>, max_capacity: usize) -> bool {
    if buf.capacity() > max_capacity {
        buf.shrink_to(max_capacity);
        true
    } else {
        false
    }
}

#[cfg(any(
    all(windows, any(feature = "glob", feature = "grep")),
    all(test, any(feature = "glob", feature = "grep"))
))]
fn clear_and_shrink_reusable_vec<T>(buf: &mut Vec<T>, max_capacity: usize) -> bool {
    buf.clear();
    shrink_reusable_vec(buf, max_capacity)
}

#[cfg(any(feature = "glob", feature = "grep"))]
mod compile;
#[cfg(any(feature = "glob", feature = "grep"))]
mod walk;

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn compile_glob(pattern: &str) -> Result<GlobSet> {
    compile::compile_glob(pattern)
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn compile_traversal_skip_globs(patterns: &[String]) -> Result<Option<GlobSet>> {
    compile::compile_traversal_skip_globs(patterns)
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn derive_safe_traversal_prefix(pattern: &str) -> Option<PathBuf> {
    compile::derive_safe_traversal_prefix(pattern)
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn walk_traversal_files(
    ctx: &Context,
    root_id: &str,
    root_path: &Path,
    walk_root: &Path,
    options: TraversalWalkOptions,
    started: &Instant,
    on_file: impl FnMut(TraversalFile, &mut TraversalDiagnostics) -> Result<std::ops::ControlFlow<()>>,
) -> Result<TraversalDiagnostics> {
    walk::walk_traversal_files(
        ctx, root_id, root_path, walk_root, options, started, on_file,
    )
}

#[cfg(any(feature = "glob", feature = "grep"))]
// A synthetic file name used to apply deny/skip glob patterns to directories: for each directory
// entry `dir`, we also evaluate `dir/<probe>` against glob rules so patterns like `node_modules/*`
// or `**/.git/**` can exclude entire directories (and avoid descending into them).
pub(super) const TRAVERSAL_GLOB_PROBE_NAME: &str = ".omne-fs-probe";

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn elapsed_ms(started: &Instant) -> u64 {
    let ms = started.elapsed().as_millis();
    if ms > u64::MAX as u128 {
        u64::MAX
    } else {
        ms as u64
    }
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) fn globset_is_match(glob: &GlobSet, path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};

        const BACKSLASH: u16 = b'\\' as u16;
        const SLASH: u16 = b'/' as u16;
        const MAX_RETAINED_WIDE_UNITS: usize = 16 * 1024;

        // Fast path: no backslash means the path is already in glob-compatible separator form.
        if !path.as_os_str().as_encoded_bytes().contains(&b'\\') {
            return glob.is_match(path);
        }
        GLOB_NORMALIZED_WIDE_BUF.with(|normalized_wide| {
            let mut normalized_wide = normalized_wide.borrow_mut();
            normalized_wide.clear();
            normalized_wide.extend(
                path.as_os_str().encode_wide().map(
                    |unit| {
                        if unit == BACKSLASH { SLASH } else { unit }
                    },
                ),
            );
            let normalized = OsString::from_wide(&normalized_wide);
            let matched = glob.is_match(Path::new(&normalized));
            let _ = clear_and_shrink_reusable_vec(&mut normalized_wide, MAX_RETAINED_WIDE_UNITS);
            matched
        })
    }
    #[cfg(not(windows))]
    {
        glob.is_match(path)
    }
}

#[cfg(any(feature = "glob", feature = "grep"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TraversalOpenMode {
    None,
    ReadFile,
}

#[cfg(any(feature = "glob", feature = "grep"))]
#[derive(Debug, Clone, Copy)]
pub(super) struct TraversalWalkOptions {
    pub(super) open_mode: TraversalOpenMode,
    pub(super) max_walk: Option<std::time::Duration>,
}

#[cfg(any(feature = "glob", feature = "grep"))]
#[derive(Debug, Default, Clone)]
pub(super) struct TraversalDiagnostics {
    scanned_files: u64,
    scanned_entries: u64,
    scan_limit_reason: Option<ScanLimitReason>,
    skipped_walk_errors: u64,
    skipped_io_errors: u64,
    skipped_dangling_symlink_targets: u64,
}

#[cfg(any(feature = "glob", feature = "grep"))]
impl TraversalDiagnostics {
    pub(super) fn scanned_files(&self) -> u64 {
        self.scanned_files
    }

    pub(super) fn scanned_entries(&self) -> u64 {
        self.scanned_entries
    }

    pub(super) fn scan_limit_reached(&self) -> bool {
        self.scan_limit_reason.is_some()
    }

    pub(super) fn scan_limit_reason(&self) -> Option<ScanLimitReason> {
        self.scan_limit_reason
    }

    pub(super) fn skipped_walk_errors(&self) -> u64 {
        self.skipped_walk_errors
    }

    pub(super) fn skipped_io_errors(&self) -> u64 {
        self.skipped_io_errors
    }

    pub(super) fn skipped_dangling_symlink_targets(&self) -> u64 {
        self.skipped_dangling_symlink_targets
    }

    // Records the first observed limit-hit reason; subsequent limit reasons are ignored.
    pub(super) fn mark_limit_reached(&mut self, reason: ScanLimitReason) {
        if self.scan_limit_reason.is_none() {
            self.scan_limit_reason = Some(reason);
        }
    }

    pub(super) fn inc_scanned_files(&mut self) {
        self.scanned_files = self.scanned_files.saturating_add(1);
    }

    pub(super) fn inc_scanned_entries(&mut self) {
        self.scanned_entries = self.scanned_entries.saturating_add(1);
    }

    pub(super) fn inc_skipped_walk_errors(&mut self) {
        self.skipped_walk_errors = self.skipped_walk_errors.saturating_add(1);
    }

    pub(super) fn inc_skipped_io_errors(&mut self) {
        self.skipped_io_errors = self.skipped_io_errors.saturating_add(1);
    }

    pub(super) fn inc_skipped_dangling_symlink_targets(&mut self) {
        self.skipped_dangling_symlink_targets =
            self.skipped_dangling_symlink_targets.saturating_add(1);
    }
}

#[cfg(any(feature = "glob", feature = "grep"))]
pub(super) struct TraversalFile {
    // Absolute canonical path is only needed when the caller must open/revalidate the entry.
    // `None` avoids per-entry `root_path.join(...)` allocations on pure traversal paths.
    pub(super) path: Option<PathBuf>,
    pub(super) relative_path: PathBuf,
    pub(super) opened_file: Option<(fs::File, fs::Metadata)>,
}

#[cfg(all(any(feature = "glob", feature = "grep"), test))]
mod tests {
    use super::*;

    #[test]
    fn mark_limit_reached_keeps_first_reason() {
        let mut diag = TraversalDiagnostics::default();
        diag.mark_limit_reached(ScanLimitReason::Entries);
        diag.mark_limit_reached(ScanLimitReason::Time);

        assert!(diag.scan_limit_reached());
        assert_eq!(diag.scan_limit_reason(), Some(ScanLimitReason::Entries));
    }

    #[test]
    fn shrink_reusable_vec_caps_capacity() {
        let mut buf: Vec<u8> = Vec::with_capacity(128);
        assert!(shrink_reusable_vec(&mut buf, 32));
        assert!(!shrink_reusable_vec(&mut buf, 256));
    }

    #[test]
    fn clear_and_shrink_reusable_vec_clears_non_empty_buffer() {
        let mut buf = vec![0_u8; 128];
        assert!(clear_and_shrink_reusable_vec(&mut buf, 32));
        assert!(buf.is_empty());
    }
}
