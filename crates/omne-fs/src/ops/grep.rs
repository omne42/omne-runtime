use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::{Context, ScanLimitReason};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepRequest {
    pub root_id: String,
    pub query: String,
    #[serde(default)]
    pub regex: bool,
    #[serde(default)]
    pub glob: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepMatch {
    pub path: PathBuf,
    pub line: u64,
    pub text: String,
    #[serde(default)]
    pub line_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrepResponse {
    pub matches: Vec<GrepMatch>,
    pub truncated: bool,
    #[serde(default)]
    pub skipped_too_large_files: u64,
    #[serde(default)]
    pub skipped_non_utf8_files: u64,
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

#[cfg(feature = "grep")]
use std::io::{BufRead, Read};

#[cfg(feature = "grep")]
use std::time::{Duration, Instant};

#[cfg(feature = "grep")]
use super::traversal::{
    TRAVERSAL_GLOB_PROBE_NAME, TraversalDiagnostics, TraversalOpenMode, TraversalWalkOptions,
    compile_glob, derive_safe_traversal_prefix, elapsed_ms, globset_is_match, walk_traversal_files,
};

#[cfg(feature = "grep")]
#[derive(Debug, Default, Clone, Copy)]
struct GrepSkipCounters {
    skipped_too_large_files: u64,
    skipped_non_utf8_files: u64,
}

#[cfg(feature = "grep")]
const MAX_GREP_QUERY_BYTES: usize = 8 * 1024;
#[cfg(feature = "grep")]
const MAX_REGEX_LINE_BYTES: usize = 8 * 1024 * 1024;

#[cfg(feature = "grep")]
fn initial_match_capacity(max_results: usize) -> usize {
    const MAX_INITIAL_MATCH_CAPACITY: usize = 1024;
    max_results.min(MAX_INITIAL_MATCH_CAPACITY)
}

#[cfg(feature = "grep")]
#[inline]
fn max_initial_buffer_bytes(max_read_bytes: u64) -> usize {
    usize::try_from(max_read_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(1)
}

#[cfg(feature = "grep")]
fn initial_line_buffer_capacity(max_line_bytes: usize, max_read_bytes: u64) -> usize {
    const DEFAULT_CAPACITY: usize = 8 * 1024;
    const MAX_INITIAL_CAPACITY: usize = 64 * 1024;
    max_line_bytes
        .clamp(DEFAULT_CAPACITY, MAX_INITIAL_CAPACITY)
        .min(max_initial_buffer_bytes(max_read_bytes))
}

#[cfg(feature = "grep")]
fn initial_reader_capacity(max_capped_line_bytes: usize, max_read_bytes: u64) -> usize {
    const DEFAULT_CAPACITY: usize = 8 * 1024;
    const MAX_INITIAL_CAPACITY: usize = 64 * 1024;
    max_capped_line_bytes
        .clamp(DEFAULT_CAPACITY, MAX_INITIAL_CAPACITY)
        .min(max_initial_buffer_bytes(max_read_bytes))
}

#[cfg(feature = "grep")]
fn max_estimated_grep_response_bytes(max_results: usize, max_line_bytes: usize) -> usize {
    max_results.saturating_mul(max_line_bytes)
}

#[cfg(feature = "grep")]
#[inline]
fn estimated_path_response_bytes(path: &std::path::Path) -> usize {
    // Response payloads serialize paths as lossy UTF-8 strings; budget accounting
    // must use the same representation to avoid under-counting non-UTF8 paths.
    path.to_string_lossy().len()
}

#[cfg(feature = "grep")]
fn validate_query(query: &str) -> Result<()> {
    if query.trim().is_empty() {
        return Err(Error::InvalidPath(
            "grep query must not be empty".to_string(),
        ));
    }
    let query_bytes = query.len();
    if query_bytes > MAX_GREP_QUERY_BYTES {
        return Err(Error::InvalidPath(format!(
            "grep query is too large ({query_bytes} bytes; max {MAX_GREP_QUERY_BYTES} bytes)"
        )));
    }
    Ok(())
}

#[cfg(feature = "grep")]
fn max_capped_line_bytes(max_line_bytes: usize) -> usize {
    const BASE_SLACK: usize = 8 * 1024;
    const MIN_CAP: usize = 8 * 1024;
    const MAX_CAP: usize = 2 * 1024 * 1024;
    max_line_bytes
        .saturating_add(BASE_SLACK)
        .clamp(MIN_CAP, MAX_CAP)
}

#[cfg(feature = "grep")]
fn max_capped_line_bytes_for_request(
    max_line_bytes: usize,
    max_read_bytes: u64,
    regex: bool,
) -> usize {
    if regex {
        usize::try_from(max_read_bytes)
            .unwrap_or(usize::MAX)
            .min(MAX_REGEX_LINE_BYTES)
    } else {
        max_capped_line_bytes(max_line_bytes)
    }
}

#[cfg(feature = "grep")]
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    memchr::memmem::find(haystack, needle).is_some()
}

#[cfg(feature = "grep")]
fn update_query_match_state(
    query_window: &mut Vec<u8>,
    query: &[u8],
    chunk: &[u8],
    query_matched: &mut bool,
) {
    if *query_matched {
        return;
    }

    // Fast path: most matches are wholly inside this chunk.
    if contains_subslice(chunk, query) {
        *query_matched = true;
        return;
    }

    let keep = query.len().saturating_sub(1);
    if keep == 0 {
        return;
    }

    // Cross-boundary candidates can only span the previous tail and the first `keep` bytes of
    // this chunk. Reuse `query_window` as scratch and restore its tail afterward.
    if !query_window.is_empty() {
        let old_tail_len = query_window.len();
        let boundary_prefix_len = keep.min(chunk.len());
        if old_tail_len.saturating_add(boundary_prefix_len) >= query.len() {
            query_window.extend_from_slice(&chunk[..boundary_prefix_len]);
            *query_matched = contains_subslice(query_window, query);
            query_window.truncate(old_tail_len);
            if *query_matched {
                return;
            }
        }
    }

    update_query_window_tail(query_window, chunk, keep);
}

#[cfg(feature = "grep")]
fn update_query_window_tail(query_window: &mut Vec<u8>, chunk: &[u8], keep: usize) {
    if keep == 0 {
        query_window.clear();
        return;
    }

    // When the current chunk already has enough bytes, the tail is fully determined by this chunk.
    if chunk.len() >= keep {
        query_window.clear();
        query_window.extend_from_slice(&chunk[chunk.len().saturating_sub(keep)..]);
        return;
    }

    let needed_from_old = keep.saturating_sub(chunk.len());
    if query_window.len() > needed_from_old {
        let start = query_window.len().saturating_sub(needed_from_old);
        query_window.copy_within(start.., 0);
        query_window.truncate(needed_from_old);
    }

    query_window.extend_from_slice(chunk);
}

#[cfg(feature = "grep")]
#[inline]
fn update_single_byte_match_state(query_byte: u8, chunk: &[u8], query_matched: &mut bool) {
    if !*query_matched && memchr::memchr(query_byte, chunk).is_some() {
        *query_matched = true;
    }
}

#[cfg(feature = "grep")]
enum ReadLineCapped {
    Eof,
    TimeLimit,
    Line {
        bytes_read: usize,
        capped: bool,
        contains_query: bool,
        utf8_valid: bool,
    },
}

#[cfg(feature = "grep")]
#[derive(Clone, Copy)]
struct ReadLineCappedOptions<'a> {
    started: Option<&'a Instant>,
    max_walk: Option<Duration>,
    stop_after_cap: bool,
}

#[cfg(feature = "grep")]
impl<'a> ReadLineCappedOptions<'a> {
    const fn new(started: Option<&'a Instant>, max_walk: Option<Duration>) -> Self {
        Self {
            started,
            max_walk,
            stop_after_cap: false,
        }
    }

    const fn with_stop_after_cap(mut self, stop_after_cap: bool) -> Self {
        self.stop_after_cap = stop_after_cap;
        self
    }
}

#[cfg(feature = "grep")]
fn update_utf8_line_validity(
    pending: &mut [u8; 3],
    pending_len: &mut usize,
    utf8_valid: &mut bool,
    mut chunk: &[u8],
) {
    if !*utf8_valid {
        return;
    }

    while *pending_len > 0 {
        if chunk.is_empty() {
            return;
        }
        let needed = 4usize.saturating_sub(*pending_len);
        let take = needed.min(chunk.len());
        let mut combined = [0_u8; 4];
        combined[..*pending_len].copy_from_slice(&pending[..*pending_len]);
        combined[*pending_len..*pending_len + take].copy_from_slice(&chunk[..take]);
        match std::str::from_utf8(&combined[..*pending_len + take]) {
            Ok(_) => {
                *pending_len = 0;
                chunk = &chunk[take..];
            }
            Err(err) => {
                if err.error_len().is_some() {
                    *utf8_valid = false;
                    *pending_len = 0;
                    return;
                }
                let trailing = &combined[err.valid_up_to()..*pending_len + take];
                if trailing.len() > pending.len() {
                    *utf8_valid = false;
                    *pending_len = 0;
                    return;
                }
                pending[..trailing.len()].copy_from_slice(trailing);
                *pending_len = trailing.len();
                chunk = &chunk[take..];
            }
        }
    }

    match std::str::from_utf8(chunk) {
        Ok(_) => {}
        Err(err) => {
            if err.error_len().is_some() {
                *utf8_valid = false;
                *pending_len = 0;
                return;
            }
            let trailing = &chunk[err.valid_up_to()..];
            if trailing.len() > pending.len() {
                *utf8_valid = false;
                *pending_len = 0;
                return;
            }
            pending[..trailing.len()].copy_from_slice(trailing);
            *pending_len = trailing.len();
        }
    }
}

#[cfg(feature = "grep")]
fn read_line_capped<R: BufRead>(
    reader: &mut R,
    line_buf: &mut Vec<u8>,
    max_line_bytes: usize,
    query: Option<&[u8]>,
    query_window: &mut Vec<u8>,
    options: ReadLineCappedOptions<'_>,
) -> std::io::Result<ReadLineCapped> {
    line_buf.clear();
    query_window.clear();
    let single_query_byte = query.and_then(|q| (q.len() == 1).then_some(q[0]));
    let track_utf8 = query.is_some();
    let mut utf8_pending = [0_u8; 3];
    let mut utf8_pending_len = 0_usize;
    let mut utf8_valid = true;
    let mut bytes_read = 0usize;
    let mut capped = false;
    let mut query_matched = false;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            if bytes_read == 0 {
                return Ok(ReadLineCapped::Eof);
            }
            if track_utf8 && utf8_pending_len > 0 {
                utf8_valid = false;
            }
            return Ok(ReadLineCapped::Line {
                bytes_read,
                capped,
                contains_query: query_matched,
                utf8_valid,
            });
        }
        if let (Some(started), Some(limit)) = (options.started, options.max_walk)
            && started.elapsed() >= limit
        {
            return Ok(ReadLineCapped::TimeLimit);
        }

        let line_end = memchr::memchr2(b'\n', b'\r', chunk);
        let (split_at, reached_line_end, ended_with_cr) = match line_end {
            Some(idx) => (idx.saturating_add(1), true, chunk[idx] == b'\r'),
            None => (chunk.len(), false, false),
        };
        let consumed = &chunk[..split_at];
        bytes_read = bytes_read.saturating_add(consumed.len());
        if track_utf8 {
            update_utf8_line_validity(
                &mut utf8_pending,
                &mut utf8_pending_len,
                &mut utf8_valid,
                consumed,
            );
        }

        if let Some(query_byte) = single_query_byte {
            update_single_byte_match_state(query_byte, consumed, &mut query_matched);
        } else if let Some(query) = query {
            update_query_match_state(query_window, query, consumed, &mut query_matched);
        }

        if !capped {
            let remaining = max_line_bytes.saturating_sub(line_buf.len());
            if consumed.len() <= remaining {
                line_buf.extend_from_slice(consumed);
            } else {
                line_buf.extend_from_slice(&consumed[..remaining]);
                capped = true;
            }
        }

        reader.consume(split_at);
        if options.stop_after_cap && capped {
            return Ok(ReadLineCapped::Line {
                bytes_read,
                capped,
                contains_query: query_matched,
                utf8_valid,
            });
        }
        if reached_line_end && ended_with_cr {
            let has_trailing_lf = {
                let next = reader.fill_buf()?;
                !next.is_empty() && next[0] == b'\n'
            };
            if has_trailing_lf {
                if let Some(query_byte) = single_query_byte {
                    update_single_byte_match_state(query_byte, b"\n", &mut query_matched);
                } else if let Some(query) = query {
                    update_query_match_state(query_window, query, b"\n", &mut query_matched);
                }
                if track_utf8 {
                    update_utf8_line_validity(
                        &mut utf8_pending,
                        &mut utf8_pending_len,
                        &mut utf8_valid,
                        b"\n",
                    );
                }
                if !capped {
                    if line_buf.len() < max_line_bytes {
                        line_buf.push(b'\n');
                    } else {
                        capped = true;
                    }
                }
                reader.consume(1);
                bytes_read = bytes_read.saturating_add(1);
            }
        }

        if reached_line_end {
            if track_utf8 && utf8_pending_len > 0 {
                utf8_valid = false;
            }
            return Ok(ReadLineCapped::Line {
                bytes_read,
                capped,
                contains_query: query_matched,
                utf8_valid,
            });
        }
    }
}

#[cfg(feature = "grep")]
fn build_grep_response(
    mut matches: Vec<GrepMatch>,
    diag: TraversalDiagnostics,
    counters: GrepSkipCounters,
    started: &Instant,
    stable_sort: bool,
    sorted_hint: bool,
) -> GrepResponse {
    maybe_sort_grep_matches(&mut matches, stable_sort, sorted_hint);
    GrepResponse {
        matches,
        truncated: diag.truncated(),
        skipped_too_large_files: counters.skipped_too_large_files,
        skipped_non_utf8_files: counters.skipped_non_utf8_files,
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

#[cfg(feature = "grep")]
fn maybe_sort_grep_matches(matches: &mut [GrepMatch], stable_sort: bool, sorted_hint: bool) {
    if !stable_sort || matches.len() <= 1 || sorted_hint {
        return;
    }
    matches.sort_unstable_by(|a, b| a.path.cmp(&b.path).then_with(|| a.line.cmp(&b.line)));
}

#[cfg(feature = "grep")]
#[cfg(test)]
fn matches_sorted_by_path_line(matches: &[GrepMatch]) -> bool {
    matches.windows(2).all(|pair| {
        let left = &pair[0];
        let right = &pair[1];
        match left.path.cmp(&right.path) {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Equal => left.line <= right.line,
            std::cmp::Ordering::Greater => false,
        }
    })
}

#[cfg(feature = "grep")]
#[inline]
fn utf8_prefix_within(input: &str, max_bytes: usize) -> &str {
    let end = input.floor_char_boundary(max_bytes.min(input.len()));
    &input[..end]
}

#[cfg(feature = "grep")]
#[inline]
fn to_owned_utf8_prefix_within(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        input.to_owned()
    } else {
        utf8_prefix_within(input, max_bytes).to_owned()
    }
}

#[cfg(feature = "grep")]
fn maybe_shrink_line_buffer(line_buf: &mut Vec<u8>, retained_hint_bytes: usize) {
    const DEFAULT_RETAINED_CAPACITY: usize = 8 * 1024;
    const MAX_RETAINED_CAPACITY: usize = 256 * 1024;
    const SHRINK_FACTOR: usize = 4;

    let retained_capacity =
        retained_hint_bytes.clamp(DEFAULT_RETAINED_CAPACITY, MAX_RETAINED_CAPACITY);
    if line_buf.capacity() > retained_capacity.saturating_mul(SHRINK_FACTOR) {
        line_buf.clear();
        line_buf.shrink_to(retained_capacity);
    }
}

#[cfg(all(test, feature = "grep"))]
#[path = "grep_tests.rs"]
mod tests;

#[cfg(not(feature = "grep"))]
pub fn grep(ctx: &Context, request: GrepRequest) -> Result<GrepResponse> {
    let _ = ctx;
    let _ = request;
    Err(Error::NotPermitted(
        "grep is not supported: crate feature 'grep' is disabled".to_string(),
    ))
}

#[cfg(feature = "grep")]
pub fn grep(ctx: &Context, request: GrepRequest) -> Result<GrepResponse> {
    ctx.ensure_policy_permission(ctx.policy.permissions.grep, "grep")?;
    validate_query(&request.query)?;
    let is_regex = request.regex;
    let query_bytes = request.query.as_bytes();
    let started = Instant::now();
    let max_walk = ctx.policy.limits.max_walk_ms.map(Duration::from_millis);
    let read_line_options =
        ReadLineCappedOptions::new(Some(&started), max_walk).with_stop_after_cap(is_regex);
    let max_read_bytes = ctx.policy.limits.max_read_bytes;
    let max_line_bytes = ctx.policy.limits.max_line_bytes;
    let max_response_bytes =
        max_estimated_grep_response_bytes(ctx.policy.limits.max_results, max_line_bytes);
    let root_path = ctx.canonical_root(&request.root_id)?;
    let mut matches =
        Vec::<GrepMatch>::with_capacity(initial_match_capacity(ctx.policy.limits.max_results));
    let stable_sort = ctx.policy.traversal.stable_sort;
    let mut matches_sorted = true;
    // Estimated payload-byte guardrail; not a strict process-memory cap.
    let mut estimated_response_bytes = 0usize;
    let mut counters = GrepSkipCounters::default();
    let mut diag = TraversalDiagnostics::default();
    let mut line_buf =
        Vec::<u8>::with_capacity(initial_line_buffer_capacity(max_line_bytes, max_read_bytes));
    let query_window_capacity = if is_regex {
        0
    } else {
        query_bytes.len().saturating_sub(1).min(8 * 1024)
    };
    let mut query_window = Vec::<u8>::with_capacity(query_window_capacity);
    let plain_query = (!is_regex).then_some(query_bytes);
    let has_redact_regexes = ctx.redactor.has_redact_regexes();
    let file_glob = request.glob.as_deref().map(compile_glob).transpose()?;
    let has_path_filters = ctx.has_traversal_path_filters();
    let traversal_open_mode = if file_glob.is_some() {
        TraversalOpenMode::None
    } else {
        TraversalOpenMode::ReadFile
    };
    let walk_root_storage = match request
        .glob
        .as_deref()
        .and_then(derive_safe_traversal_prefix)
    {
        Some(prefix) => {
            let walk_root = root_path.join(&prefix);
            if has_path_filters {
                let prefix_denied_or_skipped =
                    ctx.redactor.is_path_denied(&prefix) || ctx.is_traversal_path_skipped(&prefix);
                if prefix_denied_or_skipped {
                    return Ok(build_grep_response(
                        matches,
                        diag,
                        counters,
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
                    return Ok(build_grep_response(
                        matches,
                        diag,
                        counters,
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

    let regex = if is_regex {
        Some(
            regex::Regex::new(&request.query)
                .map_err(|err| Error::invalid_regex(request.query.clone(), err))?,
        )
    } else {
        None
    };
    let max_capped_line_bytes =
        max_capped_line_bytes_for_request(max_line_bytes, max_read_bytes, is_regex);
    // Reuse a single absolute-path buffer in glob-filter mode to avoid per-file
    // `root_path.join(relative_path)` allocations while lazily opening files.
    let mut open_path_scratch = PathBuf::new();

    diag = match walk_traversal_files(
        ctx,
        &request.root_id,
        root_path,
        walk_root,
        TraversalWalkOptions {
            open_mode: traversal_open_mode,
            max_walk,
        },
        &started,
        |file, diag| {
            let super::traversal::TraversalFile {
                path,
                relative_path,
                opened_file,
            } = file;

            if let Some(glob) = &file_glob
                && !globset_is_match(glob, &relative_path)
            {
                return Ok(std::ops::ControlFlow::Continue(()));
            }

            let (file, meta) = match opened_file {
                Some(opened) => opened,
                None => {
                    let path = match path.as_deref() {
                        Some(path) => path,
                        None => {
                            open_path_scratch.clear();
                            open_path_scratch.push(root_path);
                            open_path_scratch.push(&relative_path);
                            open_path_scratch.as_path()
                        }
                    };
                    match super::io::open_regular_file_for_read(path, &relative_path) {
                        Ok(opened) => opened,
                        Err(Error::IoPath { .. })
                        | Err(Error::Io(_))
                        | Err(Error::InvalidPath(_)) => {
                            // In glob-filter mode we lazily open paths here; treat
                            // non-regular entries (e.g. symlinked directories) as skippable.
                            diag.inc_skipped_io_errors();
                            return Ok(std::ops::ControlFlow::Continue(()));
                        }
                        Err(err) => return Err(err),
                    }
                }
            };
            if meta.len() > ctx.policy.limits.max_read_bytes {
                counters.skipped_too_large_files =
                    counters.skipped_too_large_files.saturating_add(1);
                return Ok(std::ops::ControlFlow::Continue(()));
            }

            let limit = ctx.policy.limits.max_read_bytes.saturating_add(1);
            let mut reader = std::io::BufReader::with_capacity(
                initial_reader_capacity(max_capped_line_bytes, max_read_bytes),
                file.take(limit),
            );
            let mut scanned_bytes = 0_u64;
            let mut line_no = 0_u64;
            let file_match_start = matches.len();
            let file_path_bytes = estimated_path_response_bytes(relative_path.as_path());
            let mut owned_relative_path = relative_path;
            let mut first_match_index = None::<usize>;
            loop {
                let (n, line_was_capped, contains_query, line_utf8_valid) = match read_line_capped(
                    &mut reader,
                    &mut line_buf,
                    max_capped_line_bytes,
                    plain_query,
                    &mut query_window,
                    read_line_options,
                ) {
                    Ok(ReadLineCapped::Eof) => break,
                    Ok(ReadLineCapped::TimeLimit) => {
                        diag.mark_limit_reached(ScanLimitReason::Time);
                        maybe_shrink_line_buffer(&mut line_buf, max_capped_line_bytes);
                        return Ok(std::ops::ControlFlow::Break(()));
                    }
                    Ok(ReadLineCapped::Line {
                        bytes_read,
                        capped,
                        contains_query,
                        utf8_valid,
                    }) => (bytes_read, capped, contains_query, utf8_valid),
                    Err(_) => {
                        matches.truncate(file_match_start);
                        maybe_shrink_line_buffer(&mut line_buf, max_capped_line_bytes);
                        diag.inc_skipped_io_errors();
                        return Ok(std::ops::ControlFlow::Continue(()));
                    }
                };
                let n = match u64::try_from(n) {
                    Ok(n) => n,
                    Err(_) => {
                        matches.truncate(file_match_start);
                        maybe_shrink_line_buffer(&mut line_buf, max_capped_line_bytes);
                        diag.inc_skipped_io_errors();
                        return Ok(std::ops::ControlFlow::Continue(()));
                    }
                };
                scanned_bytes = scanned_bytes.saturating_add(n);
                if scanned_bytes > ctx.policy.limits.max_read_bytes {
                    matches.truncate(file_match_start);
                    maybe_shrink_line_buffer(&mut line_buf, max_capped_line_bytes);
                    counters.skipped_too_large_files =
                        counters.skipped_too_large_files.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
                }

                line_no = line_no.saturating_add(1);
                if is_regex && line_was_capped {
                    matches.truncate(file_match_start);
                    maybe_shrink_line_buffer(&mut line_buf, max_capped_line_bytes);
                    counters.skipped_too_large_files =
                        counters.skipped_too_large_files.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
                }
                // For plain-text grep, treat any invalid UTF-8 in the fully consumed line as a
                // non-UTF8 file skip, even when the query already matched in the retained prefix.
                if !is_regex && !line_utf8_valid {
                    matches.truncate(file_match_start);
                    maybe_shrink_line_buffer(&mut line_buf, max_capped_line_bytes);
                    counters.skipped_non_utf8_files =
                        counters.skipped_non_utf8_files.saturating_add(1);
                    return Ok(std::ops::ControlFlow::Continue(()));
                }
                if !is_regex && !contains_query {
                    if line_was_capped {
                        maybe_shrink_line_buffer(&mut line_buf, max_capped_line_bytes);
                    }
                    continue;
                }
                if line_buf.last() == Some(&b'\n') {
                    let _ = line_buf.pop();
                }
                if line_buf.last() == Some(&b'\r') {
                    let _ = line_buf.pop();
                }
                let line = match std::str::from_utf8(&line_buf) {
                    Ok(line) => line,
                    Err(err) if line_was_capped && err.error_len().is_none() => {
                        std::str::from_utf8(&line_buf[..err.valid_up_to()]).unwrap_or_default()
                    }
                    Err(_) => {
                        matches.truncate(file_match_start);
                        maybe_shrink_line_buffer(&mut line_buf, max_capped_line_bytes);
                        counters.skipped_non_utf8_files =
                            counters.skipped_non_utf8_files.saturating_add(1);
                        return Ok(std::ops::ControlFlow::Continue(()));
                    }
                };
                let ok = regex
                    .as_ref()
                    .map_or_else(|| contains_query, |regex| regex.is_match(line));
                if !ok {
                    if line_was_capped {
                        maybe_shrink_line_buffer(&mut line_buf, max_capped_line_bytes);
                    }
                    continue;
                }
                if matches.len() >= ctx.policy.limits.max_results {
                    diag.mark_limit_reached(ScanLimitReason::Results);
                    return Ok(std::ops::ControlFlow::Break(()));
                }
                let path_bytes = file_path_bytes;
                // If even an empty text payload would exceed budget, stop before expensive
                // redaction/truncation work.
                if estimated_response_bytes.saturating_add(path_bytes) > max_response_bytes {
                    diag.mark_limit_reached(ScanLimitReason::ResponseBytes);
                    return Ok(std::ops::ControlFlow::Break(()));
                }
                let (text, line_truncated) = if has_redact_regexes {
                    match ctx.redactor.redact_text_outcome(line) {
                        crate::redaction::RedactionOutcome::Text(redacted) => {
                            let line_truncated = line_was_capped || redacted.len() > max_line_bytes;
                            let text = match redacted {
                                std::borrow::Cow::Borrowed(redacted) => {
                                    to_owned_utf8_prefix_within(redacted, max_line_bytes)
                                }
                                std::borrow::Cow::Owned(redacted) => {
                                    if redacted.len() <= max_line_bytes {
                                        redacted
                                    } else {
                                        utf8_prefix_within(&redacted, max_line_bytes).to_owned()
                                    }
                                }
                            };
                            (text, line_truncated)
                        }
                        crate::redaction::RedactionOutcome::OutputLimitExceeded => {
                            let marker = crate::redaction::REDACTION_OUTPUT_LIMIT_MARKER;
                            (to_owned_utf8_prefix_within(marker, max_line_bytes), true)
                        }
                    }
                } else {
                    let line_truncated = line_was_capped || line.len() > max_line_bytes;
                    (
                        to_owned_utf8_prefix_within(line, max_line_bytes),
                        line_truncated,
                    )
                };

                // Check response budget before cloning path buffers to avoid wasted allocations
                // when this match would be truncated.
                let entry_bytes = path_bytes.saturating_add(text.len());
                if estimated_response_bytes.saturating_add(entry_bytes) > max_response_bytes {
                    diag.mark_limit_reached(ScanLimitReason::ResponseBytes);
                    return Ok(std::ops::ControlFlow::Break(()));
                }
                estimated_response_bytes = estimated_response_bytes.saturating_add(entry_bytes);
                // Response schema owns `PathBuf` per match. Avoid cloning in the common
                // single-match case by cloning only after the first match already exists.
                let path = match first_match_index {
                    Some(first_idx) => matches[first_idx].path.clone(),
                    None => std::mem::take(&mut owned_relative_path),
                };
                if stable_sort
                    && matches_sorted
                    && matches
                        .last()
                        .is_some_and(|previous| match previous.path.cmp(&path) {
                            std::cmp::Ordering::Greater => true,
                            std::cmp::Ordering::Equal => previous.line > line_no,
                            std::cmp::Ordering::Less => false,
                        })
                {
                    matches_sorted = false;
                }
                let is_first_match_for_file = first_match_index.is_none();
                matches.push(GrepMatch {
                    path,
                    line: line_no,
                    text,
                    line_truncated,
                });
                if is_first_match_for_file {
                    first_match_index = Some(matches.len().saturating_sub(1));
                }
                if line_was_capped {
                    maybe_shrink_line_buffer(&mut line_buf, max_capped_line_bytes);
                }
            }

            maybe_shrink_line_buffer(&mut line_buf, max_capped_line_bytes);
            Ok(std::ops::ControlFlow::Continue(()))
        },
    ) {
        Ok(diag) => diag,
        Err(Error::WalkDirRoot { path, source })
            if source.kind() == std::io::ErrorKind::NotFound
                && path.as_path() != std::path::Path::new(".") =>
        {
            return Ok(build_grep_response(
                matches,
                diag,
                counters,
                &started,
                stable_sort,
                matches_sorted,
            ));
        }
        Err(err) => return Err(err),
    };

    Ok(build_grep_response(
        matches,
        diag,
        counters,
        &started,
        stable_sort,
        matches_sorted,
    ))
}
