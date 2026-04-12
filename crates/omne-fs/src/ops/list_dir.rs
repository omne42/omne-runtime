#[cfg(test)]
use std::borrow::Cow;
use std::cell::OnceCell;
use std::collections::BinaryHeap;
use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

fn initial_heap_capacity(max_entries: usize) -> usize {
    const MAX_INITIAL_HEAP_CAPACITY: usize = 1024;
    max_entries.min(MAX_INITIAL_HEAP_CAPACITY)
}

fn initial_entries_capacity(candidate_count: usize) -> usize {
    const MAX_INITIAL_ENTRIES_CAPACITY: usize = 4096;
    candidate_count.min(MAX_INITIAL_ENTRIES_CAPACITY)
}

fn max_estimated_list_dir_response_bytes(max_entries: usize, max_line_bytes: usize) -> usize {
    max_entries.saturating_mul(max_line_bytes)
}

#[inline]
fn decimal_len_u64(value: u64) -> usize {
    if value == 0 {
        1
    } else {
        value.ilog10() as usize + 1
    }
}

fn runtime_max_entries_cap(max_entries: usize) -> usize {
    // Guardrail for extreme policies/requests: retaining a very large top-k heap can
    // inflate memory well beyond the response-byte budget. Each retained candidate
    // owns an `OsString` name plus heap/ordering metadata, so cap this aggressively.
    const MAX_RUNTIME_RETAINED_ENTRIES: usize = 100_000;
    max_entries.min(MAX_RUNTIME_RETAINED_ENTRIES)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDirRequest {
    pub root_id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub max_entries: Option<usize>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ListDirEntryKind {
    File,
    Dir,
    Symlink,
    Other,
}

impl ListDirEntryKind {
    #[inline]
    const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Symlink => "symlink",
            Self::Other => "other",
        }
    }

    #[inline]
    const fn serialized_len(self) -> usize {
        self.as_str().len()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDirEntry {
    pub path: PathBuf,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: ListDirEntryKind,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListDirResponse {
    pub path: PathBuf,
    pub requested_path: PathBuf,
    pub entries: Vec<ListDirEntry>,
    pub truncated: bool,
    pub skipped_io_errors: u64,
}

#[derive(Debug)]
struct Candidate {
    file_name: OsString,
    cached_lossy_name: OnceCell<String>,
}

impl Candidate {
    #[inline]
    fn from_entry(entry: EntryCandidate) -> Self {
        let EntryCandidate {
            file_name,
            cached_lossy_name,
        } = entry;
        Self {
            file_name,
            cached_lossy_name,
        }
    }

    #[inline]
    fn name(&self) -> &str {
        if let Some(valid_utf8) = self.file_name.to_str() {
            valid_utf8
        } else {
            self.cached_lossy_name
                .get_or_init(|| self.file_name.to_string_lossy().into_owned())
                .as_str()
        }
    }

    #[inline]
    fn into_list_entry(
        self,
        relative_dir: &Path,
        relative_is_root: bool,
        kind: ListDirEntryKind,
        size_bytes: u64,
    ) -> ListDirEntry {
        let path = relative_entry_path_from_root_flag(
            relative_dir,
            relative_is_root,
            self.file_name.as_os_str(),
        );
        let name = match self.file_name.into_string() {
            Ok(valid_utf8) => valid_utf8,
            Err(file_name) => self
                .cached_lossy_name
                .into_inner()
                .unwrap_or_else(|| file_name.to_string_lossy().into_owned()),
        };
        ListDirEntry {
            path,
            name,
            kind,
            size_bytes,
        }
    }
}

impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.file_name == other.file_name
    }
}

impl Eq for Candidate {}

impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name()
            .cmp(other.name())
            .then_with(|| self.file_name.cmp(&other.file_name))
    }
}

enum EntryOutcome {
    Accepted(EntryCandidate),
    Denied,
}

enum CountOnlyOutcome {
    Counted,
    Denied,
}

struct EntryCandidate {
    file_name: OsString,
    cached_lossy_name: OnceCell<String>,
}

impl EntryCandidate {
    #[inline]
    fn compare_name(&self, other: &str) -> std::cmp::Ordering {
        if let Some(valid_utf8) = self.file_name.to_str() {
            valid_utf8.cmp(other)
        } else {
            self.cached_lossy_name
                .get_or_init(|| self.file_name.to_string_lossy().into_owned())
                .as_str()
                .cmp(other)
        }
    }

    #[inline]
    fn sorts_before(&self, other: &Candidate) -> bool {
        self.compare_name(other.name())
            .then_with(|| self.file_name.cmp(&other.file_name))
            == std::cmp::Ordering::Less
    }
}

fn directory_changed_during_list_error(relative_dir: &Path) -> Error {
    Error::InvalidPath(format!(
        "path {} changed during list_dir; refusing to continue",
        relative_dir.display()
    ))
}

fn ensure_directory_identity_unchanged(
    dir: &Path,
    relative_dir: &Path,
    expected_meta: &super::io::DirectoryIdentity,
) -> Result<()> {
    match expected_meta.verify(dir, relative_dir, || {
        directory_changed_during_list_error(relative_dir)
    })? {
        super::io::MetadataIdentityCheck::Verified => Ok(()),
        super::io::MetadataIdentityCheck::Unverifiable => {
            #[cfg(windows)]
            {
                // Some Windows filesystems do not provide stable file IDs.
                // Keep the directory/symlink re-check above and continue.
                Ok(())
            }
            #[cfg(not(windows))]
            {
                Err(Error::InvalidPath(format!(
                    "cannot verify directory identity for path {} on this platform",
                    relative_dir.display()
                )))
            }
        }
    }
}

fn entry_kind_and_size_no_follow(path: &Path) -> std::io::Result<(ListDirEntryKind, u64)> {
    let meta = fs::symlink_metadata(path)?;
    let file_type = meta.file_type();
    if file_type.is_file() {
        Ok((ListDirEntryKind::File, meta.len()))
    } else if file_type.is_dir() {
        Ok((ListDirEntryKind::Dir, 0))
    } else if file_type.is_symlink() {
        Ok((ListDirEntryKind::Symlink, 0))
    } else {
        Ok((ListDirEntryKind::Other, 0))
    }
}

fn process_dir_entry(
    ctx: &Context,
    entry: fs::DirEntry,
    has_deny_globs: bool,
    relative_is_root: bool,
    relative_dir: &Path,
    deny_path_scratch: Option<&mut PathBuf>,
) -> Result<EntryOutcome> {
    let name = entry.file_name();
    if is_entry_path_denied(
        ctx,
        has_deny_globs,
        relative_is_root,
        relative_dir,
        &name,
        deny_path_scratch,
    ) {
        return Ok(EntryOutcome::Denied);
    }
    Ok(EntryOutcome::Accepted(EntryCandidate {
        file_name: name,
        cached_lossy_name: OnceCell::new(),
    }))
}

fn process_dir_entry_count_only(
    ctx: &Context,
    entry: fs::DirEntry,
    relative_is_root: bool,
    relative_dir: &Path,
    deny_path_scratch: Option<&mut PathBuf>,
) -> Result<CountOnlyOutcome> {
    let name = entry.file_name();
    if is_entry_path_denied(
        ctx,
        true,
        relative_is_root,
        relative_dir,
        &name,
        deny_path_scratch,
    ) {
        return Ok(CountOnlyOutcome::Denied);
    }

    Ok(CountOnlyOutcome::Counted)
}

#[inline]
fn is_entry_path_denied(
    ctx: &Context,
    has_deny_globs: bool,
    relative_is_root: bool,
    relative_dir: &Path,
    name: &OsStr,
    deny_path_scratch: Option<&mut PathBuf>,
) -> bool {
    if !has_deny_globs {
        return false;
    }

    if relative_is_root {
        return ctx.redactor.is_path_denied(Path::new(name));
    }

    let Some(deny_path) = deny_path_scratch else {
        // Fallback for internal call-site misuse; should not happen.
        return ctx
            .redactor
            .is_path_denied(relative_dir.join(name).as_path());
    };

    deny_path.push(name);
    let denied = ctx.redactor.is_path_denied(deny_path.as_path());
    let _ = deny_path.pop();
    denied
}

#[cfg(test)]
#[inline]
fn relative_entry_path(relative_dir: &Path, name: &OsStr) -> PathBuf {
    relative_entry_path_from_root_flag(relative_dir, relative_dir == Path::new("."), name)
}

#[inline]
fn relative_entry_path_from_root_flag(
    relative_dir: &Path,
    relative_is_root: bool,
    name: &OsStr,
) -> PathBuf {
    if relative_is_root {
        PathBuf::from(name)
    } else {
        relative_dir.join(name)
    }
}

#[inline]
#[cfg(test)]
fn relative_entry_path_for_deny<'a>(relative_dir: &Path, name: &'a OsStr) -> Cow<'a, Path> {
    if relative_dir == Path::new(".") {
        Cow::Borrowed(Path::new(name))
    } else {
        Cow::Owned(relative_dir.join(name))
    }
}

#[inline]
fn is_list_dir_truncated(
    max_entries: usize,
    zero_limit_truncated: bool,
    scan_budget_truncated: bool,
    response_budget_truncated: bool,
    matched_entries: usize,
    skipped_io_errors: u64,
    materialized_entries: usize,
) -> bool {
    if scan_budget_truncated {
        return true;
    }
    if response_budget_truncated {
        return true;
    }
    if max_entries == 0 {
        return zero_limit_truncated || skipped_io_errors > 0;
    }

    let hit_entry_limit = matched_entries > max_entries;
    let incomplete_due_to_io = skipped_io_errors > 0;
    let incomplete_due_to_materialization =
        !hit_entry_limit && materialized_entries < matched_entries;
    hit_entry_limit || incomplete_due_to_io || incomplete_due_to_materialization
}

#[inline]
fn consume_scan_budget(scanned_entries: &mut u64, max_walk_entries: u64) -> bool {
    if *scanned_entries >= max_walk_entries {
        return false;
    }
    *scanned_entries = scanned_entries.saturating_add(1);
    true
}

fn scan_count_only_entries_without_deny_globs(
    read_dir: fs::ReadDir,
    max_walk_entries: u64,
) -> (bool, u64, bool) {
    let mut skipped_io_errors: u64 = 0;
    let mut scanned_entries: u64 = 0;
    for entry in read_dir {
        if !consume_scan_budget(&mut scanned_entries, max_walk_entries) {
            return (false, skipped_io_errors, true);
        }
        match entry {
            Ok(_) => {
                // With `max_entries=0`, callers only need to know whether any visible entry
                // exists. Without deny rules, a successful `read_dir` entry is sufficient.
                return (true, skipped_io_errors, false);
            }
            Err(_) => {
                skipped_io_errors = skipped_io_errors.saturating_add(1);
            }
        }
    }
    (false, skipped_io_errors, false)
}

fn scan_count_only_entries(
    ctx: &Context,
    read_dir: fs::ReadDir,
    max_walk_entries: u64,
    has_deny_globs: bool,
    relative_is_root: bool,
    relative_dir: &Path,
    mut deny_path_scratch: Option<&mut PathBuf>,
) -> Result<(bool, u64, bool)> {
    if !has_deny_globs {
        return Ok(scan_count_only_entries_without_deny_globs(
            read_dir,
            max_walk_entries,
        ));
    }

    let mut zero_limit_truncated = false;
    let mut skipped_io_errors: u64 = 0;
    let mut scanned_entries: u64 = 0;

    for entry in read_dir {
        if !consume_scan_budget(&mut scanned_entries, max_walk_entries) {
            return Ok((zero_limit_truncated, skipped_io_errors, true));
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                skipped_io_errors = skipped_io_errors.saturating_add(1);
                continue;
            }
        };

        match process_dir_entry_count_only(
            ctx,
            entry,
            relative_is_root,
            relative_dir,
            deny_path_scratch.as_deref_mut(),
        )? {
            CountOnlyOutcome::Counted => {
                // With `max_entries=0`, callers only need to know whether any entry exists.
                // Stop after the first visible match to avoid scanning huge directories.
                zero_limit_truncated = true;
                break;
            }
            CountOnlyOutcome::Denied => {}
        }
    }

    Ok((zero_limit_truncated, skipped_io_errors, false))
}

pub fn list_dir(ctx: &Context, request: ListDirRequest) -> Result<ListDirResponse> {
    ctx.ensure_policy_permission(ctx.policy.permissions.list_dir, "list_dir")?;

    let requested_max_entries = request
        .max_entries
        .unwrap_or(ctx.policy.limits.max_results)
        .min(ctx.policy.limits.max_results);
    let max_entries = runtime_max_entries_cap(requested_max_entries);
    let max_walk_entries = u64::try_from(ctx.policy.limits.max_walk_entries).unwrap_or(u64::MAX);

    let (dir, relative_dir, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let meta = super::io::DirectoryIdentity::capture(&dir, &relative_dir, || {
        Error::InvalidPath(format!(
            "path {} is not a directory",
            relative_dir.display()
        ))
    })?;

    let relative_is_root = relative_dir == Path::new(".");
    let has_deny_globs = !ctx.policy.secrets.deny_globs.is_empty();
    let mut deny_path_scratch = (has_deny_globs && !relative_is_root).then(|| relative_dir.clone());

    let read_dir =
        fs::read_dir(&dir).map_err(|err| Error::io_path("read_dir", &relative_dir, err))?;
    // Revalidate once after opening the iterator to catch swaps between preflight
    // metadata capture and iteration setup without paying an extra metadata probe.
    ensure_directory_identity_unchanged(&dir, &relative_dir, &meta)?;

    if max_entries == 0 {
        let (zero_limit_truncated, skipped_io_errors, scan_budget_truncated) =
            scan_count_only_entries(
                ctx,
                read_dir,
                max_walk_entries,
                has_deny_globs,
                relative_is_root,
                &relative_dir,
                deny_path_scratch.as_mut(),
            )?;
        ensure_directory_identity_unchanged(&dir, &relative_dir, &meta)?;

        let truncated = is_list_dir_truncated(
            max_entries,
            zero_limit_truncated,
            scan_budget_truncated,
            false,
            0,
            skipped_io_errors,
            0,
        );
        return Ok(ListDirResponse {
            path: relative_dir,
            requested_path,
            entries: Vec::new(),
            truncated,
            skipped_io_errors,
        });
    }

    let mut heap = BinaryHeap::<Candidate>::with_capacity(initial_heap_capacity(max_entries));
    let mut matched_entries: usize = 0;
    let mut skipped_io_errors: u64 = 0;
    let mut scanned_entries: u64 = 0;
    let mut scan_budget_truncated = false;

    for entry in read_dir {
        if !consume_scan_budget(&mut scanned_entries, max_walk_entries) {
            scan_budget_truncated = true;
            break;
        }
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                skipped_io_errors = skipped_io_errors.saturating_add(1);
                continue;
            }
        };

        match process_dir_entry(
            ctx,
            entry,
            has_deny_globs,
            relative_is_root,
            &relative_dir,
            deny_path_scratch.as_mut(),
        )? {
            EntryOutcome::Accepted(entry) => {
                matched_entries = matched_entries.saturating_add(1);

                if heap.len() < max_entries {
                    heap.push(Candidate::from_entry(entry));
                } else if let Some(mut top) = heap.peek_mut()
                    && entry.sorts_before(&top)
                {
                    *top = Candidate::from_entry(entry);
                }
            }
            EntryOutcome::Denied => {}
        }
    }
    ensure_directory_identity_unchanged(&dir, &relative_dir, &meta)?;

    let max_response_bytes =
        max_estimated_list_dir_response_bytes(max_entries, ctx.policy.limits.max_line_bytes);
    // Avoid huge upfront allocation when policy/request allows very large `max_entries`.
    // The vector can still grow as needed, but starts from a bounded capacity.
    let mut entries = Vec::with_capacity(initial_entries_capacity(heap.len()));
    // Estimated payload-byte guardrail; not a strict process-memory cap.
    let mut estimated_response_bytes = 0usize;
    let mut response_budget_truncated = false;
    let path_prefix_bytes = relative_dir_path_prefix_bytes(&relative_dir);
    const MIN_LIST_ENTRY_KIND_BYTES: usize = ListDirEntryKind::Dir.serialized_len();
    const MIN_SIZE_BYTES_DECIMAL_LEN: usize = 1;
    // Reuse a single absolute-path buffer while materializing retained entries.
    // This avoids one `PathBuf` allocation per candidate in large directories.
    let mut abs_entry_path = dir;
    for candidate in heap.into_sorted_vec() {
        let base_response_bytes =
            list_entry_base_estimated_response_bytes_from_prefix(path_prefix_bytes, &candidate);
        // Fast precheck: if even the minimum possible serialized entry size no longer fits the
        // response budget, avoid extra metadata syscalls and stop immediately.
        let min_entry_response_bytes =
            base_response_bytes.saturating_add(MIN_LIST_ENTRY_KIND_BYTES);
        let min_entry_response_bytes =
            min_entry_response_bytes.saturating_add(MIN_SIZE_BYTES_DECIMAL_LEN);
        if estimated_response_bytes.saturating_add(min_entry_response_bytes) > max_response_bytes {
            response_budget_truncated = true;
            break;
        }
        // Resolve final type/size only for retained top-k entries, avoiding
        // repeated metadata probes for candidates that were later evicted.
        let entry_name = candidate.file_name.as_os_str();
        abs_entry_path.push(entry_name);
        let kind_and_size = entry_kind_and_size_no_follow(abs_entry_path.as_path());
        let _ = abs_entry_path.pop();
        let (kind, size_bytes) = match kind_and_size {
            Ok(value) => value,
            Err(_) => {
                skipped_io_errors = skipped_io_errors.saturating_add(1);
                // Keep `truncated` based on the visible-entry count gathered during the
                // directory scan; metadata races here should only affect returned entry
                // materialization and `skipped_io_errors`.
                continue;
            }
        };
        let entry_response_bytes = base_response_bytes
            .saturating_add(kind.serialized_len())
            .saturating_add(decimal_len_u64(size_bytes));
        if estimated_response_bytes.saturating_add(entry_response_bytes) > max_response_bytes {
            response_budget_truncated = true;
            break;
        }
        estimated_response_bytes = estimated_response_bytes.saturating_add(entry_response_bytes);
        entries.push(candidate.into_list_entry(&relative_dir, relative_is_root, kind, size_bytes));
    }
    ensure_directory_identity_unchanged(&abs_entry_path, &relative_dir, &meta)?;
    let truncated = is_list_dir_truncated(
        max_entries,
        false,
        scan_budget_truncated,
        response_budget_truncated,
        matched_entries,
        skipped_io_errors,
        entries.len(),
    );

    Ok(ListDirResponse {
        path: relative_dir,
        requested_path,
        entries,
        truncated,
        skipped_io_errors,
    })
}

#[cfg(test)]
fn list_entry_estimated_response_bytes(
    relative_dir: &Path,
    candidate: &Candidate,
    kind: ListDirEntryKind,
    size_bytes: u64,
) -> usize {
    list_entry_estimated_response_bytes_from_prefix(
        relative_dir_path_prefix_bytes(relative_dir),
        candidate,
        kind,
        size_bytes,
    )
}

#[cfg(test)]
#[inline]
fn list_entry_estimated_response_bytes_from_prefix(
    path_prefix_bytes: usize,
    candidate: &Candidate,
    kind: ListDirEntryKind,
    size_bytes: u64,
) -> usize {
    list_entry_base_estimated_response_bytes_from_prefix(path_prefix_bytes, candidate)
        .saturating_add(kind.serialized_len())
        .saturating_add(decimal_len_u64(size_bytes))
}

#[cfg(test)]
fn list_entry_min_estimated_response_bytes(relative_dir: &Path, candidate: &Candidate) -> usize {
    list_entry_min_estimated_response_bytes_from_prefix(
        relative_dir_path_prefix_bytes(relative_dir),
        candidate,
    )
}

#[cfg(test)]
#[inline]
fn list_entry_min_estimated_response_bytes_from_prefix(
    path_prefix_bytes: usize,
    candidate: &Candidate,
) -> usize {
    const MIN_KIND_BYTES: usize = ListDirEntryKind::Dir.serialized_len();
    list_entry_base_estimated_response_bytes_from_prefix(path_prefix_bytes, candidate)
        .saturating_add(MIN_KIND_BYTES)
}

#[inline]
fn list_entry_base_estimated_response_bytes_from_prefix(
    path_prefix_bytes: usize,
    candidate: &Candidate,
) -> usize {
    // Path/name fields are serialized as lossy UTF-8; use display-name bytes so
    // non-UTF8 entries do not under-account response-budget usage.
    let display_name_bytes = candidate.name().len();
    let path_bytes = path_prefix_bytes.saturating_add(display_name_bytes);
    path_bytes.saturating_add(display_name_bytes)
}

#[inline]
fn relative_dir_path_prefix_bytes(relative_dir: &Path) -> usize {
    if relative_dir == Path::new(".") {
        0
    } else {
        relative_dir.to_string_lossy().len().saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::collections::BinaryHeap;
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::path::Path;
    use std::path::PathBuf;

    #[cfg(unix)]
    use super::entry_kind_and_size_no_follow;
    use super::{
        Candidate, ListDirEntryKind, decimal_len_u64, ensure_directory_identity_unchanged,
        initial_entries_capacity, initial_heap_capacity, is_list_dir_truncated,
        list_entry_estimated_response_bytes, list_entry_min_estimated_response_bytes,
        max_estimated_list_dir_response_bytes, relative_entry_path, relative_entry_path_for_deny,
        runtime_max_entries_cap, scan_count_only_entries_without_deny_globs,
    };

    #[test]
    fn initial_heap_capacity_is_capped() {
        assert_eq!(initial_heap_capacity(0), 0);
        assert_eq!(initial_heap_capacity(16), 16);
        assert_eq!(initial_heap_capacity(1024), 1024);
        assert_eq!(initial_heap_capacity(4096), 1024);
    }

    #[test]
    fn initial_entries_capacity_is_capped() {
        assert_eq!(initial_entries_capacity(0), 0);
        assert_eq!(initial_entries_capacity(16), 16);
        assert_eq!(initial_entries_capacity(4096), 4096);
        assert_eq!(initial_entries_capacity(100_000), 4096);
    }

    #[test]
    fn runtime_max_entries_cap_preserves_small_values() {
        assert_eq!(runtime_max_entries_cap(0), 0);
        assert_eq!(runtime_max_entries_cap(16), 16);
        assert_eq!(runtime_max_entries_cap(100_000), 100_000);
    }

    #[test]
    fn runtime_max_entries_cap_bounds_extreme_values() {
        assert_eq!(runtime_max_entries_cap(100_001), 100_000);
        assert_eq!(runtime_max_entries_cap(1_000_000), 100_000);
    }

    #[test]
    fn runtime_cap_overflow_sets_truncated_via_entry_limit_rule() {
        let capped = runtime_max_entries_cap(1_000_000);
        assert_eq!(capped, 100_000);
        assert!(is_list_dir_truncated(
            capped,
            false,
            false,
            false,
            capped.saturating_add(1),
            0,
            capped
        ));
    }

    #[test]
    fn candidate_heap_into_sorted_vec_preserves_display_name_then_path_order() {
        let mut heap = BinaryHeap::new();
        heap.push(Candidate {
            file_name: OsString::from("b-alpha"),
            cached_lossy_name: std::cell::OnceCell::new(),
        });
        heap.push(Candidate {
            file_name: OsString::from("a-beta"),
            cached_lossy_name: std::cell::OnceCell::new(),
        });
        heap.push(Candidate {
            file_name: OsString::from("a-alpha"),
            cached_lossy_name: std::cell::OnceCell::new(),
        });

        let ordered = heap
            .into_sorted_vec()
            .into_iter()
            .map(|candidate| {
                (
                    candidate.name().to_string(),
                    PathBuf::from(candidate.file_name.as_os_str()),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            ordered,
            vec![
                ("a-alpha".to_string(), PathBuf::from("a-alpha")),
                ("a-beta".to_string(), PathBuf::from("a-beta")),
                ("b-alpha".to_string(), PathBuf::from("b-alpha")),
            ]
        );
    }

    #[test]
    fn relative_entry_path_uses_file_name_for_root_dot() {
        let path = relative_entry_path(std::path::Path::new("."), OsStr::new("a.txt"));
        assert_eq!(path, PathBuf::from("a.txt"));
    }

    #[test]
    fn relative_entry_path_joins_non_root_parent() {
        let path = relative_entry_path(std::path::Path::new("nested"), OsStr::new("a.txt"));
        assert_eq!(path, PathBuf::from("nested").join("a.txt"));
    }

    #[test]
    fn relative_entry_path_for_deny_borrows_root_dot() {
        let path = relative_entry_path_for_deny(std::path::Path::new("."), OsStr::new("a.txt"));
        assert!(matches!(path, Cow::Borrowed(_)));
        assert_eq!(path.as_ref(), std::path::Path::new("a.txt"));
    }

    #[test]
    fn relative_entry_path_for_deny_joins_non_root_parent() {
        let path =
            relative_entry_path_for_deny(std::path::Path::new("nested"), OsStr::new("a.txt"));
        assert_eq!(path.as_ref(), std::path::Path::new("nested").join("a.txt"));
    }

    #[test]
    fn truncated_when_visible_entries_exceed_limit() {
        assert!(is_list_dir_truncated(2, false, false, false, 3, 0, 2));
    }

    #[test]
    fn not_truncated_when_within_limit_and_no_io_losses() {
        assert!(!is_list_dir_truncated(3, false, false, false, 2, 0, 2));
    }

    #[test]
    fn truncated_when_metadata_losses_drop_entries_under_limit() {
        assert!(is_list_dir_truncated(4, false, false, false, 2, 1, 1));
    }

    #[test]
    fn truncated_when_read_dir_losses_occur_within_limit() {
        assert!(is_list_dir_truncated(4, false, false, false, 2, 1, 2));
    }

    #[test]
    fn truncated_when_response_budget_is_hit() {
        assert!(is_list_dir_truncated(4, false, false, true, 2, 0, 2));
    }

    #[test]
    fn truncated_when_scan_budget_is_hit() {
        assert!(is_list_dir_truncated(4, false, true, false, 2, 0, 2));
    }

    #[test]
    fn zero_max_entries_uses_zero_limit_flag() {
        assert!(!is_list_dir_truncated(0, false, false, false, 0, 0, 0));
        assert!(is_list_dir_truncated(0, true, false, false, 0, 0, 0));
        assert!(is_list_dir_truncated(0, false, true, false, 0, 0, 0));
        assert!(is_list_dir_truncated(0, false, false, false, 0, 1, 0));
    }

    #[test]
    fn count_only_scan_without_deny_globs_detects_visible_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("visible.txt"), "x").expect("write");
        let read_dir = std::fs::read_dir(dir.path()).expect("read_dir");

        let (zero_limit_truncated, skipped_io_errors, scan_budget_truncated) =
            scan_count_only_entries_without_deny_globs(read_dir, 1);
        assert!(zero_limit_truncated);
        assert_eq!(skipped_io_errors, 0);
        assert!(!scan_budget_truncated);
    }

    #[test]
    fn count_only_scan_without_deny_globs_handles_empty_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let read_dir = std::fs::read_dir(dir.path()).expect("read_dir");

        let (zero_limit_truncated, skipped_io_errors, scan_budget_truncated) =
            scan_count_only_entries_without_deny_globs(read_dir, 1);
        assert!(!zero_limit_truncated);
        assert_eq!(skipped_io_errors, 0);
        assert!(!scan_budget_truncated);
    }

    #[test]
    fn count_only_scan_without_deny_globs_truncates_when_scan_budget_is_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("visible.txt"), "x").expect("write");
        let read_dir = std::fs::read_dir(dir.path()).expect("read_dir");

        let (zero_limit_truncated, skipped_io_errors, scan_budget_truncated) =
            scan_count_only_entries_without_deny_globs(read_dir, 0);
        assert!(!zero_limit_truncated);
        assert_eq!(skipped_io_errors, 0);
        assert!(scan_budget_truncated);
    }

    #[test]
    fn max_response_bytes_scales_with_requested_entries() {
        assert_eq!(max_estimated_list_dir_response_bytes(0, 4096), 0);
        assert_eq!(max_estimated_list_dir_response_bytes(3, 4096), 12_288);
    }

    #[test]
    fn entry_response_bytes_include_path_name_and_kind() {
        let candidate = Candidate {
            file_name: OsString::from("file.txt"),
            cached_lossy_name: std::cell::OnceCell::new(),
        };
        let size_bytes = 12_345_u64;
        let bytes = list_entry_estimated_response_bytes(
            std::path::Path::new("nested"),
            &candidate,
            ListDirEntryKind::File,
            size_bytes,
        );
        assert!(
            bytes
                >= "nested/file.txt".len()
                    + "file.txt".len()
                    + ListDirEntryKind::File.as_str().len()
                    + decimal_len_u64(size_bytes)
        );
    }

    #[cfg(unix)]
    #[test]
    fn entry_response_bytes_account_for_lossy_non_utf8_paths() {
        use std::os::unix::ffi::OsStringExt;

        let relative_dir = PathBuf::from(OsString::from_vec(vec![0xff]));
        let candidate = Candidate {
            file_name: OsString::from_vec(vec![0xfe]),
            cached_lossy_name: std::cell::OnceCell::new(),
        };

        let bytes = list_entry_estimated_response_bytes(
            relative_dir.as_path(),
            &candidate,
            ListDirEntryKind::File,
            0,
        );
        let display_name_bytes = candidate.name().len();
        let expected_min = relative_dir
            .to_string_lossy()
            .len()
            .saturating_add(1)
            .saturating_add(display_name_bytes)
            .saturating_add(display_name_bytes)
            .saturating_add(ListDirEntryKind::File.as_str().len())
            .saturating_add(decimal_len_u64(0));
        assert!(bytes >= expected_min);
    }

    #[test]
    fn min_entry_response_bytes_is_lower_bound_for_all_kinds() {
        let candidate = Candidate {
            file_name: OsString::from("file.txt"),
            cached_lossy_name: std::cell::OnceCell::new(),
        };
        let min_bytes = list_entry_min_estimated_response_bytes(Path::new("nested"), &candidate);
        for kind in [
            ListDirEntryKind::Dir,
            ListDirEntryKind::File,
            ListDirEntryKind::Other,
            ListDirEntryKind::Symlink,
        ] {
            let exact =
                list_entry_estimated_response_bytes(Path::new("nested"), &candidate, kind, 0);
            assert!(min_bytes <= exact);
        }
    }

    #[test]
    fn entry_response_bytes_account_for_size_digits() {
        let candidate = Candidate {
            file_name: OsString::from("a"),
            cached_lossy_name: std::cell::OnceCell::new(),
        };
        let small = list_entry_estimated_response_bytes(
            Path::new("."),
            &candidate,
            ListDirEntryKind::File,
            9,
        );
        let large = list_entry_estimated_response_bytes(
            Path::new("."),
            &candidate,
            ListDirEntryKind::File,
            10_000,
        );
        assert!(large > small);
    }

    #[cfg(unix)]
    #[test]
    fn sorts_before_caches_lossy_name_for_non_utf8_entries() {
        use std::os::unix::ffi::OsStringExt;

        let candidate = super::EntryCandidate {
            file_name: OsString::from_vec(vec![0xff]),
            cached_lossy_name: std::cell::OnceCell::new(),
        };
        let other = Candidate {
            file_name: OsString::from("y"),
            cached_lossy_name: std::cell::OnceCell::new(),
        };

        let _ = candidate.sorts_before(&other);
        assert!(candidate.cached_lossy_name.get().is_some());
        let first_cached = candidate.cached_lossy_name.get().cloned();
        let _ = candidate.sorts_before(&other);
        assert_eq!(candidate.cached_lossy_name.get().cloned(), first_cached);
    }

    #[cfg(unix)]
    #[test]
    fn entry_kind_no_follow_reports_symlink_after_replacement() {
        let dir = tempfile::tempdir().expect("tempdir");
        let outside = dir.path().join("outside.txt");
        std::fs::write(&outside, "outside target").expect("write outside");

        let victim = dir.path().join("victim.txt");
        std::fs::write(&victim, "x").expect("write victim");
        std::fs::remove_file(&victim).expect("remove victim");
        std::os::unix::fs::symlink(&outside, &victim).expect("create symlink");

        let (kind, size_bytes) = entry_kind_and_size_no_follow(&victim).expect("metadata");
        assert_eq!(kind, ListDirEntryKind::Symlink);
        assert_eq!(size_bytes, 0);
    }

    #[test]
    fn ensure_directory_identity_unchanged_detects_replaced_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let listed = dir.path().join("listed");
        std::fs::create_dir(&listed).expect("create listed dir");
        let expected =
            super::super::io::DirectoryIdentity::capture(&listed, Path::new("listed"), || {
                crate::error::Error::InvalidPath("listed is not a directory".to_string())
            })
            .expect("metadata before");

        let moved = dir.path().join("listed-old");
        std::fs::rename(&listed, &moved).expect("rename old dir");
        std::fs::create_dir(&listed).expect("recreate listed dir");

        let result = ensure_directory_identity_unchanged(&listed, Path::new("listed"), &expected);
        match result {
            Err(crate::error::Error::InvalidPath(message)) => {
                assert!(message.contains("changed during list_dir"));
            }
            Ok(()) => {
                #[cfg(windows)]
                {}
                #[cfg(not(windows))]
                panic!("directory identity change should be rejected");
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
}
