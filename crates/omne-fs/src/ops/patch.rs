use std::path::PathBuf;
#[cfg(feature = "patch")]
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

use super::Context;

#[cfg(feature = "patch")]
use diffy::{Line, Patch, apply};

#[cfg(feature = "patch")]
const MAX_PATCH_WORKING_SET_BYTES: u64 = 512 * 1024 * 1024;

#[cfg(feature = "patch")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatchHeaderPathError {
    EmptyPath,
    AbsolutePath,
    ParentDir,
    WindowsPrefix,
}

#[cfg(feature = "patch")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatchHeaderMatchResult {
    Match,
    Mismatch,
    Invalid(PatchHeaderPathError),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchRequest {
    pub root_id: String,
    pub path: PathBuf,
    pub patch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchResponse {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_path: Option<PathBuf>,
    /// Final on-disk file size when the patch changes content; `0` for a no-op patch.
    pub bytes_written: u64,
}

#[cfg(not(feature = "patch"))]
pub fn apply_unified_patch(ctx: &Context, request: PatchRequest) -> Result<PatchResponse> {
    let _ = ctx;
    let _ = request;
    Err(Error::NotPermitted(
        "patch is not supported: crate feature 'patch' is disabled".to_string(),
    ))
}

#[cfg(feature = "patch")]
pub fn apply_unified_patch(ctx: &Context, request: PatchRequest) -> Result<PatchResponse> {
    ctx.ensure_write_operation_allowed(&request.root_id, ctx.policy.permissions.patch, "patch")?;
    let (path, relative, requested_path) =
        ctx.canonical_path_in_root(&request.root_id, &request.path)?;

    let max_patch_bytes = ctx
        .policy
        .limits
        .max_patch_bytes
        .unwrap_or(ctx.policy.limits.max_read_bytes);
    let patch_bytes = u64::try_from(request.patch.len()).unwrap_or(u64::MAX);
    if patch_bytes > max_patch_bytes {
        return Err(Error::InputTooLarge {
            size_bytes: patch_bytes,
            max_bytes: max_patch_bytes,
        });
    }

    let parsed = Patch::from_str(&request.patch)
        .map_err(|err| Error::Patch(format!("{}: {err}", relative.display())))?;
    ensure_patch_headers_match_target(&parsed, &requested_path, &relative)?;

    let (content, identity) = super::io::read_string_limited_with_identity(
        &path,
        &relative,
        ctx.policy.limits.max_read_bytes,
    )?;
    let estimated_updated_len =
        estimate_patched_content_len(content.len(), &parsed).ok_or_else(|| {
            Error::Patch(format!("{}: patch size delta overflow", relative.display()))
        })?;
    if estimated_updated_len > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: relative.clone(),
            size_bytes: estimated_updated_len,
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }
    let max_patch_working_set_bytes = effective_patch_working_set_limit(
        ctx.policy.limits.max_read_bytes,
        max_patch_bytes,
        ctx.policy.limits.max_write_bytes,
    );
    // Guard against extreme peak RSS from holding input, patch text, and patched output together.
    let estimated_working_set_bytes = estimated_patch_working_set_bytes(
        content.len(),
        request.patch.len(),
        estimated_updated_len,
    )
    .ok_or(Error::InputTooLarge {
        size_bytes: u64::MAX,
        max_bytes: max_patch_working_set_bytes,
    })?;
    if estimated_working_set_bytes > max_patch_working_set_bytes {
        return Err(Error::InputTooLarge {
            size_bytes: estimated_working_set_bytes,
            max_bytes: max_patch_working_set_bytes,
        });
    }

    let updated = apply(&content, &parsed)
        .map_err(|err| Error::Patch(format!("{}: {err}", relative.display())))?;

    let updated_len = u64::try_from(updated.len()).unwrap_or(u64::MAX);
    if updated_len > ctx.policy.limits.max_write_bytes {
        return Err(Error::FileTooLarge {
            path: relative.clone(),
            size_bytes: updated_len,
            max_bytes: ctx.policy.limits.max_write_bytes,
        });
    }

    // Fast path: most real patches change byte length, so avoid a full string
    // equality scan when lengths already differ.
    let changed = updated.len() != content.len() || updated != content;
    if changed {
        super::io::write_bytes_atomic_checked(
            &path,
            &relative,
            updated.as_bytes(),
            identity,
            ctx.policy.limits.preserve_unix_xattrs,
        )?;
    }
    Ok(PatchResponse {
        path: relative,
        requested_path: Some(requested_path),
        bytes_written: if changed { updated_len } else { 0 },
    })
}

#[cfg(feature = "patch")]
fn ensure_patch_headers_match_target(
    patch: &Patch<'_, str>,
    requested_path: &Path,
    relative: &Path,
) -> Result<()> {
    let original_header = required_patch_header("original", patch.original(), relative)?;
    let modified_header = required_patch_header("modified", patch.modified(), relative)?;
    if patch_uses_diffy_default_filenames(original_header, modified_header) {
        return Ok(());
    }
    let allow_git_prefix_strip =
        patch_headers_form_git_prefixed_pair(original_header, modified_header);

    for (label, header) in [("original", original_header), ("modified", modified_header)] {
        match patch_header_matches_path(header, requested_path, allow_git_prefix_strip) {
            PatchHeaderMatchResult::Match => {}
            PatchHeaderMatchResult::Mismatch => {
                return Err(Error::Patch(format!(
                    "{}: patch {label} header '{header}' does not match target '{}'",
                    relative.display(),
                    requested_path.display()
                )));
            }
            PatchHeaderMatchResult::Invalid(kind) => {
                return Err(Error::Patch(format!(
                    "{}: patch {label} header '{header}' is invalid ({})",
                    relative.display(),
                    patch_header_path_error_message(kind)
                )));
            }
        }
    }

    Ok(())
}

#[cfg(feature = "patch")]
fn required_patch_header<'a>(
    label: &str,
    header: Option<&'a str>,
    relative: &Path,
) -> Result<&'a str> {
    header.ok_or_else(|| {
        Error::Patch(format!(
            "{}: patch {label} header is missing",
            relative.display()
        ))
    })
}

#[cfg(feature = "patch")]
fn patch_uses_diffy_default_filenames(original_header: &str, modified_header: &str) -> bool {
    original_header == "original" && modified_header == "modified"
}

#[cfg(feature = "patch")]
fn estimate_patched_content_len(content_len: usize, patch: &Patch<'_, str>) -> Option<u64> {
    let mut delta: i128 = 0;
    for hunk in patch.hunks() {
        for line in hunk.lines() {
            let signed_len = match line {
                Line::Context(_) => 0,
                Line::Insert(text) => i128::try_from(text.len()).ok()?,
                Line::Delete(text) => -i128::try_from(text.len()).ok()?,
            };
            delta = delta.checked_add(signed_len)?;
        }
    }

    let content_len = i128::try_from(content_len).ok()?;
    let estimated = content_len.checked_add(delta)?;
    if estimated < 0 {
        return None;
    }
    u64::try_from(estimated).ok()
}

#[cfg(feature = "patch")]
fn estimated_patch_working_set_bytes(
    content_len: usize,
    patch_len: usize,
    updated_len: u64,
) -> Option<u64> {
    let content_len = u64::try_from(content_len).ok()?;
    let patch_len = u64::try_from(patch_len).ok()?;
    content_len.checked_add(patch_len)?.checked_add(updated_len)
}

#[cfg(feature = "patch")]
fn effective_patch_working_set_limit(
    max_read_bytes: u64,
    max_patch_bytes: u64,
    max_write_bytes: u64,
) -> u64 {
    max_read_bytes
        .saturating_add(max_patch_bytes)
        .saturating_add(max_write_bytes)
        .min(MAX_PATCH_WORKING_SET_BYTES)
}

#[cfg(feature = "patch")]
fn patch_header_matches_path(
    header: &str,
    requested_path: &Path,
    allow_git_prefix_strip: bool,
) -> PatchHeaderMatchResult {
    let normalized_requested = crate::path_utils_internal::normalize_path_lexical(requested_path);
    let mut invalid = None;

    match normalized_patch_header_path(header, false) {
        NormalizedPatchHeaderPath::Path(normalized_header) => {
            if normalized_paths_match(&normalized_header, &normalized_requested) {
                return PatchHeaderMatchResult::Match;
            }
        }
        NormalizedPatchHeaderPath::Invalid(kind) => invalid = Some(kind),
        NormalizedPatchHeaderPath::MissingGitPrefix => {}
    }

    if allow_git_prefix_strip {
        match normalized_patch_header_path(header, true) {
            NormalizedPatchHeaderPath::Path(normalized_header) => {
                if normalized_paths_match(&normalized_header, &normalized_requested) {
                    return PatchHeaderMatchResult::Match;
                }
            }
            NormalizedPatchHeaderPath::Invalid(kind) => invalid = Some(kind),
            NormalizedPatchHeaderPath::MissingGitPrefix => {}
        }
    }

    invalid
        .map(PatchHeaderMatchResult::Invalid)
        .unwrap_or(PatchHeaderMatchResult::Mismatch)
}

#[cfg(feature = "patch")]
fn normalized_paths_match(a: &Path, b: &Path) -> bool {
    crate::path_utils::paths_equal_case_insensitive(a, b)
}

#[cfg(feature = "patch")]
fn patch_headers_form_git_prefixed_pair(original_header: &str, modified_header: &str) -> bool {
    (strip_prefixed_non_empty(original_header, "a/").is_some()
        && strip_prefixed_non_empty(modified_header, "b/").is_some())
        || (strip_prefixed_non_empty(original_header, "b/").is_some()
            && strip_prefixed_non_empty(modified_header, "a/").is_some())
}

#[cfg(feature = "patch")]
enum NormalizedPatchHeaderPath {
    Path(PathBuf),
    Invalid(PatchHeaderPathError),
    MissingGitPrefix,
}

#[cfg(feature = "patch")]
fn normalized_patch_header_path(header: &str, strip_git_prefix: bool) -> NormalizedPatchHeaderPath {
    let mut value = header;
    if strip_git_prefix {
        value = match strip_git_patch_prefix(value) {
            Some(stripped) => stripped,
            None => return NormalizedPatchHeaderPath::MissingGitPrefix,
        };
    }
    value = strip_leading_current_dir_segments(value);
    if value.is_empty() {
        return NormalizedPatchHeaderPath::Invalid(PatchHeaderPathError::EmptyPath);
    }

    let header_path = Path::new(value);
    patch_header_path_error(header_path).map_or_else(
        || {
            NormalizedPatchHeaderPath::Path(crate::path_utils_internal::normalize_path_lexical(
                header_path,
            ))
        },
        NormalizedPatchHeaderPath::Invalid,
    )
}

#[cfg(feature = "patch")]
fn strip_git_patch_prefix(header: &str) -> Option<&str> {
    strip_prefixed_non_empty(header, "a/").or_else(|| strip_prefixed_non_empty(header, "b/"))
}

#[cfg(feature = "patch")]
fn strip_prefixed_non_empty<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let stripped = value.strip_prefix(prefix)?;
    (!stripped.is_empty()).then_some(stripped)
}

#[cfg(feature = "patch")]
fn strip_leading_current_dir_segments(mut value: &str) -> &str {
    while let Some(stripped) = value.strip_prefix("./") {
        value = stripped;
    }
    value
}

#[cfg(feature = "patch")]
fn patch_header_path_error(path: &Path) -> Option<PatchHeaderPathError> {
    for component in path.components() {
        match component {
            Component::ParentDir => return Some(PatchHeaderPathError::ParentDir),
            Component::RootDir => return Some(PatchHeaderPathError::AbsolutePath),
            Component::Prefix(_) => return Some(PatchHeaderPathError::WindowsPrefix),
            _ => {}
        }
    }
    None
}

#[cfg(feature = "patch")]
const fn patch_header_path_error_message(kind: PatchHeaderPathError) -> &'static str {
    match kind {
        PatchHeaderPathError::EmptyPath => "empty path",
        PatchHeaderPathError::AbsolutePath => "absolute path",
        PatchHeaderPathError::ParentDir => "parent-dir segment",
        PatchHeaderPathError::WindowsPrefix => "windows path prefix",
    }
}

#[cfg(all(test, feature = "patch"))]
mod tests {
    use super::*;

    #[test]
    fn missing_patch_header_is_rejected() {
        let err = required_patch_header("original", None, Path::new("file.txt"))
            .expect_err("missing header should be rejected");
        match err {
            Error::Patch(msg) => assert!(
                msg.contains("patch original header is missing"),
                "unexpected message: {msg}"
            ),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn patch_header_prefixes_are_normalized_before_compare() {
        assert_eq!(
            patch_header_matches_path("a/./nested/file.txt", Path::new("nested/file.txt"), true),
            PatchHeaderMatchResult::Match
        );
    }

    #[test]
    fn diffy_default_headers_are_accepted() {
        let patch = Patch::from_str(
            "\
--- original
+++ modified
@@ -1 +1 @@
-one
+ONE
",
        )
        .expect("parse patch");

        ensure_patch_headers_match_target(&patch, Path::new("file.txt"), Path::new("file.txt"))
            .expect("default headers should be accepted");
    }

    #[test]
    fn path_bound_headers_with_common_prefixes_are_accepted() {
        let patch = Patch::from_str(
            "\
--- a/./nested/file.txt
+++ b/nested/file.txt
@@ -1 +1 @@
-one
+ONE
",
        )
        .expect("parse patch");

        ensure_patch_headers_match_target(
            &patch,
            Path::new("nested/file.txt"),
            Path::new("nested/file.txt"),
        )
        .expect("headers should match target path");
    }

    #[test]
    fn literal_a_prefixed_target_path_is_accepted_without_git_prefix_stripping() {
        let patch = Patch::from_str(
            "\
--- a/file.txt
+++ a/file.txt
@@ -1 +1 @@
-one
+ONE
",
        )
        .expect("parse patch");

        ensure_patch_headers_match_target(&patch, Path::new("a/file.txt"), Path::new("a/file.txt"))
            .expect("literal a/ path should match");
    }

    #[test]
    fn literal_b_prefixed_target_path_is_accepted_without_git_prefix_stripping() {
        let patch = Patch::from_str(
            "\
--- b/file.txt
+++ b/file.txt
@@ -1 +1 @@
-one
+ONE
",
        )
        .expect("parse patch");

        ensure_patch_headers_match_target(&patch, Path::new("b/file.txt"), Path::new("b/file.txt"))
            .expect("literal b/ path should match");
    }

    #[test]
    fn patch_headers_with_parent_dir_segments_are_rejected() {
        let patch = Patch::from_str(
            "\
--- a/../file.txt
+++ b/../file.txt
@@ -1 +1 @@
-one
+ONE
",
        )
        .expect("parse patch");

        let err =
            ensure_patch_headers_match_target(&patch, Path::new("file.txt"), Path::new("file.txt"))
                .expect_err("parent-dir segments should be rejected");
        match err {
            Error::Patch(message) => {
                assert!(
                    message.contains("a/../file.txt"),
                    "unexpected message: {message}"
                );
                assert!(
                    message.contains("is invalid (parent-dir segment)"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn patch_headers_with_absolute_paths_are_rejected() {
        let patch = Patch::from_str(
            "\
--- /abs/file.txt
+++ /abs/file.txt
@@ -1 +1 @@
-one
+ONE
",
        )
        .expect("parse patch");

        let err = ensure_patch_headers_match_target(
            &patch,
            Path::new("abs/file.txt"),
            Path::new("abs/file.txt"),
        )
        .expect_err("absolute headers should be rejected");
        match err {
            Error::Patch(message) => {
                assert!(
                    message.contains("/abs/file.txt"),
                    "unexpected message: {message}"
                );
                assert!(
                    message.contains("is invalid (absolute path)"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn patch_headers_with_mismatched_target_are_rejected() {
        let patch = Patch::from_str(
            "\
--- a/other.txt
+++ b/other.txt
@@ -1 +1 @@
-one
+ONE
",
        )
        .expect("parse patch");

        let err =
            ensure_patch_headers_match_target(&patch, Path::new("file.txt"), Path::new("file.txt"))
                .expect_err("mismatched headers should be rejected");
        match err {
            Error::Patch(message) => {
                assert!(
                    message.contains("does not match target"),
                    "unexpected message: {message}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn estimate_patched_content_len_tracks_insert_delete_delta() {
        let patch = Patch::from_str(
            "\
--- a/file.txt
+++ b/file.txt
@@ -1 +1,2 @@
 one
+two
",
        )
        .expect("parse patch");

        assert_eq!(estimate_patched_content_len(4, &patch), Some(8));
    }

    #[test]
    fn estimated_patch_working_set_bytes_sums_components() {
        assert_eq!(
            estimated_patch_working_set_bytes(1024, 2048, 4096),
            Some(7168)
        );
    }

    #[test]
    fn estimated_patch_working_set_bytes_detects_overflow() {
        assert_eq!(
            estimated_patch_working_set_bytes(usize::MAX, usize::MAX, u64::MAX),
            None
        );
    }

    #[test]
    fn effective_patch_working_set_limit_uses_policy_derived_budget() {
        assert_eq!(effective_patch_working_set_limit(10, 20, 30), 60);
    }

    #[test]
    fn effective_patch_working_set_limit_respects_hard_cap() {
        assert_eq!(
            effective_patch_working_set_limit(u64::MAX, u64::MAX, u64::MAX),
            MAX_PATCH_WORKING_SET_BYTES
        );
    }

    #[cfg(windows)]
    #[test]
    fn patch_header_compare_is_case_insensitive_on_windows() {
        assert_eq!(
            patch_header_matches_path("a/file.txt", Path::new("File.txt"), true),
            PatchHeaderMatchResult::Match
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn patch_header_compare_remains_case_sensitive_on_non_windows() {
        assert_eq!(
            patch_header_matches_path("a/file.txt", Path::new("File.txt"), true),
            PatchHeaderMatchResult::Mismatch
        );
    }
}
