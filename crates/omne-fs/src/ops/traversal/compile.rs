use std::borrow::Cow;
use std::path::PathBuf;

use globset::{GlobSet, GlobSetBuilder};

use crate::error::{Error, Result};

const MAX_GLOB_PATTERN_BYTES: usize = 4 * 1024;
const MAX_TRAVERSAL_SKIP_GLOBS: usize = 512;
const MAX_TRAVERSAL_SKIP_GLOBS_TOTAL_BYTES: usize = 64 * 1024;

fn accumulate_skip_glob_pattern_bytes(total: &mut usize, pattern_len: usize) -> Result<()> {
    *total = total.checked_add(pattern_len).ok_or_else(|| {
        Error::InvalidPolicy(
            "invalid traversal.skip_globs: total pattern bytes overflowed usize".to_string(),
        )
    })?;
    if *total > MAX_TRAVERSAL_SKIP_GLOBS_TOTAL_BYTES {
        return Err(Error::InvalidPolicy(format!(
            "invalid traversal.skip_globs: total pattern bytes too large ({} > {MAX_TRAVERSAL_SKIP_GLOBS_TOTAL_BYTES})",
            *total
        )));
    }
    Ok(())
}

fn compile_validated_glob(
    pattern: &str,
    invalid_err: impl Fn(String) -> Error,
) -> Result<globset::Glob> {
    let normalized =
        normalize_and_validate_root_relative_glob_pattern(pattern).map_err(&invalid_err)?;
    crate::path_utils_internal::build_glob_from_normalized(normalized.as_ref())
        .map_err(|err| invalid_err(err.to_string()))
}

pub(super) fn compile_glob(pattern: &str) -> Result<GlobSet> {
    let glob = compile_validated_glob(pattern, |msg| {
        Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {msg}"))
    })?;
    let mut builder = GlobSetBuilder::new();
    builder.add(glob);
    builder
        .build()
        .map_err(|err| Error::InvalidPath(format!("invalid glob pattern {pattern:?}: {err}")))
}

pub(super) fn compile_traversal_skip_globs(patterns: &[String]) -> Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    if patterns.len() > MAX_TRAVERSAL_SKIP_GLOBS {
        return Err(Error::InvalidPolicy(format!(
            "invalid traversal.skip_globs: too many patterns ({} > {MAX_TRAVERSAL_SKIP_GLOBS})",
            patterns.len()
        )));
    }

    let mut builder = GlobSetBuilder::new();
    let mut total_bytes = 0_usize;
    for pattern in patterns {
        accumulate_skip_glob_pattern_bytes(&mut total_bytes, pattern.len())?;
        let glob = compile_validated_glob(pattern, |msg| {
            Error::InvalidPolicy(format!(
                "invalid traversal.skip_globs glob {pattern:?}: {msg}"
            ))
        })?;
        builder.add(glob);
    }

    let set = builder
        .build()
        .map_err(|err| Error::InvalidPolicy(format!("invalid traversal.skip_globs: {err}")))?;
    Ok(Some(set))
}

pub(super) fn derive_safe_traversal_prefix(pattern: &str) -> Option<PathBuf> {
    let normalized = normalize_and_validate_root_relative_glob_pattern(pattern).ok()?;
    collect_literal_traversal_prefix(normalized.as_ref())
}

fn normalize_and_validate_root_relative_glob_pattern(
    pattern: &str,
) -> std::result::Result<Cow<'_, str>, String> {
    if pattern.len() > MAX_GLOB_PATTERN_BYTES {
        return Err(format!(
            "glob pattern too long ({} bytes > {MAX_GLOB_PATTERN_BYTES} bytes)",
            pattern.len()
        ));
    }

    if pattern.trim().is_empty() {
        return Err("glob pattern must not be empty".to_string());
    }

    let normalized = crate::path_utils_internal::normalize_glob_pattern_for_matching(pattern);
    crate::path_utils_internal::validate_root_relative_glob_pattern(normalized.as_ref())
        .map_err(|msg| msg.to_string())?;
    Ok(normalized)
}

fn collect_literal_traversal_prefix(pattern: &str) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for segment in pattern.split('/') {
        if segment.is_empty() || segment == "." {
            continue;
        }

        if reject_unsafe_segment(segment) {
            return None;
        }

        if !segment_is_strict_literal(segment) {
            break;
        }
        out.push(segment);
    }

    if out.as_os_str().is_empty() {
        None
    } else {
        Some(out)
    }
}

fn segment_is_strict_literal(segment: &str) -> bool {
    // Keep this conservative but not overly narrow: only reject bytes that can
    // change glob semantics for the segment itself.
    !segment.is_empty() && !segment.bytes().any(is_segment_glob_meta_byte)
}

#[inline]
const fn is_segment_glob_meta_byte(byte: u8) -> bool {
    matches!(byte, b'*' | b'?' | b'[' | b']' | b'{' | b'}' | b'\\')
}

#[cfg(windows)]
fn reject_unsafe_segment(segment: &str) -> bool {
    use std::path::{Component, Path};

    matches!(
        Path::new(segment).components().next(),
        Some(Component::Prefix(_))
    )
}

#[cfg(not(windows))]
fn reject_unsafe_segment(_: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::accumulate_skip_glob_pattern_bytes;
    use crate::error::Error;

    #[test]
    fn skip_glob_total_bytes_overflow_is_rejected() {
        let mut total = usize::MAX;
        let err = accumulate_skip_glob_pattern_bytes(&mut total, 1)
            .expect_err("overflow should be rejected");
        match err {
            Error::InvalidPolicy(message) => {
                assert!(message.contains("overflowed usize"), "message: {message}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
