//! Path utilities used across policy/path validation and traversal.
//!
//! This module is intentionally **lexical**: it does not touch the filesystem and therefore does
//! not resolve symlinks. Its job is to normalize and compare paths in a way that is predictable
//! across platforms.
//!
//! Invariants of `normalize_path_lexical`:
//! - Removes `.` segments.
//! - Resolves `..` against preceding *normal* segments when possible.
//! - Preserves leading `..` for relative paths (e.g. `../../a/../b` → `../../b`).
//! - For absolute paths, `..` cannot escape the filesystem root (e.g. `/../etc` → `/etc`).
//! - On Windows, preserves path prefixes (Disk/UNC/verbatim) and does not drop them when
//!   normalizing.
use std::borrow::Cow;
#[cfg(windows)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use globset::GlobBuilder;

#[cfg(windows)]
#[inline]
pub(crate) fn normalize_glob_pattern(pattern: &str) -> Cow<'_, str> {
    if !pattern.contains('\\') {
        return Cow::Borrowed(pattern);
    }
    Cow::Owned(pattern.replace('\\', "/"))
}

#[cfg(not(windows))]
#[inline]
pub(crate) fn normalize_glob_pattern(pattern: &str) -> Cow<'_, str> {
    Cow::Borrowed(pattern)
}

pub(crate) fn normalize_glob_pattern_for_matching(pattern: &str) -> Cow<'_, str> {
    match normalize_glob_pattern(pattern) {
        Cow::Borrowed(normalized) => {
            let mut trimmed = normalized;
            while let Some(rest) = trimmed.strip_prefix("./") {
                trimmed = rest;
            }
            if trimmed.is_empty() {
                Cow::Borrowed(".")
            } else {
                Cow::Borrowed(trimmed)
            }
        }
        Cow::Owned(normalized) => {
            let mut trimmed = normalized.as_str();
            while let Some(rest) = trimmed.strip_prefix("./") {
                trimmed = rest;
            }
            if trimmed.is_empty() {
                Cow::Borrowed(".")
            } else if trimmed.len() == normalized.len() {
                Cow::Owned(normalized)
            } else {
                Cow::Owned(trimmed.to_string())
            }
        }
    }
}

pub(crate) fn validate_root_relative_glob_pattern(
    pattern: &str,
) -> std::result::Result<(), &'static str> {
    let normalized = normalize_glob_pattern(pattern);
    let pattern = normalized.as_ref();

    if pattern.starts_with('/') {
        return Err("glob patterns must be root-relative (must not start with '/')");
    }

    #[cfg(windows)]
    {
        let bytes = pattern.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
            return Err(
                "glob patterns must be root-relative (drive letter prefixes are not supported)",
            );
        }
    }

    if pattern.split('/').any(|segment| segment == "..") {
        return Err("glob patterns must not contain '..' segments");
    }

    Ok(())
}

pub(crate) fn build_glob_from_normalized(
    pattern: &str,
) -> std::result::Result<globset::Glob, globset::Error> {
    let mut builder = GlobBuilder::new(pattern);
    builder.literal_separator(true);
    #[cfg(windows)]
    builder.case_insensitive(true);
    builder.build()
}

#[derive(Debug)]
enum Segment {
    ParentDir,
    Normal(OsString),
}

#[derive(Debug)]
struct NormalizedPathParts {
    path_prefix: Option<OsString>,
    has_root: bool,
    segments: Vec<Segment>,
}

fn normalize_path_lexical_inner(path: &Path) -> NormalizedPathParts {
    let mut parts = NormalizedPathParts {
        path_prefix: None,
        has_root: false,
        segments: Vec::new(),
    };

    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(parts.segments.last(), Some(Segment::Normal(_))) {
                    parts.segments.pop();
                } else if !parts.has_root {
                    parts.segments.push(Segment::ParentDir);
                }
            }
            Component::Normal(part) => parts.segments.push(Segment::Normal(part.to_os_string())),
            Component::RootDir => parts.has_root = true,
            Component::Prefix(prefix_comp) => {
                parts.path_prefix = Some(prefix_comp.as_os_str().to_os_string());
            }
        }
    }

    parts
}

fn reconstruct_path(path: &Path, parts: NormalizedPathParts) -> PathBuf {
    let mut out = PathBuf::new();
    if let Some(prefix) = parts.path_prefix {
        out.push(Path::new(&prefix));
    }
    if parts.has_root {
        if out.as_os_str().is_empty() {
            #[cfg(windows)]
            out.push("\\");
            #[cfg(not(windows))]
            out.push("/");
        } else {
            // On Windows, pushing `RootDir` after `Prefix` would reset the path (dropping
            // the prefix). Append a separator instead.
            #[cfg(windows)]
            {
                out.as_mut_os_string().push("\\");
            }
            #[cfg(not(windows))]
            {
                out.push("/");
            }
        }
    }
    for segment in parts.segments {
        match segment {
            Segment::ParentDir => out.push(".."),
            Segment::Normal(part) => out.push(part),
        }
    }

    if out.as_os_str().is_empty() && path.is_relative() {
        PathBuf::from(".")
    } else {
        out
    }
}

pub(crate) fn normalize_path_lexical(path: &Path) -> PathBuf {
    reconstruct_path(path, normalize_path_lexical_inner(path))
}

#[cfg(windows)]
#[inline]
fn os_str_eq_case_insensitive_windows(a: &OsStr, b: &OsStr) -> bool {
    crate::platform::windows_path_compare::os_str_eq_case_insensitive(a, b)
}

#[cfg(windows)]
#[inline]
fn prefixes_eq(a: std::path::Prefix<'_>, b: std::path::Prefix<'_>) -> bool {
    use std::path::Prefix::*;

    match (a, b) {
        (Disk(a), Disk(b))
        | (Disk(a), VerbatimDisk(b))
        | (VerbatimDisk(a), Disk(b))
        | (VerbatimDisk(a), VerbatimDisk(b)) => a.eq_ignore_ascii_case(&b),
        (UNC(a_server, a_share), UNC(b_server, b_share))
        | (UNC(a_server, a_share), VerbatimUNC(b_server, b_share))
        | (VerbatimUNC(a_server, a_share), UNC(b_server, b_share))
        | (VerbatimUNC(a_server, a_share), VerbatimUNC(b_server, b_share)) => {
            os_str_eq_case_insensitive_windows(a_server, b_server)
                && os_str_eq_case_insensitive_windows(a_share, b_share)
        }
        (Verbatim(a), Verbatim(b)) => os_str_eq_case_insensitive_windows(a, b),
        (DeviceNS(a), DeviceNS(b)) => os_str_eq_case_insensitive_windows(a, b),
        _ => false,
    }
}

#[cfg(windows)]
#[inline]
fn components_eq_case_insensitive(a: Component<'_>, b: Component<'_>) -> bool {
    match (a, b) {
        (Component::Prefix(a), Component::Prefix(b)) => prefixes_eq(a.kind(), b.kind()),
        (Component::RootDir, Component::RootDir) => true,
        (Component::Normal(a), Component::Normal(b)) => os_str_eq_case_insensitive_windows(a, b),
        (Component::CurDir, Component::CurDir) => true,
        (Component::ParentDir, Component::ParentDir) => true,
        _ => false,
    }
}

#[inline]
pub(crate) fn normalized_for_boundary(path: &Path) -> Cow<'_, Path> {
    if path.as_os_str().is_empty() {
        return Cow::Borrowed(Path::new("."));
    }
    if path == Path::new(".") {
        return Cow::Borrowed(Path::new("."));
    }
    let mut needs_normalization = false;
    let mut only_curdir = true;
    for component in path.components() {
        match component {
            Component::CurDir => {
                needs_normalization = true;
            }
            Component::ParentDir => {
                needs_normalization = true;
                only_curdir = false;
            }
            _ => {
                only_curdir = false;
            }
        }
        if needs_normalization && !only_curdir {
            break;
        }
    }

    if only_curdir {
        return Cow::Borrowed(Path::new("."));
    }
    if !needs_normalization {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(normalize_path_lexical(path))
    }
}

/// A case-insensitive `Path::starts_with` for Windows paths.
///
/// This function is purely lexical and does not resolve symlinks.
/// Inputs are normalized lexically before comparison.
///
/// On non-Windows platforms this is equivalent to `Path::starts_with`.
#[inline]
pub fn starts_with_case_insensitive(path: &Path, prefix: &Path) -> bool {
    let path = normalized_for_boundary(path);
    let prefix = normalized_for_boundary(prefix);
    starts_with_case_insensitive_normalized(path.as_ref(), prefix.as_ref())
}

/// Internal fast path for callers that already hold lexically-normalized paths.
///
/// This is intentionally `pub(crate)` to avoid exposing a footgun in the public API.
#[inline]
pub(crate) fn starts_with_case_insensitive_normalized(path: &Path, prefix: &Path) -> bool {
    #[cfg(windows)]
    {
        let mut path_components = path.components();
        for prefix_comp in prefix.components() {
            let Some(path_comp) = path_components.next() else {
                return false;
            };

            if !components_eq_case_insensitive(path_comp, prefix_comp) {
                return false;
            }
        }
        true
    }

    #[cfg(not(windows))]
    {
        path.starts_with(prefix)
    }
}

/// A case-insensitive `Path::strip_prefix` for Windows paths.
///
/// This function is purely lexical and does not resolve symlinks.
/// Inputs are normalized lexically before comparison.
///
/// On non-Windows platforms this is equivalent to `Path::strip_prefix`.
#[inline]
pub fn strip_prefix_case_insensitive(path: &Path, prefix: &Path) -> Option<PathBuf> {
    let path = normalized_for_boundary(path);
    let prefix = normalized_for_boundary(prefix);
    strip_prefix_case_insensitive_normalized(path.as_ref(), prefix.as_ref())
}

/// Lexical path equality under platform boundary semantics.
///
/// On Windows this is case-insensitive and prefix-aware (drive/UNC/verbatim handling matches the
/// strip/starts_with helpers); on non-Windows this is equivalent to normalized lexical equality.
#[inline]
pub(crate) fn paths_equal_case_insensitive(path: &Path, other: &Path) -> bool {
    let path = normalized_for_boundary(path);
    let other = normalized_for_boundary(other);
    paths_equal_case_insensitive_normalized(path.as_ref(), other.as_ref())
}

/// Internal fast path for callers that already hold lexically-normalized paths.
///
/// This is intentionally `pub(crate)` to avoid exposing a footgun in the public API.
#[inline]
pub(crate) fn paths_equal_case_insensitive_normalized(path: &Path, other: &Path) -> bool {
    starts_with_case_insensitive_normalized(path, other)
        && starts_with_case_insensitive_normalized(other, path)
}

/// Internal fast path for callers that already hold lexically-normalized paths.
///
/// This is intentionally `pub(crate)` to avoid exposing a footgun in the public API.
#[inline]
pub(crate) fn strip_prefix_case_insensitive_normalized(
    path: &Path,
    prefix: &Path,
) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let mut path_components = path.components();
        for prefix_comp in prefix.components() {
            let path_comp = path_components.next()?;

            if !components_eq_case_insensitive(path_comp, prefix_comp) {
                return None;
            }
        }

        Some(path_components.as_path().to_path_buf())
    }

    #[cfg(not(windows))]
    {
        path.strip_prefix(prefix).ok().map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_lexical_dot_is_stable() {
        assert_eq!(normalize_path_lexical(Path::new(".")), PathBuf::from("."));
        assert_eq!(
            normalize_path_lexical(Path::new("././")),
            PathBuf::from(".")
        );
        assert_eq!(
            normalize_path_lexical(Path::new("a/..")),
            PathBuf::from(".")
        );
        assert_eq!(normalize_path_lexical(Path::new("")), PathBuf::from("."));
    }

    #[test]
    fn normalized_for_boundary_empty_path_uses_borrowed_dot() {
        let normalized = normalized_for_boundary(Path::new(""));
        assert!(matches!(normalized, Cow::Borrowed(_)));
        assert_eq!(normalized.as_ref(), Path::new("."));
    }

    #[test]
    fn normalized_for_boundary_curdir_only_paths_use_borrowed_dot() {
        let dot = normalized_for_boundary(Path::new("."));
        assert!(matches!(dot, Cow::Borrowed(_)));
        assert_eq!(dot.as_ref(), Path::new("."));

        let dotted = normalized_for_boundary(Path::new("././"));
        assert!(matches!(dotted, Cow::Borrowed(_)));
        assert_eq!(dotted.as_ref(), Path::new("."));
    }

    #[test]
    fn strip_prefix_case_insensitive_handles_relative_paths() {
        assert_eq!(
            strip_prefix_case_insensitive(Path::new("a/b/c"), Path::new("a/b")),
            Some(PathBuf::from("c"))
        );
        assert_eq!(
            strip_prefix_case_insensitive(Path::new("a/b"), Path::new("a/b")),
            Some(PathBuf::new())
        );
        assert_eq!(
            strip_prefix_case_insensitive(Path::new("a/b"), Path::new("a/b/c")),
            None
        );
    }

    #[test]
    fn starts_with_case_insensitive_handles_relative_paths() {
        assert!(starts_with_case_insensitive(
            Path::new("a/b/c"),
            Path::new("a/b")
        ));
        assert!(starts_with_case_insensitive(
            Path::new("a/b"),
            Path::new("a/b")
        ));
        assert!(!starts_with_case_insensitive(
            Path::new("a/b"),
            Path::new("a/b/c")
        ));
    }

    #[test]
    fn normalize_glob_pattern_for_matching_collapses_leading_dot_segments() {
        assert_eq!(normalize_glob_pattern_for_matching("././a/b"), "a/b");
        assert_eq!(normalize_glob_pattern_for_matching("././"), ".");
        let long = format!("{}file", "./".repeat(1024));
        assert_eq!(normalize_glob_pattern_for_matching(&long), "file");
    }

    #[test]
    fn normalize_glob_pattern_for_matching_borrows_when_already_normalized() {
        let normalized = normalize_glob_pattern_for_matching("a/b");
        assert!(matches!(normalized, Cow::Borrowed("a/b")));
    }

    #[test]
    fn normalize_glob_pattern_for_matching_borrows_when_leading_dot_segments_removed() {
        let normalized = normalize_glob_pattern_for_matching("././a/b");
        assert!(matches!(normalized, Cow::Borrowed("a/b")));
    }

    #[test]
    fn starts_with_case_insensitive_normalizes_unnormalized_inputs() {
        assert!(starts_with_case_insensitive(
            Path::new("a/./b"),
            Path::new("./a")
        ));
    }

    #[test]
    fn strip_prefix_case_insensitive_normalizes_unnormalized_inputs() {
        assert_eq!(
            strip_prefix_case_insensitive(Path::new("a/./b/c"), Path::new("./a/b")),
            Some(PathBuf::from("c"))
        );
    }

    #[test]
    fn paths_equal_case_insensitive_normalizes_inputs() {
        assert!(paths_equal_case_insensitive(
            Path::new("a/./b"),
            Path::new("./a/b")
        ));
        assert!(!paths_equal_case_insensitive(
            Path::new("a/b"),
            Path::new("a/b/c")
        ));
    }

    #[test]
    fn normalize_path_lexical_handles_deep_paths() {
        let mut input = PathBuf::new();
        for _ in 0..10_000 {
            input.push("a");
        }
        for _ in 0..9_999 {
            input.push("..");
        }
        input.push("tail");

        assert_eq!(
            normalize_path_lexical(&input),
            PathBuf::from("a").join("tail")
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn normalize_path_lexical_handles_absolute_paths() {
        assert_eq!(
            normalize_path_lexical(Path::new("/../etc")),
            PathBuf::from("/etc")
        );
        assert_eq!(
            normalize_path_lexical(Path::new("/a/./b")),
            PathBuf::from("/a/b")
        );
    }

    #[test]
    #[cfg(windows)]
    fn normalize_path_lexical_handles_windows_prefix_paths() {
        assert_eq!(
            normalize_path_lexical(Path::new(r"C:\foo\..\bar")),
            PathBuf::from(r"C:\bar")
        );
        assert_eq!(
            normalize_path_lexical(Path::new(r"\\?\C:\foo\..")),
            PathBuf::from("\\\\?\\C:\\")
        );
        assert_eq!(
            normalize_path_lexical(Path::new(r"\\server\share\a\..")),
            PathBuf::from("\\\\server\\share\\")
        );
    }

    #[test]
    #[cfg(windows)]
    fn strip_prefix_case_insensitive_is_case_insensitive_for_drive_prefixes() {
        assert_eq!(
            strip_prefix_case_insensitive(Path::new(r"C:\Foo\Bar"), Path::new(r"c:\foo")),
            Some(PathBuf::from("Bar"))
        );
        assert!(starts_with_case_insensitive(
            Path::new(r"C:\Foo\Bar"),
            Path::new(r"c:\foo")
        ));
    }

    #[test]
    #[cfg(windows)]
    fn strip_prefix_case_insensitive_matches_verbatim_drive_prefixes() {
        assert_eq!(
            strip_prefix_case_insensitive(Path::new(r"\\?\C:\Foo\Bar"), Path::new(r"c:\foo")),
            Some(PathBuf::from("Bar"))
        );
        assert!(starts_with_case_insensitive(
            Path::new(r"\\?\C:\Foo\Bar"),
            Path::new(r"c:\foo")
        ));
    }

    #[test]
    #[cfg(windows)]
    fn strip_prefix_case_insensitive_is_some_when_starts_with_for_prefix_only_matches() {
        let cases = [
            (Path::new(r"C:\Foo\Bar"), Path::new(r"c:")),
            (
                Path::new(r"\\Server\Share\Dir"),
                Path::new(r"\\server\share"),
            ),
            (Path::new(r"\\?\C:\Foo\Bar"), Path::new(r"c:")),
        ];

        for (path, prefix) in cases {
            assert!(
                starts_with_case_insensitive(path, prefix),
                "expected starts_with for path={path:?}, prefix={prefix:?}"
            );
            assert!(
                strip_prefix_case_insensitive(path, prefix).is_some(),
                "expected strip_prefix to succeed for path={path:?}, prefix={prefix:?}"
            );
        }
    }

    #[test]
    #[cfg(windows)]
    fn strip_prefix_case_insensitive_empty_prefix_matches_std() {
        let path = Path::new(r"C:\Foo\Bar");
        assert_eq!(
            strip_prefix_case_insensitive(path, Path::new("")),
            path.strip_prefix(Path::new("")).ok().map(PathBuf::from)
        );
    }

    #[test]
    #[cfg(windows)]
    fn os_str_eq_case_insensitive_windows_handles_empty_and_unicode() {
        use std::ffi::OsStr;

        assert!(os_str_eq_case_insensitive_windows(
            OsStr::new(""),
            OsStr::new("")
        ));
        assert!(os_str_eq_case_insensitive_windows(
            OsStr::new("Straße"),
            OsStr::new("straße")
        ));
        assert!(!os_str_eq_case_insensitive_windows(
            OsStr::new("alpha"),
            OsStr::new("beta")
        ));
    }

    #[test]
    #[cfg(windows)]
    fn starts_with_case_insensitive_matches_device_namespace_prefixes() {
        assert!(starts_with_case_insensitive(
            Path::new(r"\\.\COM1\Logs\Today.txt"),
            Path::new(r"\\.\com1\logs")
        ));
        assert_eq!(
            strip_prefix_case_insensitive(
                Path::new(r"\\.\COM1\Logs\Today.txt"),
                Path::new(r"\\.\com1\logs")
            ),
            Some(PathBuf::from("Today.txt"))
        );
    }

    #[test]
    #[cfg(windows)]
    fn paths_equal_case_insensitive_is_case_insensitive_on_windows() {
        assert!(paths_equal_case_insensitive(
            Path::new(r"C:\Foo\Bar"),
            Path::new(r"c:\foo\bar")
        ));
        assert!(paths_equal_case_insensitive(
            Path::new(r"\\?\C:\Foo\Bar"),
            Path::new(r"c:\foo\bar")
        ));
    }
}
