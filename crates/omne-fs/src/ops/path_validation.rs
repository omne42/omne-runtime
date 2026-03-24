use std::ffi::OsStr;
use std::path::{Component, Path};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LeafOp {
    Write,
    Delete,
    Mkdir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LeafValidationSpec {
    op_name: &'static str,
    missing_segment_label: &'static str,
    root_rejection_message: &'static str,
}

impl LeafValidationSpec {
    const fn for_op(op: LeafOp) -> Self {
        match op {
            LeafOp::Write => Self {
                op_name: "write",
                missing_segment_label: "file name",
                root_rejection_message: "refusing to write to the root directory",
            },
            LeafOp::Delete => Self {
                op_name: "delete",
                missing_segment_label: "path segment",
                root_rejection_message: "refusing to delete the root directory",
            },
            LeafOp::Mkdir => Self {
                op_name: "mkdir",
                missing_segment_label: "directory name",
                root_rejection_message: "refusing to create the root directory",
            },
        }
    }
}

fn validate_requested_path_contract(
    requested_path: &Path,
    raw_input_path: &Path,
    spec: LeafValidationSpec,
) -> Result<()> {
    let has_non_relative_components = requested_path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    });
    if has_non_relative_components {
        return Err(Error::InvalidPath(format!(
            "invalid {} path {:?}: internal contract violation: requested path must stay root-relative (raw input {:?})",
            spec.op_name, requested_path, raw_input_path
        )));
    }

    // Contract hardening: normalized root-relative paths may only contain `.`
    // as the full-root marker, never as an interior segment.
    if requested_path != Path::new(".")
        && requested_path
            .components()
            .any(|component| matches!(component, Component::CurDir))
    {
        return Err(Error::InvalidPath(format!(
            "invalid {} path {:?}: internal contract violation: requested path must be normalized root-relative (raw input {:?})",
            spec.op_name, requested_path, raw_input_path
        )));
    }

    #[cfg(debug_assertions)]
    {
        let normalized = crate::path_utils_internal::normalize_path_lexical(requested_path);
        debug_assert_eq!(
            normalized.as_os_str(),
            requested_path.as_os_str(),
            "internal contract violation: requested path must be normalized root-relative: requested={requested_path:?}, raw={raw_input_path:?}"
        );
    }

    Ok(())
}

/// Validates the leaf path segment for mutating operations.
///
/// Contract: `requested_path` must be a normalized root-relative path emitted by
/// path resolution (`.` means root). Missing-leaf checks are kept as defensive
/// validation for callers violating that contract.
pub(super) fn ensure_non_root_leaf<'a>(
    requested_path: &'a Path,
    raw_input_path: &Path,
    op: LeafOp,
) -> Result<&'a OsStr> {
    let spec = LeafValidationSpec::for_op(op);

    validate_requested_path_contract(requested_path, raw_input_path, spec)?;

    if requested_path == Path::new(".") {
        return Err(Error::InvalidPath(spec.root_rejection_message.to_string()));
    }

    let file_name = requested_path.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid {} path {:?}: missing final {}",
            spec.op_name, raw_input_path, spec.missing_segment_label
        ))
    })?;

    Ok(file_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invalid_path_message(err: Error) -> String {
        match err {
            Error::InvalidPath(message) => message,
            other => panic!("expected invalid path error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_root_dot_with_operation_specific_message() {
        let cases = [
            (LeafOp::Write, "refusing to write to the root directory"),
            (LeafOp::Delete, "refusing to delete the root directory"),
            (LeafOp::Mkdir, "refusing to create the root directory"),
        ];

        for (op, expected_message) in cases {
            let err = ensure_non_root_leaf(Path::new("."), Path::new("."), op)
                .expect_err("root path should be rejected");

            assert_eq!(invalid_path_message(err), expected_message);
        }
    }

    #[test]
    fn rejects_non_root_relative_requested_path_for_all_ops() {
        let cases = [
            (LeafOp::Write, "write"),
            (LeafOp::Delete, "delete"),
            (LeafOp::Mkdir, "mkdir"),
        ];

        for (op, op_name) in cases {
            let err = ensure_non_root_leaf(Path::new("../file.txt"), Path::new("../file.txt"), op)
                .expect_err("parent-dir segment should be rejected");

            assert_eq!(
                invalid_path_message(err),
                format!(
                    "invalid {op_name} path \"../file.txt\": internal contract violation: requested path must stay root-relative (raw input \"../file.txt\")"
                )
            );
        }
    }

    #[test]
    fn contract_violation_reports_requested_path_for_diagnostics() {
        let err = ensure_non_root_leaf(
            Path::new("../file.txt"),
            Path::new("user-input.txt"),
            LeafOp::Delete,
        )
        .expect_err("parent-dir segment should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "invalid delete path \"../file.txt\": internal contract violation: requested path must stay root-relative (raw input \"user-input.txt\")"
        );
    }

    #[test]
    fn rejects_requested_path_with_root_component() {
        let err = ensure_non_root_leaf(
            Path::new("/tmp/file.txt"),
            Path::new("/tmp/file.txt"),
            LeafOp::Delete,
        )
        .expect_err("absolute requested path should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "invalid delete path \"/tmp/file.txt\": internal contract violation: requested path must stay root-relative (raw input \"/tmp/file.txt\")"
        );
    }

    #[test]
    fn rejects_requested_path_with_curdir_segments() {
        let err = ensure_non_root_leaf(
            Path::new("./nested/file.txt"),
            Path::new("./nested/file.txt"),
            LeafOp::Delete,
        )
        .expect_err("requested path with curdir segments should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "invalid delete path \"./nested/file.txt\": internal contract violation: requested path must be normalized root-relative (raw input \"./nested/file.txt\")"
        );
    }

    #[test]
    #[cfg(windows)]
    fn rejects_requested_path_with_windows_prefix_component() {
        let err = ensure_non_root_leaf(
            Path::new(r"C:\tmp\file.txt"),
            Path::new(r"C:\tmp\file.txt"),
            LeafOp::Delete,
        )
        .expect_err("prefixed requested path should be rejected");

        assert_eq!(
            invalid_path_message(err),
            "invalid delete path \"C:\\tmp\\file.txt\": internal contract violation: requested path must stay root-relative (raw input \"C:\\tmp\\file.txt\")"
        );
    }

    #[test]
    fn reports_contract_violation_before_leaf_extraction() {
        let err = ensure_non_root_leaf(Path::new(".."), Path::new(".."), LeafOp::Delete)
            .expect_err("contract violation should trigger before missing-leaf checks");

        assert_eq!(
            invalid_path_message(err),
            "invalid delete path \"..\": internal contract violation: requested path must stay root-relative (raw input \"..\")"
        );
    }

    #[test]
    fn accepts_normalized_non_root_leaf_for_all_ops() {
        let cases = [LeafOp::Write, LeafOp::Delete, LeafOp::Mkdir];

        for op in cases {
            let leaf = ensure_non_root_leaf(
                Path::new("nested/file.txt"),
                Path::new("nested/file.txt"),
                op,
            )
            .expect("valid normalized path should pass");

            assert_eq!(leaf, OsStr::new("file.txt"));
        }
    }
}
