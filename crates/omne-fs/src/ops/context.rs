use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use policy_meta::WriteScope;

use crate::error::{Error, Result};
use crate::policy::SandboxPolicy;
use crate::redaction::SecretRedactor;

use super::{
    Context, CopyFileRequest, CopyFileResponse, DeleteRequest, DeleteResponse, EditRequest,
    EditResponse, ListDirRequest, ListDirResponse, MkdirRequest, MkdirResponse, MovePathRequest,
    MovePathResponse, PatchRequest, PatchResponse, ReadRequest, ReadResponse, RootRuntime,
    StatRequest, StatResponse, WriteFileRequest, WriteFileResponse,
};
#[cfg(feature = "glob")]
use super::{GlobRequest, GlobResponse};
#[cfg(feature = "grep")]
use super::{GrepRequest, GrepResponse};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecisionTrace {
    pub reason_code: &'static str,
    pub risk_tag: &'static str,
    pub policy_rule: Option<&'static str>,
}

impl Context {
    pub fn new(policy: SandboxPolicy) -> Result<Self> {
        Self::build_from_policy(policy)
    }

    fn build_from_policy(policy: SandboxPolicy) -> Result<Self> {
        policy.validate()?;
        let redactor = SecretRedactor::from_rules(&policy.secrets)?;

        let mut canonical_roots = Vec::<CanonicalRoot>::with_capacity(policy.roots.len());
        for root in &policy.roots {
            let canonical = root.path.canonicalize().map_err(|err| {
                Error::InvalidPolicy(format!(
                    "failed to canonicalize root {} ({}): {err}",
                    root.id,
                    root.path.display()
                ))
            })?;
            let meta = fs::metadata(&canonical).map_err(|err| {
                Error::InvalidPolicy(format!(
                    "failed to stat root {} ({}): {err}",
                    root.id,
                    canonical.display()
                ))
            })?;
            if !meta.is_dir() {
                return Err(Error::InvalidPolicy(format!(
                    "root {} ({}) is not a directory",
                    root.id,
                    canonical.display()
                )));
            }
            canonical_roots.push(CanonicalRoot {
                id: root.id.clone(),
                declared_path: root.path.clone(),
                canonical_path: canonical,
                write_scope: root.write_scope,
            });
        }
        validate_canonical_roots_non_overlapping(&canonical_roots)?;

        let mut roots = HashMap::<String, RootRuntime>::with_capacity(canonical_roots.len());
        for root in canonical_roots {
            let replaced = roots.insert(
                root.id,
                RootRuntime {
                    declared_path: root.declared_path,
                    canonical_path: root.canonical_path,
                    write_scope: root.write_scope,
                },
            );
            debug_assert!(
                replaced.is_none(),
                "duplicate root.id should be rejected by SandboxPolicy::validate_structural"
            );
        }

        #[cfg(any(feature = "glob", feature = "grep"))]
        let traversal_skip_globs =
            super::traversal::compile_traversal_skip_globs(&policy.traversal.skip_globs)?;

        Ok(Self {
            policy,
            redactor,
            roots,
            #[cfg(any(feature = "glob", feature = "grep"))]
            traversal_skip_globs,
        })
    }

    #[cfg(feature = "policy-io")]
    pub fn from_policy_path(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let policy = crate::policy_io::load_policy(path)?;
        Self::new(policy)
    }

    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    pub fn read_file(&self, request: ReadRequest) -> Result<ReadResponse> {
        super::read_file(self, request)
    }

    pub fn list_dir(&self, request: ListDirRequest) -> Result<ListDirResponse> {
        super::list_dir(self, request)
    }

    #[cfg(feature = "glob")]
    pub fn glob_paths(&self, request: GlobRequest) -> Result<GlobResponse> {
        super::glob_paths(self, request)
    }

    #[cfg(feature = "grep")]
    pub fn grep(&self, request: GrepRequest) -> Result<GrepResponse> {
        super::grep(self, request)
    }

    pub fn stat(&self, request: StatRequest) -> Result<StatResponse> {
        super::stat(self, request)
    }

    pub fn edit_range(&self, request: EditRequest) -> Result<EditResponse> {
        super::edit_range(self, request)
    }

    pub fn apply_unified_patch(&self, request: PatchRequest) -> Result<PatchResponse> {
        super::apply_unified_patch(self, request)
    }

    pub fn delete(&self, request: DeleteRequest) -> Result<DeleteResponse> {
        super::delete(self, request)
    }

    pub fn mkdir(&self, request: MkdirRequest) -> Result<MkdirResponse> {
        super::mkdir(self, request)
    }

    pub fn write_file(&self, request: WriteFileRequest) -> Result<WriteFileResponse> {
        super::write_file(self, request)
    }

    pub fn move_path(&self, request: MovePathRequest) -> Result<MovePathResponse> {
        super::move_path(self, request)
    }

    pub fn copy_file(&self, request: CopyFileRequest) -> Result<CopyFileResponse> {
        super::copy_file(self, request)
    }

    /// Build a stable decision trace from an operation error for audit pipelines.
    pub fn decision_trace_for_error(&self, error: &Error) -> DecisionTrace {
        let _ = self;
        DecisionTrace {
            reason_code: error.code(),
            risk_tag: error.risk_tag(),
            policy_rule: error.policy_rule(),
        }
    }

    fn root_runtime(&self, root_id: &str) -> Result<&RootRuntime> {
        self.roots
            .get(root_id)
            .ok_or_else(|| Error::RootNotFound(root_id.to_string()))
    }

    pub(super) fn canonical_root(&self, root_id: &str) -> Result<&Path> {
        self.root_runtime(root_id)
            .map(|root| root.canonical_path.as_path())
    }

    pub(super) fn declared_root(&self, root_id: &str) -> Result<&Path> {
        self.root_runtime(root_id)
            .map(|root| root.declared_path.as_path())
    }

    #[cfg(any(feature = "glob", feature = "grep"))]
    pub(super) fn is_traversal_path_skipped(&self, relative: &Path) -> bool {
        self.traversal_skip_globs
            .as_ref()
            .is_some_and(|skip| super::traversal::globset_is_match(skip, relative))
    }

    #[cfg(any(feature = "glob", feature = "grep"))]
    #[inline]
    pub(super) fn has_traversal_path_filters(&self) -> bool {
        !self.policy.secrets.deny_globs.is_empty() || self.traversal_skip_globs.is_some()
    }

    pub(super) fn reject_secret_path(&self, path: PathBuf) -> Result<PathBuf> {
        if self.redactor.is_path_denied(&path) {
            return Err(Error::SecretPathDenied(path));
        }
        Ok(path)
    }

    pub(super) fn ensure_policy_permission(&self, enabled: bool, op: &str) -> Result<()> {
        if !enabled {
            return Err(Error::NotPermitted(format!("{op} is disabled by policy")));
        }
        Ok(())
    }

    pub(super) fn ensure_can_write(&self, root_id: &str, op: &str) -> Result<()> {
        let root = self.root_runtime(root_id)?;
        if !matches!(
            root.write_scope,
            WriteScope::WorkspaceWrite | WriteScope::FullAccess
        ) {
            return Err(Error::NotPermitted(format!(
                "{op} is not allowed: root {root_id} is read_only"
            )));
        }
        Ok(())
    }

    pub(super) fn ensure_write_operation_allowed(
        &self,
        root_id: &str,
        enabled: bool,
        op: &str,
    ) -> Result<()> {
        self.ensure_policy_permission(enabled, op)?;
        self.ensure_can_write(root_id, op)
    }

    #[inline]
    pub(super) fn git_permission_fallback_enabled(&self) -> bool {
        cfg!(feature = "git-permissions")
    }

    pub(super) fn ensure_git_revertible_write_allowed(
        &self,
        root_id: &str,
        relative_path: &Path,
        op: &str,
        recursive: bool,
    ) -> Result<()> {
        super::git_permissions::ensure_revertible_write_allowed(
            self,
            root_id,
            relative_path,
            op,
            recursive,
        )
    }
}

#[derive(Debug)]
struct CanonicalRoot {
    id: String,
    declared_path: PathBuf,
    canonical_path: PathBuf,
    write_scope: WriteScope,
}

fn overlap_error(a_id: &str, a_path: &Path, b_id: &str, b_path: &Path, same: bool) -> Error {
    if same {
        Error::InvalidPolicy(format!(
            "root {} ({}) resolves to the same canonical directory as root {} ({})",
            a_id,
            a_path.display(),
            b_id,
            b_path.display()
        ))
    } else {
        Error::InvalidPolicy(format!(
            "root {} ({}) overlaps with root {} ({})",
            a_id,
            a_path.display(),
            b_id,
            b_path.display()
        ))
    }
}

#[cfg(not(windows))]
fn validate_canonical_roots_non_overlapping(canonical_roots: &[CanonicalRoot]) -> Result<()> {
    if canonical_roots.len() < 2 {
        return Ok(());
    }

    let mut sorted = canonical_roots
        .iter()
        .map(|root| (root.id.as_str(), root.canonical_path.as_path()))
        .collect::<Vec<_>>();
    sorted.sort_unstable_by(|a, b| a.1.cmp(b.1));

    for pair in sorted.windows(2) {
        let (a_id, a_path) = pair[0];
        let (b_id, b_path) = pair[1];
        if canonical_paths_equal(a_path, b_path) {
            return Err(overlap_error(a_id, a_path, b_id, b_path, true));
        }
        if canonical_paths_overlap(a_path, b_path) {
            return Err(overlap_error(a_id, a_path, b_id, b_path, false));
        }
    }

    Ok(())
}

#[cfg(windows)]
fn validate_canonical_roots_non_overlapping(canonical_roots: &[CanonicalRoot]) -> Result<()> {
    if canonical_roots.len() < 2 {
        return Ok(());
    }

    // Windows roots on different drive letters are guaranteed disjoint.
    // Partition by disk letter in fixed buckets to avoid map overhead and
    // unnecessary cross-drive pair checks.
    let mut disk_roots = std::array::from_fn::<_, 26, _>(|_| Vec::<&CanonicalRoot>::new());
    let mut non_disk_roots = Vec::<&CanonicalRoot>::with_capacity(canonical_roots.len());
    for root in canonical_roots {
        if let Some(letter) = windows_disk_letter(&root.canonical_path) {
            let lower = letter.to_ascii_lowercase();
            match lower {
                b'a'..=b'z' => {
                    let idx = usize::from(lower - b'a');
                    disk_roots[idx].push(root);
                }
                _ => non_disk_roots.push(root),
            }
        } else {
            non_disk_roots.push(root);
        }
    }

    for roots in &disk_roots {
        if roots.len() > 1 {
            validate_root_group_non_overlapping(roots)?;
        }
    }
    if non_disk_roots.len() > 1 {
        validate_root_group_non_overlapping(&non_disk_roots)?;
    }

    Ok(())
}

#[cfg(windows)]
fn validate_root_group_non_overlapping(roots: &[&CanonicalRoot]) -> Result<()> {
    if roots.len() < 2 {
        return Ok(());
    }

    // Within a drive/UNC group, case-insensitive lexical order allows overlap
    // checks with only adjacent pairs instead of O(n^2) pairwise checks.
    let mut sorted = roots.to_vec();
    sorted.sort_unstable_by(|a, b| {
        canonical_paths_cmp_case_insensitive(&a.canonical_path, &b.canonical_path)
    });

    for pair in sorted.windows(2) {
        let a = pair[0];
        let b = pair[1];
        if canonical_paths_equal(&a.canonical_path, &b.canonical_path) {
            return Err(overlap_error(
                &a.id,
                &a.canonical_path,
                &b.id,
                &b.canonical_path,
                true,
            ));
        }
        if canonical_paths_overlap(&a.canonical_path, &b.canonical_path) {
            return Err(overlap_error(
                &a.id,
                &a.canonical_path,
                &b.id,
                &b.canonical_path,
                false,
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_disk_letter(path: &Path) -> Option<u8> {
    use std::path::{Component, Prefix};

    match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => Some(letter),
            _ => None,
        },
        _ => None,
    }
}

fn canonical_paths_equal(a: &Path, b: &Path) -> bool {
    crate::path_utils::paths_equal_case_insensitive(a, b)
}

fn canonical_paths_overlap(a: &Path, b: &Path) -> bool {
    crate::path_utils::starts_with_case_insensitive_normalized(a, b)
        || crate::path_utils::starts_with_case_insensitive_normalized(b, a)
}

#[cfg(test)]
mod decision_trace_tests {
    use super::*;
    use crate::policy::SandboxPolicy;

    #[test]
    fn decision_trace_uses_error_classification_contract() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy = SandboxPolicy::single_root("root", dir.path(), WriteScope::ReadOnly);
        let ctx = Context::new(policy).expect("ctx");

        let trace =
            ctx.decision_trace_for_error(&Error::SecretPathDenied(PathBuf::from(".git/config")));
        assert_eq!(trace.reason_code, Error::CODE_SECRET_PATH_DENIED);
        assert_eq!(trace.risk_tag, "boundary_violation");
        assert_eq!(trace.policy_rule, Some("secrets.deny_globs"));
    }
}

#[cfg(windows)]
fn canonical_paths_cmp_case_insensitive(a: &Path, b: &Path) -> std::cmp::Ordering {
    crate::platform::windows_path_compare::os_str_cmp_case_insensitive(a.as_os_str(), b.as_os_str())
}

#[cfg(all(test, windows))]
mod tests {
    use std::path::PathBuf;

    use super::{CanonicalRoot, Error, validate_root_group_non_overlapping};
    use policy_meta::WriteScope;

    fn canonical_root(id: &str, canonical_path: &str) -> CanonicalRoot {
        CanonicalRoot {
            id: id.to_string(),
            declared_path: PathBuf::from(canonical_path),
            canonical_path: PathBuf::from(canonical_path),
            write_scope: WriteScope::ReadOnly,
        }
    }

    #[test]
    fn windows_group_overlap_detects_case_insensitive_parent_child() {
        let root_a = canonical_root("root_a", r"C:\A\child");
        let root_b = canonical_root("root_b", r"c:\a");
        let root_c = canonical_root("root_c", r"C:\B");
        let roots = vec![&root_a, &root_b, &root_c];

        let err =
            validate_root_group_non_overlapping(&roots).expect_err("overlap should be rejected");
        match err {
            Error::InvalidPolicy(message) => {
                assert!(message.contains("overlaps with root"), "message: {message}");
                assert!(message.contains("root_a"), "message: {message}");
                assert!(message.contains("root_b"), "message: {message}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn windows_group_non_overlapping_paths_are_accepted() {
        let root_a = canonical_root("root_a", r"C:\Alpha");
        let root_b = canonical_root("root_b", r"C:\Beta");
        let roots = vec![&root_a, &root_b];

        validate_root_group_non_overlapping(&roots).expect("non-overlapping roots should pass");
    }
}
