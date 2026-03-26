#[cfg(windows)]
use std::path::Component;
use std::path::{Path, PathBuf};

use policy_meta::{PolicyMetaV1, WriteScope};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Root {
    pub id: String,
    pub path: PathBuf,
    #[serde(default)]
    pub write_scope: WriteScope,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Permissions {
    #[serde(default)]
    pub read: bool,
    #[serde(default)]
    pub glob: bool,
    #[serde(default)]
    pub grep: bool,
    #[serde(default)]
    pub list_dir: bool,
    #[serde(default)]
    pub stat: bool,
    #[serde(default)]
    pub edit: bool,
    #[serde(default)]
    pub patch: bool,
    #[serde(default)]
    pub delete: bool,
    #[serde(default)]
    pub mkdir: bool,
    #[serde(default)]
    pub write: bool,
    #[serde(default, rename = "move")]
    pub move_path: bool,
    #[serde(default)]
    pub copy_file: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "default_max_read_bytes")]
    pub max_read_bytes: u64,
    /// Optional cap for unified-diff patch *input* size (bytes).
    ///
    /// - `None` => defaults to `max_read_bytes`.
    /// - `Some(0)` is invalid and rejected by policy validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_patch_bytes: Option<u64>,
    #[serde(default = "default_max_write_bytes")]
    pub max_write_bytes: u64,
    #[serde(default = "default_max_results")]
    pub max_results: usize,
    #[serde(default = "default_max_walk_entries")]
    pub max_walk_entries: usize,
    #[serde(default = "default_max_walk_files")]
    pub max_walk_files: usize,
    /// Optional wall-clock traversal budget for `glob`/`grep` (milliseconds).
    ///
    /// - `None` => no time budget enforcement.
    /// - `Some(0)` => immediately stop traversal (useful for tests / hard disable).
    #[serde(default)]
    pub max_walk_ms: Option<u64>,
    /// Maximum bytes retained per returned text line.
    ///
    /// This also scales the default response-byte *estimate* budget for `glob`/`grep`/`list_dir`
    /// (`max_results * max_line_bytes`). It is not a strict process-memory cap.
    #[serde(default = "default_max_line_bytes")]
    pub max_line_bytes: usize,
    /// Optional byte budget for `glob` response payload (sum of matched relative-path bytes).
    ///
    /// - `None` => backward-compatible budget: `max_results * max_line_bytes`.
    /// - `Some(0)` is invalid and rejected by policy validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_glob_bytes: Option<usize>,
    /// Preserve Linux/Android extended attributes during atomic overwrite writes.
    ///
    /// Keep enabled for metadata fidelity (for example SELinux labels). Disabling can reduce
    /// syscall overhead on filesystems with many xattrs, at the cost of xattr preservation.
    #[serde(default = "default_preserve_unix_xattrs")]
    pub preserve_unix_xattrs: bool,
}

const fn default_max_read_bytes() -> u64 {
    1024 * 1024
}

const fn default_max_write_bytes() -> u64 {
    1024 * 1024
}

const fn default_max_results() -> usize {
    2000
}

const fn default_max_walk_entries() -> usize {
    500_000
}

const fn default_max_walk_files() -> usize {
    200_000
}

const fn default_max_line_bytes() -> usize {
    4096
}

const fn default_preserve_unix_xattrs() -> bool {
    true
}

const ROOT_ID_MAX_LEN: usize = 64;
// Hard caps are policy-level guardrails against misconfiguration and accidental DoS.
const MAX_READ_BYTES_HARD_CAP: u64 = 256 * 1024 * 1024;
const MAX_PATCH_BYTES_HARD_CAP: u64 = 256 * 1024 * 1024;
const MAX_WRITE_BYTES_HARD_CAP: u64 = 256 * 1024 * 1024;
const MAX_RESULTS_HARD_CAP: usize = 1_000_000;
const MAX_WALK_ENTRIES_HARD_CAP: usize = 10_000_000;
const MAX_WALK_FILES_HARD_CAP: usize = 5_000_000;
const MAX_LINE_BYTES_HARD_CAP: usize = 1024 * 1024;
const MAX_GREP_RESPONSE_BYTES_HARD_CAP: usize = 64 * 1024 * 1024;
const MAX_GLOB_RESPONSE_BYTES_HARD_CAP: usize = 64 * 1024 * 1024;
const MAX_LIST_DIR_RESPONSE_BYTES_HARD_CAP: usize = 64 * 1024 * 1024;

fn is_valid_root_id(id: &str) -> bool {
    id.as_bytes().iter().all(|byte| {
        matches!(
            byte,
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-'
        )
    })
}

fn validate_u64_limit(value: u64, field: &str, hard_cap: u64) -> Result<()> {
    if value == 0 {
        return Err(Error::InvalidPolicy(format!("{field} must be > 0")));
    }
    if value > hard_cap {
        return Err(Error::InvalidPolicy(format!(
            "{field} must be <= {hard_cap}"
        )));
    }
    Ok(())
}

fn validate_usize_limit(value: usize, field: &str, hard_cap: usize) -> Result<()> {
    if value == 0 {
        return Err(Error::InvalidPolicy(format!("{field} must be > 0")));
    }
    if value > hard_cap {
        return Err(Error::InvalidPolicy(format!(
            "{field} must be <= {hard_cap}"
        )));
    }
    Ok(())
}

fn validate_grep_response_budget(max_results: usize, max_line_bytes: usize) -> Result<()> {
    let worst_case_bytes = max_results.checked_mul(max_line_bytes).ok_or_else(|| {
        Error::InvalidPolicy(
            "limits.max_results * limits.max_line_bytes overflowed usize".to_string(),
        )
    })?;
    if worst_case_bytes > MAX_GREP_RESPONSE_BYTES_HARD_CAP {
        return Err(Error::InvalidPolicy(format!(
            "limits.max_results * limits.max_line_bytes must be <= {} bytes",
            MAX_GREP_RESPONSE_BYTES_HARD_CAP
        )));
    }
    Ok(())
}

fn validate_list_dir_response_budget(max_results: usize, max_line_bytes: usize) -> Result<()> {
    let worst_case_bytes = max_results.checked_mul(max_line_bytes).ok_or_else(|| {
        Error::InvalidPolicy(
            "limits.max_results * limits.max_line_bytes overflowed usize".to_string(),
        )
    })?;
    if worst_case_bytes > MAX_LIST_DIR_RESPONSE_BYTES_HARD_CAP {
        return Err(Error::InvalidPolicy(format!(
            "list_dir response budget (limits.max_results * limits.max_line_bytes) must be <= {} bytes",
            MAX_LIST_DIR_RESPONSE_BYTES_HARD_CAP
        )));
    }
    Ok(())
}

fn validate_glob_response_budget(
    max_results: usize,
    max_line_bytes: usize,
    max_glob_bytes: Option<usize>,
) -> Result<()> {
    let effective_budget = match max_glob_bytes {
        Some(bytes) => bytes,
        None => max_results.checked_mul(max_line_bytes).ok_or_else(|| {
            Error::InvalidPolicy(
                "limits.max_results * limits.max_line_bytes overflowed usize".to_string(),
            )
        })?,
    };
    if effective_budget > MAX_GLOB_RESPONSE_BYTES_HARD_CAP {
        return Err(Error::InvalidPolicy(format!(
            "effective glob response budget (limits.max_glob_bytes or limits.max_results * limits.max_line_bytes) must be <= {} bytes",
            MAX_GLOB_RESPONSE_BYTES_HARD_CAP
        )));
    }
    Ok(())
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_read_bytes: default_max_read_bytes(),
            max_patch_bytes: None,
            max_write_bytes: default_max_write_bytes(),
            max_results: default_max_results(),
            max_walk_entries: default_max_walk_entries(),
            max_walk_files: default_max_walk_files(),
            max_walk_ms: None,
            max_line_bytes: default_max_line_bytes(),
            max_glob_bytes: None,
            preserve_unix_xattrs: default_preserve_unix_xattrs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRules {
    #[serde(default = "default_secret_deny_globs")]
    pub deny_globs: Vec<String>,
    #[serde(default)]
    pub redact_regexes: Vec<String>,
    #[serde(default = "default_redaction_replacement")]
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraversalRules {
    /// Glob patterns that should be skipped during traversal (`glob`/`grep`) for performance.
    ///
    /// Unlike `secrets.deny_globs`, this does **not** deny direct access to the path.
    #[serde(default)]
    pub skip_globs: Vec<String>,
    /// Keep traversal directory entry order stable across filesystems by sorting names.
    ///
    /// Disabling this can improve `glob`/`grep` performance for very large directories at the
    /// cost of non-deterministic truncation order when scan limits are hit.
    #[serde(default = "default_traversal_stable_sort")]
    pub stable_sort: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathRules {
    /// Whether absolute request paths are accepted.
    ///
    /// When `false`, all request paths must be root-relative.
    #[serde(default = "default_allow_absolute_paths")]
    pub allow_absolute: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyMetadata {
    /// Shared descriptive policy metadata.
    ///
    /// `omne-fs` parses and serializes this section but does not treat it as an
    /// authorization, enforcement, or budget switch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_meta: Option<PolicyMetaV1>,
}

impl PolicyMetadata {
    pub const fn is_empty(&self) -> bool {
        self.policy_meta.is_none()
    }
}

const fn default_allow_absolute_paths() -> bool {
    false
}

impl Default for PathRules {
    fn default() -> Self {
        Self {
            allow_absolute: default_allow_absolute_paths(),
        }
    }
}

fn default_secret_deny_globs() -> Vec<String> {
    vec![
        ".git/**".to_string(),
        "**/.git/**".to_string(),
        ".env".to_string(),
        ".env.*".to_string(),
        "**/.env".to_string(),
        "**/.env.*".to_string(),
    ]
}

fn default_redaction_replacement() -> String {
    "***REDACTED***".to_string()
}

const fn default_traversal_stable_sort() -> bool {
    true
}

impl Default for SecretRules {
    fn default() -> Self {
        Self {
            deny_globs: default_secret_deny_globs(),
            redact_regexes: Vec::new(),
            replacement: default_redaction_replacement(),
        }
    }
}

impl Default for TraversalRules {
    fn default() -> Self {
        Self {
            skip_globs: Vec::new(),
            stable_sort: default_traversal_stable_sort(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxPolicy {
    pub roots: Vec<Root>,
    #[serde(default)]
    pub permissions: Permissions,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub secrets: SecretRules,
    #[serde(default)]
    pub traversal: TraversalRules,
    #[serde(default)]
    pub paths: PathRules,
    /// Shared descriptive metadata only. This is not consulted by omne-fs enforcement.
    #[serde(default, skip_serializing_if = "PolicyMetadata::is_empty")]
    pub metadata: PolicyMetadata,
}

impl SandboxPolicy {
    pub fn single_root(
        id: impl Into<String>,
        path: impl Into<PathBuf>,
        write_scope: WriteScope,
    ) -> Self {
        Self {
            roots: vec![Root {
                id: id.into(),
                path: path.into(),
                write_scope,
            }],
            permissions: Permissions::default(),
            limits: Limits::default(),
            secrets: SecretRules::default(),
            traversal: TraversalRules::default(),
            paths: PathRules::default(),
            metadata: PolicyMetadata::default(),
        }
    }

    /// Structural policy validation entrypoint.
    /// Structural validation only: validates policy shape and limit values.
    ///
    /// This is a purely *structural* validation: it does **not** perform any filesystem IO
    /// (e.g. it does not check whether roots exist or are directories).
    ///
    /// Root existence and directory checks happen in `ops::Context::new`, which also canonicalizes
    /// the configured root paths.
    ///
    /// Pattern syntax (deny globs / traversal skip globs / redact regexes) is also validated in
    /// `ops::Context::new` when compiling rule matchers.
    pub fn validate(&self) -> Result<()> {
        self.validate_structural()
    }

    /// Structural policy validation for config loading and early checks.
    pub fn validate_structural(&self) -> Result<()> {
        if self.roots.is_empty() {
            return Err(Error::InvalidPolicy("roots is empty".to_string()));
        }
        validate_u64_limit(
            self.limits.max_read_bytes,
            "limits.max_read_bytes",
            MAX_READ_BYTES_HARD_CAP,
        )?;
        if let Some(max_patch_bytes) = self.limits.max_patch_bytes {
            validate_u64_limit(
                max_patch_bytes,
                "limits.max_patch_bytes",
                MAX_PATCH_BYTES_HARD_CAP,
            )?;
        }
        validate_u64_limit(
            self.limits.max_write_bytes,
            "limits.max_write_bytes",
            MAX_WRITE_BYTES_HARD_CAP,
        )?;
        validate_usize_limit(
            self.limits.max_results,
            "limits.max_results",
            MAX_RESULTS_HARD_CAP,
        )?;
        validate_usize_limit(
            self.limits.max_walk_files,
            "limits.max_walk_files",
            MAX_WALK_FILES_HARD_CAP,
        )?;
        validate_usize_limit(
            self.limits.max_walk_entries,
            "limits.max_walk_entries",
            MAX_WALK_ENTRIES_HARD_CAP,
        )?;
        if self.limits.max_walk_files > self.limits.max_walk_entries {
            return Err(Error::InvalidPolicy(
                "limits.max_walk_files must be <= limits.max_walk_entries".to_string(),
            ));
        }
        validate_usize_limit(
            self.limits.max_line_bytes,
            "limits.max_line_bytes",
            MAX_LINE_BYTES_HARD_CAP,
        )?;
        if let Some(max_glob_bytes) = self.limits.max_glob_bytes {
            validate_usize_limit(
                max_glob_bytes,
                "limits.max_glob_bytes",
                MAX_GLOB_RESPONSE_BYTES_HARD_CAP,
            )?;
        }
        validate_glob_response_budget(
            self.limits.max_results,
            self.limits.max_line_bytes,
            self.limits.max_glob_bytes,
        )?;
        validate_list_dir_response_budget(self.limits.max_results, self.limits.max_line_bytes)?;
        validate_grep_response_budget(self.limits.max_results, self.limits.max_line_bytes)?;
        let mut seen_ids = std::collections::HashSet::<&str>::new();
        for root in &self.roots {
            let normalized_id = root.id.trim();
            if normalized_id.is_empty() {
                return Err(Error::InvalidPolicy("root.id is empty".to_string()));
            }
            if normalized_id != root.id {
                return Err(Error::InvalidPolicy(format!(
                    "root.id must not contain leading/trailing whitespace: {:?}",
                    root.id
                )));
            }
            if normalized_id.len() > ROOT_ID_MAX_LEN {
                return Err(Error::InvalidPolicy(format!(
                    "root.id is too long: {:?} (max={})",
                    root.id, ROOT_ID_MAX_LEN
                )));
            }
            if !is_valid_root_id(normalized_id) {
                return Err(Error::InvalidPolicy(format!(
                    "root.id contains invalid characters: {:?} (allowed: [A-Za-z0-9._-])",
                    root.id
                )));
            }
            if !seen_ids.insert(normalized_id) {
                return Err(Error::InvalidPolicy(format!(
                    "duplicate root.id: {:?}",
                    root.id
                )));
            }
            if root.path.as_os_str().is_empty() {
                return Err(Error::InvalidPolicy(format!(
                    "root.path is empty (root.id={})",
                    root.id
                )));
            }
            if !root.path.is_absolute() {
                return Err(Error::InvalidPolicy(format!(
                    "root.path must be absolute (root.id={}, path={})",
                    root.id,
                    root.path.display()
                )));
            }
        }
        Ok(())
    }

    pub fn root(&self, id: &str) -> Result<&Root> {
        self.roots
            .iter()
            .find(|root| root.id == id)
            .ok_or_else(|| Error::RootNotFound(id.to_string()))
    }

    /// Resolve a path against the selected root without enforcing root-boundary checks.
    ///
    /// This does **not** enforce any root boundary checks; it only joins paths.
    /// Use `ops::Context` (or equivalent checks) to ensure the resolved path
    /// stays within the root.
    ///
    /// On Windows, this also rejects rooted paths (e.g. `\foo`), drive-relative
    /// paths (e.g. `C:foo`), and paths containing `:` in a normal component
    /// (blocks NTFS alternate data streams like `file.txt:stream`).
    ///
    /// This function is purely lexical: it does not touch the filesystem and does not attempt to
    /// detect Windows reparse points / junctions. Root boundary enforcement is best-effort and
    /// happens in `ops::Context` (and is not TOCTOU-hardened).
    pub fn resolve_path_unchecked(&self, root_id: &str, path: &Path) -> Result<PathBuf> {
        let root = self.root(root_id)?;
        if path.as_os_str().is_empty() {
            return Err(Error::InvalidPath("path is empty".to_string()));
        }
        if path.is_absolute() && !self.paths.allow_absolute {
            return Err(Error::InvalidPath(
                "absolute request paths are not allowed by policy".to_string(),
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;

            if !path.is_absolute() && matches!(path.components().next(), Some(Component::RootDir)) {
                return Err(Error::InvalidPath(format!(
                    "invalid path {}: rooted paths are not supported",
                    path.display()
                )));
            }
            for comp in path.components() {
                if let Component::Normal(part) = comp
                    && part.encode_wide().any(|ch| ch == u16::from(b':'))
                {
                    return Err(Error::InvalidPath(format!(
                        "invalid path {}: ':' is not allowed on Windows",
                        path.display()
                    )));
                }
            }
            if !path.is_absolute() && matches!(path.components().next(), Some(Component::Prefix(_)))
            {
                return Err(Error::InvalidPath(format!(
                    "invalid path {}: drive-relative paths are not supported",
                    path.display()
                )));
            }
        }
        if path.is_absolute() {
            return Ok(path.to_path_buf());
        }
        Ok(root.path.join(path))
    }

    /// Resolve a path against the selected root and enforce lexical root-boundary checks.
    ///
    /// This is a lexical check only: it normalizes paths without accessing the filesystem or
    /// resolving symlinks.
    /// For canonicalized checks against existing filesystem state, use `ops::Context`.
    pub fn resolve_path_checked(&self, root_id: &str, path: &Path) -> Result<PathBuf> {
        let root = self.root(root_id)?;
        let resolved = self.resolve_path_unchecked(root_id, path)?;
        let normalized_resolved = crate::path_utils::normalized_for_boundary(&resolved);
        let normalized_root = crate::path_utils::normalized_for_boundary(&root.path);
        if !crate::path_utils::starts_with_case_insensitive_normalized(
            normalized_resolved.as_ref(),
            normalized_root.as_ref(),
        ) {
            return Err(Error::OutsideRoot {
                root_id: root_id.to_string(),
                path: crate::path_utils::normalize_path_lexical(path),
            });
        }
        // WARNING: lexical-only boundary check. This does not resolve symlinks and is not
        // TOCTOU-hardened. Security-sensitive callers must still canonicalize against live
        // filesystem state (see `ops::Context` resolution path).
        Ok(match normalized_resolved {
            std::borrow::Cow::Borrowed(_) => resolved,
            std::borrow::Cow::Owned(path) => path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use policy_meta::{Decision, ExecutionIsolation, RiskProfile, SpecVersion};
    use serde_json::json;

    fn sample_policy_meta() -> PolicyMetaV1 {
        PolicyMetaV1 {
            version: Some(SpecVersion::V1),
            risk_profile: Some(RiskProfile::Standard),
            write_scope: Some(WriteScope::WorkspaceWrite),
            execution_isolation: Some(ExecutionIsolation::BestEffort),
            decision: Some(Decision::Prompt),
        }
    }

    #[test]
    fn sandbox_policy_omits_empty_metadata_on_serialization() {
        let policy =
            SandboxPolicy::single_root("workspace", std::env::temp_dir(), WriteScope::ReadOnly);

        let value = serde_json::to_value(&policy).expect("serialize policy");

        assert!(value.get("metadata").is_none());
    }

    #[test]
    fn sandbox_policy_supports_nested_policy_meta() {
        let root_path = std::env::temp_dir();
        let root_path_string = root_path.to_string_lossy().into_owned();

        let policy: SandboxPolicy = serde_json::from_value(json!({
            "roots": [{
                "id": "workspace",
                "path": root_path_string,
                "write_scope": "read_only"
            }],
            "permissions": {
                "read": true
            },
            "metadata": {
                "policy_meta": {
                    "version": 1,
                    "risk_profile": "standard",
                    "write_scope": "workspace_write",
                    "execution_isolation": "best_effort",
                    "decision": "prompt"
                }
            }
        }))
        .expect("deserialize policy");

        policy.validate().expect("validate policy");
        assert_eq!(
            policy.root("workspace").expect("root").write_scope,
            WriteScope::ReadOnly
        );
        assert_eq!(
            policy.metadata.policy_meta.as_ref().expect("policy meta"),
            &sample_policy_meta()
        );

        let value = serde_json::to_value(&policy).expect("serialize policy");
        assert_eq!(
            value["metadata"]["policy_meta"],
            json!({
                "version": 1,
                "risk_profile": "standard",
                "write_scope": "workspace_write",
                "execution_isolation": "best_effort",
                "decision": "prompt"
            })
        );
    }
}
