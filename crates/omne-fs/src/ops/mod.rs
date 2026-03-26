//! Internal operation modules and request/response API surface.
//!
//! `glob` / `grep` request and response types, plus their entrypoints, are always
//! available from this module and re-exported at crate root.
//! When a corresponding crate feature is disabled, the function returns a
//! deterministic `Error::NotPermitted` from its fallback implementation.

use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(any(feature = "glob", feature = "grep"))]
use globset::GlobSet;
use policy_meta::WriteScope;
use serde::{Deserialize, Serialize};

use crate::policy::{Permissions, SandboxPolicy};
use crate::redaction::SecretRedactor;

mod context;
mod copy_file;
mod delete;
mod edit;
mod git_permissions;
mod glob;
mod grep;
mod io;
mod list_dir;
mod mkdir;
mod move_path;
mod patch;
mod path_validation;
mod read;
mod resolve;
mod stat;
mod transfer;
#[cfg(any(feature = "glob", feature = "grep"))]
mod traversal;
mod write;

pub use context::DecisionTrace;
pub use copy_file::{CopyFileRequest, CopyFileResponse, copy_file};
pub use delete::{DeleteKind, DeleteRequest, DeleteResponse, delete};
pub use edit::{EditRequest, EditResponse, edit_range};
pub use glob::{GlobRequest, GlobResponse, glob_paths};
pub use grep::{GrepMatch, GrepRequest, GrepResponse, grep};
pub use list_dir::{ListDirEntry, ListDirEntryKind, ListDirRequest, ListDirResponse, list_dir};
pub use mkdir::{MkdirRequest, MkdirResponse, mkdir};
pub use move_path::{MovePathRequest, MovePathResponse, move_path};
pub use patch::{PatchRequest, PatchResponse, apply_unified_patch};
pub use read::{ReadRequest, ReadResponse, read_file};
pub use stat::{StatKind, StatRequest, StatResponse, stat};
pub use write::{WriteFileRequest, WriteFileResponse, write_file};

#[cfg(test)]
mod tests;

pub struct Context {
    policy: SandboxPolicy,
    redactor: SecretRedactor,
    roots: HashMap<String, RootRuntime>,
    #[cfg(any(feature = "glob", feature = "grep"))]
    traversal_skip_globs: Option<GlobSet>,
}

#[derive(Debug)]
struct RootRuntime {
    declared_path: PathBuf,
    canonical_path: PathBuf,
    write_scope: WriteScope,
}

impl std::fmt::Debug for Context {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut root_ids: Vec<_> = self.roots.keys().collect();
        root_ids.sort_unstable();
        let enabled_permission_count = count_enabled_permissions(&self.policy.permissions);
        f.debug_struct("Context")
            .field("roots", &root_ids)
            .field("permissions_enabled_count", &enabled_permission_count)
            .finish_non_exhaustive()
    }
}

fn count_enabled_permissions(permissions: &Permissions) -> usize {
    [
        permissions.read,
        permissions.glob,
        permissions.grep,
        permissions.list_dir,
        permissions.stat,
        permissions.edit,
        permissions.patch,
        permissions.delete,
        permissions.mkdir,
        permissions.write,
        permissions.move_path,
        permissions.copy_file,
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ScanLimitReason {
    /// Traversal stopped after visiting too many filesystem entries
    /// (files plus directories), as bounded by `limits.max_walk_entries`.
    Entries,
    /// Traversal stopped after visiting too many files, as bounded by
    /// `limits.max_walk_files`.
    Files,
    /// Traversal stopped after exceeding wall-clock budget, as bounded by
    /// `limits.max_walk_ms`.
    Time,
    /// Traversal stopped after collecting too many matches, as bounded by
    /// `limits.max_results`.
    Results,
    /// Traversal stopped after estimated response bytes exceeded the configured
    /// response budget (`limits.max_glob_bytes` or `limits.max_results * limits.max_line_bytes`).
    ResponseBytes,
}
