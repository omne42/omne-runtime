#![deny(unsafe_code)]

//! `omne-fs` provides policy-bounded filesystem operations for local tooling.
//!
//! The crate enforces an explicit root/permission policy in-process and offers stable request/
//! response types for operations like read/write/edit/delete/list_dir/copy/move/mkdir/stat/patch.
//! `glob` and `grep` APIs are always available; when the corresponding `glob`/`grep`
//! feature is disabled, calls return `Error::NotPermitted`.

mod error;
pub mod ops;
pub mod path_utils;
mod platform;

pub(crate) mod path_utils_internal {
    pub(crate) use super::path_utils::{
        build_glob_from_normalized, normalize_glob_pattern_for_matching, normalize_path_lexical,
        validate_root_relative_glob_pattern,
    };
}
mod platform_open;
pub mod policy;
#[cfg(feature = "policy-io")]
pub mod policy_io;
pub mod redaction;

pub use error::{Error, Result};

pub use ops::{
    Context, CopyFileRequest, CopyFileResponse, DeleteKind, DeleteRequest, DeleteResponse,
    EditRequest, EditResponse, GlobRequest, GlobResponse, GrepMatch, GrepRequest, GrepResponse,
    ListDirEntry, ListDirRequest, ListDirResponse, MkdirRequest, MkdirResponse, MovePathRequest,
    MovePathResponse, PatchRequest, PatchResponse, ReadRequest, ReadResponse, ScanLimitReason,
    StatKind, StatRequest, StatResponse, WriteFileRequest, WriteFileResponse, glob_paths, grep,
};
pub use ops::{
    apply_unified_patch, copy_file, delete, edit_range, list_dir, mkdir, move_path, read_file,
    stat, write_file,
};

pub use policy::{
    Limits, PathRules, Permissions, PolicyMetaV1, PolicyMetadata, Root, RootMode, SandboxPolicy,
    SecretRules, TraversalRules,
};
