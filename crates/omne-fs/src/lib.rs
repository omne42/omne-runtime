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
pub mod policy;
#[cfg(feature = "policy-io")]
pub mod policy_io;
mod redaction;

pub use error::{Error, Result};
