use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
#[non_exhaustive]
#[error(transparent)]
pub struct Utf8Source(#[from] std::str::Utf8Error);

impl From<std::string::FromUtf8Error> for Utf8Source {
    fn from(source: std::string::FromUtf8Error) -> Self {
        Self(source.utf8_error())
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[source] std::io::Error),

    #[error("io error during {op} ({path}): {source}")]
    IoPath {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("filesystem update committed but parent sync failed during {op} ({path}): {source}")]
    CommittedButUnsynced {
        op: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[cfg(any(feature = "glob", feature = "grep"))]
    #[error("walkdir error: {0}")]
    WalkDir(#[from] walkdir::Error),

    #[cfg(any(feature = "glob", feature = "grep"))]
    #[error("io error while preparing walk root ({path}): {source}")]
    WalkDirRoot {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("invalid path: {0}")]
    InvalidPath(String),

    #[error("root not found: {0}")]
    RootNotFound(String),

    #[error("path resolves outside root '{root_id}': {path}")]
    OutsideRoot { root_id: String, path: PathBuf },

    #[error("operation is not permitted: {0}")]
    NotPermitted(String),

    #[error("path is denied by secret rules: {0}")]
    SecretPathDenied(PathBuf),

    #[error("file is too large ({size_bytes} bytes; max {max_bytes} bytes): {path}")]
    FileTooLarge {
        path: PathBuf,
        size_bytes: u64,
        max_bytes: u64,
    },

    #[error("invalid utf-8 in file: {path}: {source}")]
    InvalidUtf8 {
        path: PathBuf,
        #[source]
        source: Utf8Source,
    },

    #[error("failed to apply patch: {0}")]
    Patch(String),

    #[error("invalid regex pattern {pattern:?}: {source}")]
    InvalidRegex {
        pattern: String,
        #[source]
        source: regex::Error,
    },

    #[error("input is too large ({size_bytes} bytes; max {max_bytes} bytes)")]
    InputTooLarge { size_bytes: u64, max_bytes: u64 },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub const CODE_IO: &'static str = "io";
    pub const CODE_IO_PATH: &'static str = "io_path";
    pub const CODE_COMMITTED_UNSYNCED: &'static str = "committed_unsynced";
    #[cfg(any(feature = "glob", feature = "grep"))]
    pub const CODE_WALKDIR: &'static str = "walkdir";
    #[cfg(any(feature = "glob", feature = "grep"))]
    pub const CODE_WALKDIR_ROOT: &'static str = "walkdir_root";
    pub const CODE_INVALID_POLICY: &'static str = "invalid_policy";
    pub const CODE_INVALID_PATH: &'static str = "invalid_path";
    pub const CODE_ROOT_NOT_FOUND: &'static str = "root_not_found";
    pub const CODE_OUTSIDE_ROOT: &'static str = "outside_root";
    pub const CODE_NOT_PERMITTED: &'static str = "not_permitted";
    pub const CODE_SECRET_PATH_DENIED: &'static str = "secret_path_denied";
    pub const CODE_FILE_TOO_LARGE: &'static str = "file_too_large";
    pub const CODE_INVALID_UTF8: &'static str = "invalid_utf8";
    pub const CODE_PATCH: &'static str = "patch";
    pub const CODE_INVALID_REGEX: &'static str = "invalid_regex";
    pub const CODE_INPUT_TOO_LARGE: &'static str = "input_too_large";

    pub(crate) fn io_path(
        op: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self::IoPath {
            op,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn committed_but_unsynced(
        op: &'static str,
        path: impl Into<PathBuf>,
        source: std::io::Error,
    ) -> Self {
        Self::CommittedButUnsynced {
            op,
            path: path.into(),
            source,
        }
    }

    pub(crate) fn invalid_utf8(path: impl Into<PathBuf>, source: impl Into<Utf8Source>) -> Self {
        Self::InvalidUtf8 {
            path: path.into(),
            source: source.into(),
        }
    }

    #[cfg(any(feature = "grep", test))]
    pub(crate) fn invalid_regex(pattern: impl Into<String>, source: regex::Error) -> Self {
        Self::InvalidRegex {
            pattern: pattern.into(),
            source,
        }
    }

    /// A stable, programmatic error code for callers that need to classify failures.
    pub fn code(&self) -> &'static str {
        match self {
            Error::Io(_) => Self::CODE_IO,
            Error::IoPath { .. } => Self::CODE_IO_PATH,
            Error::CommittedButUnsynced { .. } => Self::CODE_COMMITTED_UNSYNCED,
            #[cfg(any(feature = "glob", feature = "grep"))]
            Error::WalkDir(_) => Self::CODE_WALKDIR,
            #[cfg(any(feature = "glob", feature = "grep"))]
            Error::WalkDirRoot { .. } => Self::CODE_WALKDIR_ROOT,
            Error::InvalidPolicy(_) => Self::CODE_INVALID_POLICY,
            Error::InvalidPath(_) => Self::CODE_INVALID_PATH,
            Error::RootNotFound(_) => Self::CODE_ROOT_NOT_FOUND,
            Error::OutsideRoot { .. } => Self::CODE_OUTSIDE_ROOT,
            Error::NotPermitted(_) => Self::CODE_NOT_PERMITTED,
            Error::SecretPathDenied(_) => Self::CODE_SECRET_PATH_DENIED,
            Error::FileTooLarge { .. } => Self::CODE_FILE_TOO_LARGE,
            Error::InvalidUtf8 { .. } => Self::CODE_INVALID_UTF8,
            Error::Patch(_) => Self::CODE_PATCH,
            Error::InvalidRegex { .. } => Self::CODE_INVALID_REGEX,
            Error::InputTooLarge { .. } => Self::CODE_INPUT_TOO_LARGE,
        }
    }

    /// Coarse-grained risk tag for fast policy/audit grouping.
    pub fn risk_tag(&self) -> &'static str {
        match self {
            Error::OutsideRoot { .. } | Error::SecretPathDenied(_) => "boundary_violation",
            Error::NotPermitted(_) => "authorization",
            Error::InvalidPolicy(_) | Error::RootNotFound(_) => "policy_configuration",
            Error::InvalidPath(_)
            | Error::InvalidUtf8 { .. }
            | Error::InvalidRegex { .. }
            | Error::Patch(_)
            | Error::InputTooLarge { .. }
            | Error::FileTooLarge { .. } => "input_validation",
            Error::Io(_) | Error::IoPath { .. } | Error::CommittedButUnsynced { .. } => {
                "runtime_io"
            }
            #[cfg(any(feature = "glob", feature = "grep"))]
            Error::WalkDir(_) | Error::WalkDirRoot { .. } => "runtime_io",
        }
    }

    /// Optional policy rule hint associated with an error.
    pub fn policy_rule(&self) -> Option<&'static str> {
        match self {
            Error::OutsideRoot { .. } => Some("roots/paths.allow_absolute"),
            Error::SecretPathDenied(_) => Some("secrets.deny_globs"),
            Error::InvalidPolicy(_) => Some("policy.validate"),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    fn not_found_error() -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::NotFound, "not found")
    }

    #[cfg(any(feature = "glob", feature = "grep"))]
    fn sample_walkdir_error() -> walkdir::Error {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("missing");
        walkdir::WalkDir::new(&missing)
            .into_iter()
            .find_map(|entry| entry.err())
            .expect("walk error")
    }

    fn sample_utf8_error() -> std::str::Utf8Error {
        let bytes = vec![0xFF_u8];
        std::str::from_utf8(&bytes).expect_err("invalid utf8")
    }

    fn sample_from_utf8_error() -> std::string::FromUtf8Error {
        String::from_utf8(vec![0xFF]).expect_err("invalid utf8")
    }

    fn sample_regex_error() -> regex::Error {
        let invalid = String::from("[");
        regex::Regex::new(&invalid).expect_err("invalid regex")
    }

    #[test]
    fn code_covers_variants() {
        let cases = vec![
            (Error::Io(not_found_error()), Error::CODE_IO),
            (
                Error::IoPath {
                    op: "open",
                    path: PathBuf::from("file.txt"),
                    source: not_found_error(),
                },
                Error::CODE_IO_PATH,
            ),
            (
                Error::CommittedButUnsynced {
                    op: "rename",
                    path: PathBuf::from("file.txt"),
                    source: not_found_error(),
                },
                Error::CODE_COMMITTED_UNSYNCED,
            ),
            (
                Error::InvalidPolicy("x".to_string()),
                Error::CODE_INVALID_POLICY,
            ),
            (
                Error::InvalidPath("x".to_string()),
                Error::CODE_INVALID_PATH,
            ),
            (
                Error::RootNotFound("root".to_string()),
                Error::CODE_ROOT_NOT_FOUND,
            ),
            (
                Error::OutsideRoot {
                    root_id: "root".to_string(),
                    path: PathBuf::from("x"),
                },
                Error::CODE_OUTSIDE_ROOT,
            ),
            (
                Error::NotPermitted("x".to_string()),
                Error::CODE_NOT_PERMITTED,
            ),
            (
                Error::SecretPathDenied(PathBuf::from("secret")),
                Error::CODE_SECRET_PATH_DENIED,
            ),
            (
                Error::FileTooLarge {
                    path: PathBuf::from("x"),
                    size_bytes: 2,
                    max_bytes: 1,
                },
                Error::CODE_FILE_TOO_LARGE,
            ),
            (
                Error::invalid_utf8(PathBuf::from("x"), sample_utf8_error()),
                Error::CODE_INVALID_UTF8,
            ),
            (Error::Patch("x".to_string()), Error::CODE_PATCH),
            (
                Error::invalid_regex("x".to_string(), sample_regex_error()),
                Error::CODE_INVALID_REGEX,
            ),
            (
                Error::InputTooLarge {
                    size_bytes: 2,
                    max_bytes: 1,
                },
                Error::CODE_INPUT_TOO_LARGE,
            ),
            #[cfg(any(feature = "glob", feature = "grep"))]
            (Error::WalkDir(sample_walkdir_error()), Error::CODE_WALKDIR),
            #[cfg(any(feature = "glob", feature = "grep"))]
            (
                Error::WalkDirRoot {
                    path: PathBuf::from("x"),
                    source: not_found_error(),
                },
                Error::CODE_WALKDIR_ROOT,
            ),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code);
        }
    }

    #[test]
    fn io_error_exposes_source() {
        let error = Error::Io(not_found_error());
        assert!(error.source().is_some());
    }

    #[test]
    fn invalid_utf8_exposes_source_and_context() {
        let error = Error::invalid_utf8(PathBuf::from("x.txt"), sample_from_utf8_error());
        assert!(error.source().is_some());
        assert_eq!(error.code(), Error::CODE_INVALID_UTF8);
        assert!(error.to_string().contains("x.txt"));
    }

    #[test]
    fn invalid_utf8_source_does_not_expose_from_utf8_error() {
        let error = Error::invalid_utf8(PathBuf::from("x.txt"), sample_from_utf8_error());
        let source = error.source().expect("utf8 source");
        assert!(source.downcast_ref::<Utf8Source>().is_some());
        assert!(
            source
                .downcast_ref::<std::string::FromUtf8Error>()
                .is_none()
        );
    }

    #[test]
    fn invalid_regex_exposes_source_and_context() {
        let error = Error::invalid_regex("[".to_string(), sample_regex_error());
        assert!(error.source().is_some());
        assert_eq!(error.code(), Error::CODE_INVALID_REGEX);
        assert!(error.to_string().contains("["));
    }

    #[test]
    fn code_is_used_as_stable_reason_code() {
        let err = Error::NotPermitted("x".to_string());
        assert_eq!(err.code(), Error::CODE_NOT_PERMITTED);
    }

    #[test]
    fn risk_tag_and_policy_rule_are_classified() {
        let boundary = Error::OutsideRoot {
            root_id: "root".to_string(),
            path: PathBuf::from("x"),
        };
        assert_eq!(boundary.risk_tag(), "boundary_violation");
        assert_eq!(boundary.policy_rule(), Some("roots/paths.allow_absolute"));

        let denied = Error::SecretPathDenied(PathBuf::from(".git/config"));
        assert_eq!(denied.risk_tag(), "boundary_violation");
        assert_eq!(denied.policy_rule(), Some("secrets.deny_globs"));

        let not_permitted = Error::NotPermitted("x".to_string());
        assert_eq!(not_permitted.risk_tag(), "authorization");
        assert_eq!(not_permitted.policy_rule(), None);

        let io = Error::Io(not_found_error());
        assert_eq!(io.risk_tag(), "runtime_io");
        assert_eq!(io.policy_rule(), None);
    }
}
