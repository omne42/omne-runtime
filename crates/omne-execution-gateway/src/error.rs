use std::path::PathBuf;

use thiserror::Error;

use crate::types::IsolationLevel;

#[derive(Debug, Error)]
pub enum ExecError {
    #[error(
        "security policy violation: requested isolation {requested:?}, but host only supports {supported:?}"
    )]
    IsolationNotSupported {
        requested: IsolationLevel,
        supported: IsolationLevel,
    },

    #[error("workspace root does not exist or is inaccessible: {path}")]
    WorkspaceRootInvalid { path: PathBuf },

    #[error("working directory is outside workspace root: cwd={cwd}, root={workspace_root}")]
    CwdOutsideWorkspace {
        cwd: PathBuf,
        workspace_root: PathBuf,
    },

    #[error(
        "request claims policy-default isolation {requested:?}, but gateway policy default is {policy_default:?}"
    )]
    PolicyDefaultIsolationMismatch {
        requested: IsolationLevel,
        policy_default: IsolationLevel,
    },

    #[error(
        "prepared command does not match request identity: requested {requested_program:?} {requested_args:?}, actual {actual_program:?} {actual_args:?}"
    )]
    PreparedCommandMismatch {
        requested_program: String,
        requested_args: Vec<String>,
        actual_program: String,
        actual_args: Vec<String>,
    },

    #[error("sandbox backend rejected request: {0}")]
    Sandbox(String),

    #[error("policy denied request: {0}")]
    PolicyDenied(String),

    #[error("failed to spawn process: {0}")]
    Spawn(#[source] std::io::Error),
}

pub type ExecResult<T> = std::result::Result<T, ExecError>;
