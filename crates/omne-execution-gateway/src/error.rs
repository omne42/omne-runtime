use std::path::PathBuf;
use std::process::ExitStatus;

use thiserror::Error;

use policy_meta::ExecutionIsolation;

#[derive(Debug, Error)]
pub enum ExecError {
    #[error(
        "security policy violation: requested isolation {requested:?}, but host only supports {supported:?}"
    )]
    IsolationNotSupported {
        requested: ExecutionIsolation,
        supported: ExecutionIsolation,
    },

    #[error("workspace root does not exist or is inaccessible: {path}")]
    WorkspaceRootInvalid { path: PathBuf },

    #[error("explicit program paths must be absolute: {program}")]
    RelativeProgramPath { program: String },

    #[error("program path is invalid: {path} ({detail})")]
    ProgramPathInvalid { path: PathBuf, detail: String },

    #[error("program lookup failed for {program}: {detail}")]
    ProgramLookupFailed { program: String, detail: String },

    #[error("working directory is outside workspace root: cwd={cwd}, root={workspace_root}")]
    CwdOutsideWorkspace {
        cwd: PathBuf,
        workspace_root: PathBuf,
    },

    #[error("working directory is invalid: {cwd} ({detail})")]
    CwdInvalid { cwd: PathBuf, detail: String },

    #[error(
        "request must explicitly declare whether it mutates host state before gateway evaluation"
    )]
    MutationDeclarationRequired,

    #[error("cannot bind validated {kind} identity for {path}")]
    PathIdentityUnavailable { kind: &'static str, path: PathBuf },

    #[error("validated {kind} changed before spawn: {path} ({detail})")]
    RequestPathChanged {
        kind: &'static str,
        path: PathBuf,
        detail: String,
    },

    #[error(
        "request claims policy-default isolation {requested:?}, but gateway policy default is {policy_default:?}"
    )]
    PolicyDefaultIsolationMismatch {
        requested: ExecutionIsolation,
        policy_default: ExecutionIsolation,
    },

    #[error("sandbox backend rejected request: {0}")]
    Sandbox(String),

    #[error("policy denied request: {0}")]
    PolicyDenied(String),

    #[error("audit log is unavailable at {path}: {detail}")]
    AuditLogUnavailable { path: PathBuf, detail: String },

    #[error("audit log path is invalid: {path} ({detail})")]
    AuditLogPathInvalid { path: PathBuf, detail: String },

    #[error("failed to write audit log at {path}: {detail}")]
    AuditLogWriteFailed { path: PathBuf, detail: String },

    #[error(
        "failed to write audit log at {path}: {detail} after the process already exited with {status}"
    )]
    AuditLogWriteFailedAfterExecutionSuccess {
        path: PathBuf,
        detail: String,
        status: ExitStatus,
    },

    #[error(
        "failed to write audit log at {path}: {detail} (original execution error: {execution_error})"
    )]
    AuditLogWriteFailedAfterExecutionError {
        path: PathBuf,
        detail: String,
        execution_error: String,
    },

    #[error("failed to spawn process: {0}")]
    Spawn(#[source] std::io::Error),
}

impl ExecError {
    /// Returns the child status when execution already completed but persisting the terminal audit
    /// record failed afterwards.
    #[must_use]
    pub fn completed_status(&self) -> Option<&ExitStatus> {
        match self {
            Self::AuditLogWriteFailedAfterExecutionSuccess { status, .. } => Some(status),
            _ => None,
        }
    }

    /// Returns whether the child already completed successfully before the audit write failed.
    #[must_use]
    pub fn command_completed_successfully(&self) -> bool {
        self.completed_status().is_some_and(ExitStatus::success)
    }
}

pub type ExecResult<T> = std::result::Result<T, ExecError>;

#[cfg(test)]
mod tests {
    use super::ExecError;
    use std::path::PathBuf;
    use std::process::{Command, ExitStatus};

    #[cfg(windows)]
    fn exit_status_from_code(code: i32) -> ExitStatus {
        Command::new("cmd")
            .args(["/C", &format!("exit {code}")])
            .status()
            .expect("run cmd exit")
    }

    #[cfg(not(windows))]
    fn exit_status_from_code(code: i32) -> ExitStatus {
        Command::new("sh")
            .args(["-c", &format!("exit {code}")])
            .status()
            .expect("run sh exit")
    }

    #[test]
    fn completed_status_is_exposed_for_post_execution_audit_failures() {
        let err = ExecError::AuditLogWriteFailedAfterExecutionSuccess {
            path: PathBuf::from("audit.jsonl"),
            detail: "disk full".to_string(),
            status: exit_status_from_code(7),
        };

        assert_eq!(err.completed_status().and_then(ExitStatus::code), Some(7));
        assert!(!err.command_completed_successfully());
    }

    #[test]
    fn completed_status_is_absent_for_pre_execution_failures() {
        let err = ExecError::PolicyDenied("denied".to_string());

        assert!(err.completed_status().is_none());
        assert!(!err.command_completed_successfully());
    }

    #[test]
    fn command_completed_successfully_reports_zero_exit_status() {
        let err = ExecError::AuditLogWriteFailedAfterExecutionSuccess {
            path: PathBuf::from("audit.jsonl"),
            detail: "disk full".to_string(),
            status: exit_status_from_code(0),
        };

        assert!(err.command_completed_successfully());
    }
}
