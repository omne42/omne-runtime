use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::audit::ExecEvent;
use crate::error::{ExecError, ExecResult};

#[derive(Debug, Clone)]
pub struct AuditLogger {
    path: PathBuf,
}

impl AuditLogger {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub fn write_prepare_record(&self, event: &ExecEvent, result: &ExecResult<()>) {
        self.write_record(AuditRecord::from_prepare(event, result));
    }

    pub fn write_execution_record(&self, event: &ExecEvent, result: &ExecResult<ExitStatus>) {
        self.write_record(AuditRecord::from_execution(event, result));
    }

    fn write_record(&self, record: AuditRecord) {
        if let Err(err) = self.try_write_record(record) {
            eprintln!(
                "omne-execution-gateway: failed to write audit log {}: {err}",
                self.path.display()
            );
        }
    }

    fn try_write_record(&self, record: AuditRecord) -> Result<(), Box<dyn std::error::Error>> {
        let line = serde_json::to_string(&record)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        writeln!(file, "{line}")?;
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct AuditRecord {
    ts_unix_ms: u128,
    event: ExecEvent,
    result: AuditResult,
}

impl AuditRecord {
    fn from_prepare(event: &ExecEvent, result: &ExecResult<()>) -> Self {
        Self {
            ts_unix_ms: now_unix_ms(),
            event: event.clone(),
            result: AuditResult::from_prepare(result),
        }
    }

    fn from_execution(event: &ExecEvent, result: &ExecResult<ExitStatus>) -> Self {
        Self {
            ts_unix_ms: now_unix_ms(),
            event: event.clone(),
            result: AuditResult::from_execution(result),
        }
    }
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[derive(Debug, Serialize)]
struct AuditResult {
    status: &'static str,
    error: Option<String>,
    exit_code: Option<i32>,
    success: Option<bool>,
    signal: Option<i32>,
}

impl AuditResult {
    fn from_prepare(result: &ExecResult<()>) -> Self {
        match result {
            Ok(()) => Self {
                status: "prepared",
                error: None,
                exit_code: None,
                success: None,
                signal: None,
            },
            Err(err) => Self {
                status: "prepare_error",
                error: Some(err.to_string()),
                exit_code: None,
                success: None,
                signal: None,
            },
        }
    }

    fn from_execution(result: &ExecResult<ExitStatus>) -> Self {
        match result {
            Ok(status) => Self {
                status: "exited",
                error: exit_status_signal(status)
                    .map(|signal| format!("process terminated by signal {signal}")),
                exit_code: status.code(),
                success: Some(status.success()),
                signal: exit_status_signal(status),
            },
            Err(ExecError::Spawn(err)) => Self {
                status: "spawn_error",
                error: Some(err.to_string()),
                exit_code: None,
                success: None,
                signal: None,
            },
            Err(err) => Self {
                status: "prepare_error",
                error: Some(err.to_string()),
                exit_code: None,
                success: None,
                signal: None,
            },
        }
    }
}

#[cfg(unix)]
fn exit_status_signal(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(not(unix))]
fn exit_status_signal(_: &ExitStatus) -> Option<i32> {
    None
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use serde_json::json;
    use tempfile::tempdir;

    use super::*;
    use crate::audit::{ExecDecision, ExecEvent};
    use crate::types::IsolationLevel;

    #[test]
    fn writes_jsonl_record() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(&path);

        let event = ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: IsolationLevel::BestEffort,
            requested_policy_meta: crate::audit::requested_policy_meta(IsolationLevel::BestEffort),
            supported_isolation: IsolationLevel::BestEffort,
            program: "echo".into(),
            cwd: ".".into(),
            workspace_root: ".".into(),
            declared_mutation: false,
            reason: None,
            sandbox_runtime: None,
        };

        logger.write_prepare_record(&event, &Ok(()));

        let content = fs::read_to_string(path).expect("read audit");
        let record: serde_json::Value =
            serde_json::from_str(content.lines().next().expect("audit line")).expect("json");
        assert_eq!(record["result"]["status"], "prepared");
        assert_eq!(record["event"]["decision"], "run");
        assert_eq!(record["event"]["program"], "echo");
        assert_eq!(
            record["event"]["requested_policy_meta"],
            json!({
                "version": 1,
                "execution_isolation": "best_effort"
            })
        );
    }

    #[test]
    fn writes_execution_record_with_exit_metadata() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(&path);

        let event = ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: IsolationLevel::BestEffort,
            requested_policy_meta: crate::audit::requested_policy_meta(IsolationLevel::BestEffort),
            supported_isolation: IsolationLevel::BestEffort,
            program: "false".into(),
            cwd: ".".into(),
            workspace_root: ".".into(),
            declared_mutation: false,
            reason: None,
            sandbox_runtime: None,
        };

        logger.write_execution_record(&event, &Ok(nonzero_exit_status()));

        let content = fs::read_to_string(path).expect("read audit");
        let record: serde_json::Value =
            serde_json::from_str(content.lines().next().expect("audit line")).expect("json");
        assert_eq!(record["result"]["status"], "exited");
        assert_eq!(record["result"]["exit_code"], 1);
        assert_eq!(record["result"]["success"], false);
        assert_eq!(
            record["event"]["requested_policy_meta"],
            json!({
                "version": 1,
                "execution_isolation": "best_effort"
            })
        );
    }

    #[cfg(windows)]
    fn nonzero_exit_status() -> ExitStatus {
        Command::new("cmd")
            .args(["/C", "exit 1"])
            .status()
            .expect("run cmd /C exit 1")
    }

    #[cfg(not(windows))]
    fn nonzero_exit_status() -> ExitStatus {
        Command::new("sh")
            .args(["-c", "exit 1"])
            .status()
            .expect("run sh -c exit 1")
    }
}
