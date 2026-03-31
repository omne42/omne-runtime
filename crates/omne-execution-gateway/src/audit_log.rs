use std::fmt::Display;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::{SystemTime, UNIX_EPOCH};

use fs2::FileExt;
use serde::Serialize;

use crate::audit::ExecEvent;
use crate::error::{ExecError, ExecResult};
use crate::path_guard;

const APPENDABLE_OPEN_NOT_FOUND_RETRIES: usize = 4;

#[derive(Debug, Clone)]
pub(crate) struct AuditLogger {
    path: PathBuf,
}

impl AuditLogger {
    pub(crate) fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    pub(crate) fn write_prepare_record<T, E>(
        &self,
        event: &ExecEvent,
        result: &Result<T, E>,
    ) -> ExecResult<()>
    where
        E: Display,
    {
        self.write_record(AuditRecord::from_prepare(event, result))
    }

    pub(crate) fn write_execution_record(
        &self,
        event: &ExecEvent,
        result: &ExecResult<ExitStatus>,
    ) -> ExecResult<()> {
        self.write_record(AuditRecord::from_execution(event, result))
    }

    pub(crate) fn ensure_ready(&self) -> ExecResult<()> {
        self.try_open_appendable_file()
            .map(|_| ())
            .map_err(|err| ExecError::AuditLogUnavailable {
                path: self.path.clone(),
                detail: err.to_string(),
            })
    }

    pub(crate) fn validate_ready_without_side_effects(&self) -> ExecResult<()> {
        path_guard::validate_appendable_regular_file_nofollow(&self.path, "audit log").map_err(
            |err| ExecError::AuditLogUnavailable {
                path: self.path.clone(),
                detail: err.to_string(),
            },
        )
    }

    fn write_record(&self, record: AuditRecord) -> ExecResult<()> {
        self.try_write_record(record)
            .map_err(|err| ExecError::AuditLogWriteFailed {
                path: self.path.clone(),
                detail: err.to_string(),
            })
    }

    fn try_write_record(&self, record: AuditRecord) -> Result<(), Box<dyn std::error::Error>> {
        let line = serde_json::to_string(&record)?;
        let mut file = self.try_open_appendable_file()?;
        file.lock_exclusive()?;
        let write_result = file
            .seek(SeekFrom::End(0))
            .and_then(|_| writeln!(file, "{line}"))
            .and_then(|_| file.flush());
        let unlock_result = file.unlock();
        write_result?;
        unlock_result?;
        Ok(())
    }

    fn try_open_appendable_file(&self) -> Result<std::fs::File, Box<dyn std::error::Error>> {
        let mut last_not_found = None;
        for attempt in 0..APPENDABLE_OPEN_NOT_FOUND_RETRIES {
            match path_guard::open_appendable_regular_file_nofollow(&self.path, "audit log") {
                Ok(file) => return Ok(file),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                    last_not_found = Some(err);
                    if attempt + 1 < APPENDABLE_OPEN_NOT_FOUND_RETRIES {
                        std::thread::yield_now();
                        continue;
                    }
                }
                Err(err) => return Err(err.into()),
            }
        }

        Err(last_not_found
            .unwrap_or_else(|| std::io::Error::other("audit log open failed without an error"))
            .into())
    }
}

#[derive(Debug, Serialize)]
struct AuditRecord {
    ts_unix_ms: u128,
    event: ExecEvent,
    result: AuditResult,
}

impl AuditRecord {
    fn from_prepare<T, E>(event: &ExecEvent, result: &Result<T, E>) -> Self
    where
        E: Display,
    {
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
    fn from_prepare<T, E>(result: &Result<T, E>) -> Self
    where
        E: Display,
    {
        match result {
            Ok(_) => Self {
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
    use std::ffi::OsString;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use serde_json::json;
    use tempfile::tempdir;

    use super::*;
    use crate::audit::{ExecDecision, ExecEvent};
    use policy_meta::ExecutionIsolation;

    fn canonical_test_root(dir: &tempfile::TempDir) -> PathBuf {
        dir.path()
            .canonicalize()
            .unwrap_or_else(|_| dir.path().to_path_buf())
    }

    #[test]
    fn writes_jsonl_record() {
        let dir = tempdir().expect("tempdir");
        let path = canonical_test_root(&dir).join("audit.jsonl");
        let logger = AuditLogger::new(&path);

        let event = sample_event("echo");

        logger
            .write_prepare_record(&event, &Ok::<(), ExecError>(()))
            .expect("write prepare record");

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
        let path = canonical_test_root(&dir).join("audit.jsonl");
        let logger = AuditLogger::new(&path);

        let event = sample_event("false");

        logger
            .write_execution_record(&event, &Ok(nonzero_exit_status()))
            .expect("write execution record");

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

    #[test]
    fn concurrent_prepare_writes_preserve_jsonl_lines() {
        let dir = tempdir().expect("tempdir");
        let path = canonical_test_root(&dir).join("audit.jsonl");
        let logger = Arc::new(AuditLogger::new(&path));
        let thread_count = 8;
        let writes_per_thread = 25;
        let barrier = Arc::new(Barrier::new(thread_count));

        let handles: Vec<_> = (0..thread_count)
            .map(|index| {
                let logger = Arc::clone(&logger);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    let event = sample_event(format!("echo-{index}"));
                    barrier.wait();
                    for _ in 0..writes_per_thread {
                        logger
                            .write_prepare_record(&event, &Ok::<(), ExecError>(()))
                            .expect("concurrent audit write should succeed");
                    }
                })
            })
            .collect();

        for handle in handles {
            handle.join().expect("writer thread should not panic");
        }

        let content = fs::read_to_string(path).expect("read audit");
        let lines: Vec<_> = content.lines().collect();
        assert_eq!(lines.len(), thread_count * writes_per_thread);
        for line in lines {
            let record: serde_json::Value = serde_json::from_str(line).expect("valid json line");
            assert_eq!(record["result"]["status"], "prepared");
        }
    }

    #[test]
    fn ensure_ready_creates_missing_parent_directories() {
        let dir = tempdir().expect("tempdir");
        let path = canonical_test_root(&dir)
            .join("nested")
            .join("audit")
            .join("audit.jsonl");
        let logger = AuditLogger::new(&path);

        logger
            .ensure_ready()
            .expect("audit path should become writable");

        assert!(path.exists(), "audit log file should be created");
        assert!(
            path.parent().expect("audit parent").is_dir(),
            "audit parent directories should be created"
        );
    }

    #[test]
    fn ensure_ready_rejects_non_directory_parent() {
        let dir = tempdir().expect("tempdir");
        let parent_file = canonical_test_root(&dir).join("not-a-dir");
        fs::write(&parent_file, "blocker").expect("write parent file");
        let audit_path = parent_file.join("audit.jsonl");
        let logger = AuditLogger::new(&audit_path);

        let err = logger
            .ensure_ready()
            .expect_err("audit path with file parent must fail");

        match err {
            ExecError::AuditLogUnavailable { path, .. } => assert_eq!(path, audit_path),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn ensure_ready_rejects_symlink_audit_sink() {
        let dir = tempdir().expect("tempdir");
        let root = canonical_test_root(&dir);
        let target = root.join("real-audit.jsonl");
        fs::write(&target, "target").expect("write target");
        let audit_path = root.join("audit.jsonl");
        symlink(&target, &audit_path).expect("create audit symlink");
        let logger = AuditLogger::new(&audit_path);

        let err = logger
            .ensure_ready()
            .expect_err("audit path symlink must fail");

        match err {
            ExecError::AuditLogUnavailable { path, .. } => assert_eq!(path, audit_path),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn ensure_ready_rejects_special_file_sink() {
        let dir = tempdir().expect("tempdir");
        let audit_path = canonical_test_root(&dir).join("audit.sock");
        let _listener = UnixListener::bind(&audit_path).expect("bind socket");
        let logger = AuditLogger::new(&audit_path);

        let err = logger
            .ensure_ready()
            .expect_err("special file sink must fail");

        match err {
            ExecError::AuditLogUnavailable { path, .. } => assert_eq!(path, audit_path),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn ensure_ready_rejects_symlink_parent_directory() {
        let dir = tempdir().expect("tempdir");
        let root = canonical_test_root(&dir);
        let target_parent = root.join("real-parent");
        fs::create_dir(&target_parent).expect("create target parent");
        let symlink_parent = root.join("linked-parent");
        symlink(&target_parent, &symlink_parent).expect("create parent symlink");
        let audit_path = symlink_parent.join("nested").join("audit.jsonl");
        let logger = AuditLogger::new(&audit_path);

        let err = logger
            .ensure_ready()
            .expect_err("audit path with symlink ancestor must fail");

        match err {
            ExecError::AuditLogUnavailable { path, .. } => assert_eq!(path, audit_path),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn write_prepare_record_surfaces_post_ready_write_failure() {
        let dir = tempdir().expect("tempdir");
        let path = canonical_test_root(&dir).join("audit.jsonl");
        let logger = AuditLogger::new(&path);
        let event = sample_event("echo");

        logger
            .ensure_ready()
            .expect("audit path should be writable before failure injection");
        fs::remove_file(&path).expect("remove audit file");
        fs::create_dir(&path).expect("replace audit file with directory");

        let err = logger
            .write_prepare_record(&event, &Ok::<(), ExecError>(()))
            .expect_err("write failure should be returned");
        match err {
            ExecError::AuditLogWriteFailed { path: err_path, .. } => assert_eq!(err_path, path),
            other => panic!("unexpected error: {other}"),
        }
    }

    fn sample_event(program: impl Into<OsString>) -> ExecEvent {
        ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: ExecutionIsolation::BestEffort,
            requested_policy_meta: crate::audit::requested_policy_meta(
                ExecutionIsolation::BestEffort,
            ),
            supported_isolation: ExecutionIsolation::BestEffort,
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: ".".into(),
            workspace_root: ".".into(),
            declared_mutation: false,
            reason: None,
            sandbox_runtime: None,
        }
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
