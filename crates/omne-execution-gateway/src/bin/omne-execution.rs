#![forbid(unsafe_code)]

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::process::{ExitCode, ExitStatus};
use std::str;

use omne_execution_gateway::{
    ExecEvent, ExecGateway, ExecRequest, ExecResult, GatewayPolicy, RequestResolution,
};
use policy_meta::ExecutionIsolation;
use serde::{Deserialize, Serialize};

const MAX_REQUEST_JSON_BYTES: usize = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecRequestWire {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    cwd: PathBuf,
    workspace_root: PathBuf,
    #[serde(default)]
    required_isolation: Option<ExecutionIsolation>,
    declared_mutation: bool,
}

#[derive(Debug, Serialize)]
struct ExecOutput {
    request_resolution: RequestResolution,
    event: ExecEvent,
    exit_code: Option<i32>,
    signal: Option<i32>,
    error: Option<String>,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("omne-execution error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode, String> {
    let mut policy_path = None::<PathBuf>;
    let mut request_path = None::<PathBuf>;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--policy" => {
                let val = args
                    .next()
                    .ok_or_else(|| "missing value for --policy".to_string())?;
                policy_path = Some(PathBuf::from(val));
            }
            "--request" => {
                let val = args
                    .next()
                    .ok_or_else(|| "missing value for --request".to_string())?;
                request_path = Some(PathBuf::from(val));
            }
            _ => {
                return Err(format!(
                    "unknown argument: {arg}. usage: omne-execution --policy <policy.json> --request <request.json>"
                ));
            }
        }
    }

    let policy_path = policy_path.ok_or_else(|| "missing --policy".to_string())?;
    let request_path = request_path.ok_or_else(|| "missing --request".to_string())?;

    let policy = GatewayPolicy::load_json(&policy_path)
        .map_err(|e| format!("failed to load policy {}: {e}", policy_path.display()))?;

    let request_wire = load_request(&request_path)?;
    let request = build_exec_request(&policy, request_wire)?;
    let gateway = ExecGateway::with_policy(policy);
    let request_resolution = gateway.resolve_request(&request);
    let execution = gateway.execute(&request);
    let output = exec_output_from_result(request_resolution, execution.event, execution.result);

    println!(
        "{}",
        serde_json::to_string(&output).map_err(|e| format!("serialize output failed: {e}"))?
    );

    Ok(match output.exit_code {
        Some(0) if output.signal.is_none() => ExitCode::SUCCESS,
        Some(_) | None => ExitCode::FAILURE,
    })
}

fn build_exec_request(
    policy: &GatewayPolicy,
    request_wire: ExecRequestWire,
) -> Result<ExecRequest, String> {
    let request = match request_wire.required_isolation {
        Some(required_isolation) => ExecRequest::new(
            request_wire.program,
            request_wire.args,
            request_wire.cwd,
            required_isolation,
            request_wire.workspace_root,
        ),
        None => ExecRequest::with_policy_default_isolation(
            request_wire.program,
            request_wire.args,
            request_wire.cwd,
            policy.default_isolation,
            request_wire.workspace_root,
        ),
    };

    Ok(request.with_declared_mutation(request_wire.declared_mutation))
}

fn load_request(path: &Path) -> Result<ExecRequestWire, String> {
    let content = read_utf8_regular_file_nofollow(path, MAX_REQUEST_JSON_BYTES)
        .map_err(|e| format!("failed to read request {}: {e}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("invalid request json {}: {e}", path.display()))
}

fn read_utf8_regular_file_nofollow(path: &Path, max_bytes: usize) -> std::io::Result<String> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("path is not a regular file: {}", path.display()),
        ));
    }
    let file = open_regular_readonly_nofollow(path)?;
    let mut bytes = Vec::new();
    let limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut limited = file.take(limit);
    limited.read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "request file exceeds size limit ({} > {} bytes)",
                bytes.len(),
                max_bytes
            ),
        ));
    }
    str::from_utf8(&bytes)
        .map(str::to_owned)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err.to_string()))
}

#[cfg(unix)]
fn open_regular_readonly_nofollow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path)?;
    ensure_regular_file(path, file)
}

#[cfg(windows)]
fn open_regular_readonly_nofollow(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path)?;
    ensure_regular_file(path, file)
}

#[cfg(all(not(unix), not(windows)))]
fn open_regular_readonly_nofollow(path: &Path) -> std::io::Result<File> {
    let file = OpenOptions::new().read(true).open(path)?;
    ensure_regular_file(path, file)
}

fn ensure_regular_file(path: &Path, file: File) -> std::io::Result<File> {
    let metadata = file.metadata()?;
    if metadata.is_file() {
        return Ok(file);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("path is not a regular file: {}", path.display()),
    ))
}

fn exec_output_from_result(
    request_resolution: RequestResolution,
    event: ExecEvent,
    result: ExecResult<ExitStatus>,
) -> ExecOutput {
    match result {
        Ok(status) => ExecOutput {
            request_resolution,
            event,
            exit_code: status.code(),
            signal: exit_status_signal(&status),
            error: exit_status_signal(&status)
                .map(|signal| format!("process terminated by signal {signal}")),
        },
        Err(err) => ExecOutput {
            request_resolution,
            event,
            exit_code: None,
            signal: None,
            error: Some(err.to_string()),
        },
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
    use super::*;
    use omne_execution_gateway::{ExecDecision, RequestedIsolationSource, requested_policy_meta};
    use policy_meta::SpecVersion;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;
    use tempfile::tempdir;

    fn sample_workspace() -> std::path::PathBuf {
        std::env::current_dir().expect("current_dir")
    }

    fn sample_event() -> omne_execution_gateway::ExecEvent {
        let workspace = sample_workspace();
        omne_execution_gateway::ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: ExecutionIsolation::BestEffort,
            requested_policy_meta: requested_policy_meta(ExecutionIsolation::BestEffort),
            supported_isolation: ExecutionIsolation::BestEffort,
            program: "echo".into(),
            args: vec!["hello".into()],
            cwd: workspace.clone(),
            workspace_root: workspace,
            declared_mutation: false,
            reason: None,
            sandbox_runtime: None,
        }
    }

    fn sample_request_resolution() -> RequestResolution {
        let workspace = sample_workspace();
        let request = ExecRequest::new(
            "echo",
            vec!["hello"],
            &workspace,
            ExecutionIsolation::BestEffort,
            &workspace,
        )
        .with_declared_mutation(false);
        ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort)
            .resolve_request(&request)
    }

    #[cfg(unix)]
    fn sample_policy_default_request_resolution() -> RequestResolution {
        let workspace = sample_workspace();
        let request = ExecRequest::with_policy_default_isolation(
            "echo",
            vec!["hello"],
            &workspace,
            ExecutionIsolation::BestEffort,
            &workspace,
        )
        .with_declared_mutation(false);
        ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort)
            .resolve_request(&request)
    }

    #[test]
    fn exec_output_keeps_nonzero_exit_code() {
        let status = nonzero_exit_status();
        let request_resolution = sample_request_resolution();
        let mut event = sample_event();
        event.program = request_resolution.program.clone();
        let output = exec_output_from_result(request_resolution, event, Ok(status));
        assert_eq!(output.event.program, output.request_resolution.program);
        assert_eq!(output.request_resolution.args, vec!["hello"]);
        assert_eq!(output.exit_code, Some(1));
        assert_eq!(
            output.request_resolution.requested_isolation_source,
            RequestedIsolationSource::Request
        );
        assert_eq!(
            output.request_resolution.policy_default_isolation,
            ExecutionIsolation::BestEffort
        );
        assert_eq!(
            output.request_resolution.requested_policy_meta.version,
            Some(SpecVersion::V1)
        );
        assert_eq!(
            output
                .request_resolution
                .requested_policy_meta
                .execution_isolation,
            Some(ExecutionIsolation::BestEffort)
        );
        assert_eq!(output.signal, None);
        assert_eq!(output.error, None);
        let value = serde_json::to_value(&output).expect("serialize output");
        assert_eq!(
            value["request_resolution"],
            serde_json::json!({
                "program": output.request_resolution.program.to_string_lossy(),
                "args": ["hello"],
                "program_exact": {
                    "encoding": "utf8",
                    "value": output.request_resolution.program.to_string_lossy()
                },
                "args_exact": [{
                    "encoding": "utf8",
                    "value": "hello"
                }],
                "cwd": output.request_resolution.cwd,
                "workspace_root": output.request_resolution.workspace_root,
                "declared_mutation": false,
                "input_required_isolation": "best_effort",
                "requested_isolation": "best_effort",
                "requested_isolation_source": "request",
                "requested_policy_meta": {
                    "version": 1,
                    "execution_isolation": "best_effort"
                },
                "policy_default_isolation": "best_effort"
            })
        );
        assert_eq!(
            value["event"],
            serde_json::json!({
                "decision": "run",
                "requested_isolation": "best_effort",
                "requested_policy_meta": {
                    "version": 1,
                    "execution_isolation": "best_effort"
                },
                "supported_isolation": "best_effort",
                "program": output.event.program.to_string_lossy(),
                "args": ["hello"],
                "program_exact": {
                    "encoding": "utf8",
                    "value": output.event.program.to_string_lossy()
                },
                "args_exact": [{
                    "encoding": "utf8",
                    "value": "hello"
                }],
                "cwd": output.event.cwd,
                "workspace_root": output.event.workspace_root,
                "declared_mutation": false,
                "reason": null
            })
        );
    }

    #[cfg(unix)]
    #[test]
    fn exec_output_reports_signal_termination() {
        let status = signal_terminated_status();
        let request_resolution = sample_policy_default_request_resolution();
        let mut event = sample_event();
        event.program = request_resolution.program.clone();
        let output = exec_output_from_result(request_resolution, event, Ok(status));
        assert_eq!(output.exit_code, None);
        assert_eq!(output.signal, Some(15));
        assert_eq!(
            output.request_resolution.requested_isolation_source,
            RequestedIsolationSource::PolicyDefault
        );
        assert_eq!(
            output.error.as_deref(),
            Some("process terminated by signal 15")
        );
    }

    #[test]
    fn shared_request_resolution_tracks_raw_and_effective_isolation() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let workspace = sample_workspace();
        let request = ExecRequest::with_policy_default_isolation(
            "whoami",
            Vec::<String>::new(),
            &workspace,
            ExecutionIsolation::BestEffort,
            &workspace,
        )
        .with_declared_mutation(false);

        let resolution = gateway.resolve_request(&request);

        assert!(std::path::Path::new(&resolution.program).is_absolute());
        assert!(resolution.args.is_empty());
        assert_eq!(resolution.input_required_isolation, None);
        assert_eq!(
            resolution.requested_isolation,
            ExecutionIsolation::BestEffort
        );
        assert_eq!(
            resolution.requested_isolation_source,
            RequestedIsolationSource::PolicyDefault
        );
        assert_eq!(
            resolution.requested_policy_meta,
            omne_execution_gateway::requested_policy_meta(ExecutionIsolation::BestEffort)
        );
        assert!(!resolution.declared_mutation);
        let canonical_workspace = workspace
            .canonicalize()
            .expect("canonicalize sample workspace");
        assert_eq!(resolution.cwd, canonical_workspace);
        assert_eq!(resolution.workspace_root, canonical_workspace);
    }

    #[test]
    fn build_exec_request_requires_declared_mutation_field() {
        let err = serde_json::from_str::<ExecRequestWire>(
            r#"{
                "program": "echo",
                "args": ["hello"],
                "cwd": ".",
                "workspace_root": ".",
                "required_isolation": "best_effort"
            }"#,
        )
        .expect_err("missing declared_mutation should fail closed");

        assert!(err.to_string().contains("declared_mutation"));
    }

    #[test]
    fn build_exec_request_keeps_explicit_declared_mutation_value() {
        let policy = GatewayPolicy::default();
        let request = build_exec_request(
            &policy,
            ExecRequestWire {
                program: "echo".to_string(),
                args: vec!["hello".to_string()],
                cwd: ".".into(),
                workspace_root: ".".into(),
                required_isolation: None,
                declared_mutation: true,
            },
        )
        .expect("build request");

        assert!(request.declared_mutation);
        assert_eq!(
            request.requested_isolation_source,
            RequestedIsolationSource::PolicyDefault
        );
    }

    #[test]
    fn exec_request_wire_rejects_unknown_fields() {
        let err = serde_json::from_str::<ExecRequestWire>(
            r#"{
                "program": "echo",
                "args": ["hello"],
                "cwd": ".",
                "workspace_root": ".",
                "required_isolation": "best_effort",
                "declared_mutation": false,
                "required_isolation_typo": "none"
            }"#,
        )
        .expect_err("unknown fields should be rejected");

        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn load_request_rejects_unknown_fields() {
        let wire = serde_json::from_str::<ExecRequestWire>(
            r#"{
                "program": "echo",
                "args": ["hello"],
                "cwd": ".",
                "workspace_root": ".",
                "required_isolation": "best_effort",
                "declared_mutation": false,
                "unexpected": true
            }"#,
        )
        .expect_err("unknown request fields should fail closed");

        assert!(wire.to_string().contains("unknown field"));
    }

    #[test]
    fn load_request_rejects_oversized_input() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("request.json");
        let oversized_len = u64::try_from(MAX_REQUEST_JSON_BYTES)
            .expect("request size bound fits u64")
            .saturating_add(1);
        let file = File::create(&path).expect("create oversized request placeholder");
        file.set_len(oversized_len)
            .expect("extend oversized request placeholder");

        let err = load_request(&path).expect_err("oversized request should fail closed");
        assert!(
            err.contains("exceeds size limit"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_request_rejects_symlink_input() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("request-real.json");
        fs::write(
            &target,
            r#"{"program":"echo","args":[],"cwd":".","workspace_root":".","declared_mutation":false}"#,
        )
        .expect("write request");
        let link = dir.path().join("request-link.json");
        symlink(&target, &link).expect("create request symlink");

        let err = load_request(&link).expect_err("symlink request should fail closed");
        assert!(
            err.contains("path is not a regular file"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_request_rejects_special_file_input() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("request.sock");
        let _listener = UnixListener::bind(&path).expect("bind socket");

        let err = load_request(&path).expect_err("special-file request should fail closed");
        assert!(
            err.contains("path is not a regular file"),
            "unexpected error: {err}"
        );
    }

    #[cfg(windows)]
    fn nonzero_exit_status() -> ExitStatus {
        std::process::Command::new("cmd")
            .args(["/C", "exit 1"])
            .status()
            .expect("run cmd /C exit 1")
    }

    #[cfg(not(windows))]
    fn nonzero_exit_status() -> ExitStatus {
        std::process::Command::new("sh")
            .args(["-c", "exit 1"])
            .status()
            .expect("run sh -c exit 1")
    }

    #[cfg(unix)]
    fn signal_terminated_status() -> ExitStatus {
        std::process::Command::new("sh")
            .args(["-c", "kill -TERM $$"])
            .status()
            .expect("run sh -c kill -TERM $$")
    }
}
