#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::{ExitCode, ExitStatus};

use omne_execution_gateway::{
    ExecEvent, ExecGateway, ExecRequest, ExecResult, GatewayPolicy, RequestResolution,
};
use policy_meta::ExecutionIsolation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct ExecRequestWire {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    cwd: PathBuf,
    workspace_root: PathBuf,
    #[serde(default)]
    required_isolation: Option<ExecutionIsolation>,
    #[serde(default)]
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
    }
    .with_declared_mutation(request_wire.declared_mutation);
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

fn load_request(path: &PathBuf) -> Result<ExecRequestWire, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("failed to read request {}: {e}", path.display()))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("invalid request json {}: {e}", path.display()))
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
    use omne_execution_gateway::ExecDecision;
    use omne_execution_gateway::{RequestedIsolationSource, requested_policy_meta};
    use policy_meta::SpecVersion;

    fn sample_event() -> omne_execution_gateway::ExecEvent {
        omne_execution_gateway::ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: ExecutionIsolation::BestEffort,
            requested_policy_meta: requested_policy_meta(ExecutionIsolation::BestEffort),
            supported_isolation: ExecutionIsolation::BestEffort,
            program: "echo".into(),
            cwd: ".".into(),
            workspace_root: ".".into(),
            declared_mutation: false,
            reason: None,
            sandbox_runtime: None,
        }
    }

    fn sample_request_resolution() -> RequestResolution {
        let request = ExecRequest::new(
            "echo",
            vec!["hello"],
            ".",
            ExecutionIsolation::BestEffort,
            ".",
        );
        ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort)
            .resolve_request(&request)
    }

    fn sample_policy_default_request_resolution() -> RequestResolution {
        let request = ExecRequest::with_policy_default_isolation(
            "echo",
            vec!["hello"],
            ".",
            ExecutionIsolation::BestEffort,
            ".",
        );
        ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort)
            .resolve_request(&request)
    }

    #[test]
    fn exec_output_keeps_nonzero_exit_code() {
        let status = nonzero_exit_status();
        let output =
            exec_output_from_result(sample_request_resolution(), sample_event(), Ok(status));
        assert_eq!(output.event.program.to_string_lossy(), "echo");
        assert_eq!(output.request_resolution.program, "echo");
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
                "program": "echo",
                "args": ["hello"],
                "cwd": ".",
                "workspace_root": ".",
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
                "program": "echo",
                "cwd": ".",
                "workspace_root": ".",
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
        let output = exec_output_from_result(request_resolution, sample_event(), Ok(status));
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
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let request = ExecRequest::with_policy_default_isolation(
            "sh",
            vec!["-lc", "echo hi"],
            ".",
            ExecutionIsolation::BestEffort,
            ".",
        )
        .with_declared_mutation(true);

        let resolution = gateway.resolve_request(&request);

        assert_eq!(resolution.program.to_string_lossy(), "sh");
        assert_eq!(
            resolution.args,
            vec![
                std::ffi::OsString::from("-lc"),
                std::ffi::OsString::from("echo hi")
            ]
        );
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
        assert!(resolution.declared_mutation);
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
