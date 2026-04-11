use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::sync::OnceLock;

use crate::audit::{ExecDecision, ExecEvent, SandboxRuntimeObservation, requested_policy_meta};
use crate::audit_log::{AuditLogger, PreparedAuditSink};
use crate::error::{ExecError, ExecResult};
use crate::policy::GatewayPolicy;
use crate::sandbox;
use crate::types::{ExecRequest, RequestResolution, RequestedIsolationSource};
use policy_meta::ExecutionIsolation;
use same_file::Handle as SameFileHandle;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug)]
struct BoundDirectory {
    path: PathBuf,
    identity: SameFileHandle,
}

#[derive(Debug)]
struct ResolvedRequestPaths {
    workspace_root: BoundDirectory,
    cwd: BoundDirectory,
}

#[derive(Debug)]
struct PreparedExecRequest {
    event: ExecEvent,
    required_isolation: ExecutionIsolation,
    bound_program: BoundProgram,
    resolved_paths: ResolvedRequestPaths,
}

#[derive(Debug)]
struct BoundProgram {
    path: PathBuf,
    identity: SameFileHandle,
    content_fingerprint: [u8; 32],
}

#[derive(Debug)]
pub struct PreflightError {
    event: Box<ExecEvent>,
    error: ExecError,
}

impl PreflightError {
    pub fn into_parts(self) -> (ExecEvent, ExecError) {
        (*self.event, self.error)
    }
}

#[derive(Debug)]
pub struct ExecGateway {
    supported_isolation: ExecutionIsolation,
    policy: GatewayPolicy,
    audit: Option<AuditLogger>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CapabilityReport {
    pub supported_isolation: ExecutionIsolation,
    pub policy_default_isolation: ExecutionIsolation,
}

#[derive(Debug)]
#[must_use = "execution outcomes carry policy, audit, and sandbox metadata"]
pub struct ExecutionOutcome {
    pub event: ExecEvent,
    pub result: ExecResult<ExitStatus>,
}

#[derive(Debug)]
#[must_use = "prepared spawn outcomes carry child ownership and sandbox metadata"]
pub struct PreparedChild {
    child: std::process::Child,
    sandbox_runtime: Option<SandboxRuntimeObservation>,
    event: ExecEvent,
    audit_sink: Option<PreparedAuditSink>,
}

#[derive(Debug)]
#[must_use = "prepared commands must be spawned to apply validated cwd and sandbox state"]
pub struct PreparedCommand {
    args: Vec<OsString>,
    prepared: PreparedExecRequest,
    audit_sink: Option<PreparedAuditSink>,
}

impl ExecutionOutcome {
    pub fn into_parts(self) -> (ExecEvent, ExecResult<ExitStatus>) {
        (self.event, self.result)
    }
}

impl PreparedChild {
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn stdin(&mut self) -> Option<&mut ChildStdin> {
        self.child.stdin.as_mut()
    }

    pub fn stdout(&mut self) -> Option<&mut ChildStdout> {
        self.child.stdout.as_mut()
    }

    pub fn stderr(&mut self) -> Option<&mut ChildStderr> {
        self.child.stderr.as_mut()
    }

    pub fn sandbox_runtime(&self) -> Option<&SandboxRuntimeObservation> {
        self.sandbox_runtime.as_ref()
    }

    pub fn try_wait(&mut self) -> ExecResult<Option<ExitStatus>> {
        let status = self.child.try_wait().map_err(ExecError::Spawn)?;
        match status {
            Some(status) => self.finalize_result(Ok(status)).map(Some),
            None => Ok(None),
        }
    }

    pub fn wait(mut self) -> ExecutionOutcome {
        let event = self.event_with_runtime();
        let result = self
            .child
            .wait()
            .map_err(ExecError::Spawn)
            .and_then(|status| self.finalize_result(Ok(status)));
        ExecutionOutcome { event, result }
    }

    pub fn kill(&mut self) -> ExecResult<()> {
        self.child.kill().map_err(ExecError::Spawn)
    }

    fn event_with_runtime(&self) -> ExecEvent {
        let mut event = self.event.clone();
        event.sandbox_runtime = self.sandbox_runtime.clone();
        event
    }

    fn finalize_result(&mut self, result: ExecResult<ExitStatus>) -> ExecResult<ExitStatus> {
        let audit_result = if let Some(mut audit_sink) = self.audit_sink.take() {
            audit_sink.write_execution_record(&self.event_with_runtime(), &result)
        } else {
            Ok(())
        };
        combine_exit_status_with_audit_write(result, audit_result)
    }

    fn finalize_on_drop(&mut self) {
        let Some(mut audit_sink) = self.audit_sink.take() else {
            return;
        };
        let event = self.event_with_runtime();
        let _ = match self.child.try_wait() {
            Ok(Some(status)) => audit_sink.write_execution_record(&event, &Ok(status)),
            Ok(None) => audit_sink
                .write_detached_record(&event, "prepared child dropped without wait/try_wait"),
            Err(err) => audit_sink.write_execution_error_record(&event, &ExecError::Spawn(err)),
        };
    }
}

impl Drop for PreparedChild {
    fn drop(&mut self) {
        self.finalize_on_drop();
    }
}

impl PreparedCommand {
    pub fn current_dir(&self) -> Option<&Path> {
        Some(self.prepared.resolved_paths.cwd.path.as_path())
    }

    pub fn spawn(mut self) -> ExecResult<PreparedChild> {
        let event = self.prepared.event.clone();
        let result = revalidate_prepared_request(&self.prepared)
            .and_then(|_| {
                let mut command = build_prepared_spawn_command(&self.prepared, &self.args);
                configure_noninteractive_stdio(&mut command);
                apply_prepared_request(&self.prepared, &mut command)
                    .and_then(|monitor| spawn_command_with_monitor(&mut command, monitor))
            })
            .map(|(child, sandbox_runtime)| PreparedChild {
                child,
                sandbox_runtime,
                event: event.clone(),
                audit_sink: self.audit_sink.take(),
            });
        let audit_event = match &result {
            Ok(_) => event.clone(),
            Err(err) => event_for_post_preflight_error(event.clone(), err),
        };
        let audit_result = match (&result, self.audit_sink.as_mut()) {
            (Err(err), Some(audit_sink)) => {
                audit_sink.write_execution_error_record(&audit_event, err)
            }
            _ => Ok(()),
        };
        combine_result_with_audit_write(result, audit_result)
    }
}

impl Default for ExecGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecGateway {
    /// Construct a gateway with host-compatible isolation defaults but fail-closed mutation policy.
    ///
    /// `GatewayPolicy::default_for_supported_isolation(...)` still enables mutation enforcement
    /// and starts with empty allowlists, so callers that expect commands to run must either supply
    /// explicit allowlists or build a custom policy that disables mutation enforcement.
    pub fn new() -> Self {
        let supported_isolation = sandbox::detect_supported_isolation();
        Self::with_policy_and_supported_isolation(
            GatewayPolicy::default_for_supported_isolation(supported_isolation),
            supported_isolation,
        )
    }

    pub fn with_policy(policy: GatewayPolicy) -> Self {
        Self::with_policy_and_supported_isolation(policy, sandbox::detect_supported_isolation())
    }

    pub fn with_policy_and_supported_isolation(
        policy: GatewayPolicy,
        supported_isolation: ExecutionIsolation,
    ) -> Self {
        let audit = policy.audit_log_path.as_ref().map(AuditLogger::new);
        Self {
            supported_isolation,
            policy,
            audit,
        }
    }

    /// Construct a gateway with the supplied host capability but the same fail-closed default
    /// policy shape as [`ExecGateway::new`].
    pub fn with_supported_isolation(supported_isolation: ExecutionIsolation) -> Self {
        Self::with_policy_and_supported_isolation(
            GatewayPolicy::default_for_supported_isolation(supported_isolation),
            supported_isolation,
        )
    }

    pub fn capability_report(&self) -> CapabilityReport {
        CapabilityReport {
            supported_isolation: self.supported_isolation,
            policy_default_isolation: self.policy.default_isolation,
        }
    }

    /// Project a request into the gateway's canonical pre-execution view.
    pub fn resolve_request(&self, request: &ExecRequest) -> RequestResolution {
        match self.prepare_request(request) {
            Ok(prepared) => RequestResolution::from_event(
                request,
                &prepared.event,
                self.policy.default_isolation,
            ),
            Err(err) => RequestResolution::from_event(
                request,
                err.event.as_ref(),
                self.policy.default_isolation,
            ),
        }
    }

    pub fn evaluate(&self, request: &ExecRequest) -> ExecEvent {
        match self.prepare_request(request) {
            Ok(prepared) => prepared.event,
            Err(err) => *err.event,
        }
    }

    /// Execute a request and retain the authoritative policy/audit event.
    pub fn execute(&self, request: &ExecRequest) -> ExecutionOutcome {
        let (event, result, audit_sink) = match self.prepare_request(request) {
            Ok(prepared) => match self.prepare_audit_sink(&prepared.event) {
                Ok(mut audit_sink) => {
                    let result = revalidate_prepared_request(&prepared).and_then(|_| {
                        let mut command = build_prepared_spawn_command(&prepared, &request.args);
                        configure_noninteractive_stdio(&mut command);
                        apply_prepared_request(&prepared, &mut command).and_then(|monitor| {
                            let (mut child, sandbox_runtime) =
                                spawn_command_with_monitor(&mut command, monitor)?;
                            let status = child.wait().map_err(ExecError::Spawn)?;
                            Ok((sandbox_runtime, status))
                        })
                    });
                    match result {
                        Ok((sandbox_runtime, status)) => {
                            let mut event = prepared.event;
                            event.sandbox_runtime = sandbox_runtime;
                            (event, Ok(status), audit_sink.take())
                        }
                        Err(err) => (
                            event_for_post_preflight_error(prepared.event, &err),
                            Err(err),
                            audit_sink.take(),
                        ),
                    }
                }
                Err(err) => {
                    let (event, err) = err.into_parts();
                    (event, Err(err), None)
                }
            },
            Err(err) => {
                let (event, err) = err.into_parts();
                (event, Err(err), None)
            }
        };
        let result = if audit_error_already_reported(&result) {
            result
        } else if let Some(mut audit_sink) = audit_sink {
            let audit_result = audit_sink.write_execution_record(&event, &result);
            combine_exit_status_with_audit_write(result, audit_result)
        } else if let Some(audit) = &self.audit {
            let audit_result = audit.write_execution_record(&event, &result);
            combine_exit_status_with_audit_write(result, audit_result)
        } else {
            result
        };
        ExecutionOutcome { event, result }
    }

    /// Convenience helper for callers that intentionally discard policy/audit metadata.
    pub fn execute_status(&self, request: &ExecRequest) -> ExecResult<ExitStatus> {
        self.execute(request).result
    }

    /// Validate request identity and return a spawn-only prepared wrapper.
    pub fn prepare_command(
        &self,
        request: &ExecRequest,
    ) -> (ExecEvent, ExecResult<PreparedCommand>) {
        let (event, result, audit_sink) = match self.prepare_request(request) {
            Ok(prepared) => match self.prepare_audit_sink(&prepared.event) {
                Ok(mut audit_sink) => {
                    let event = prepared.event.clone();
                    (
                        event,
                        Ok(PreparedCommand {
                            args: request.args.clone(),
                            prepared,
                            audit_sink: None,
                        }),
                        audit_sink.take(),
                    )
                }
                Err(err) => {
                    let (event, err) = err.into_parts();
                    (event, Err(err), None)
                }
            },
            Err(err) => {
                let (event, err) = err.into_parts();
                (event, Err(err), None)
            }
        };
        let mut retained_audit_sink = None;
        let result = if audit_error_already_reported(&result) {
            result
        } else if let Some(mut audit_sink) = audit_sink {
            let audit_result = audit_sink.write_prepare_record(&event, &result);
            let result = combine_result_with_audit_write(result, audit_result);
            if result.is_ok() {
                retained_audit_sink = Some(audit_sink);
            }
            result
        } else if let Some(audit) = &self.audit {
            let audit_result = audit.write_prepare_record(&event, &result);
            combine_result_with_audit_write(result, audit_result)
        } else {
            result
        };
        (
            event,
            result.map(|mut prepared| {
                prepared.audit_sink = retained_audit_sink;
                prepared
            }),
        )
    }

    #[allow(clippy::result_large_err)]
    pub fn preflight(&self, request: &ExecRequest) -> Result<ExecEvent, PreflightError> {
        self.prepare_request(request).map(|prepared| prepared.event)
    }

    #[allow(clippy::result_large_err)]
    fn prepare_request(
        &self,
        request: &ExecRequest,
    ) -> Result<PreparedExecRequest, PreflightError> {
        let mut event = self.preflight_event(request);

        if matches!(
            request.requested_isolation_source(),
            RequestedIsolationSource::PolicyDefault
        ) && request.required_isolation() != self.policy.default_isolation
        {
            return Err(self.deny_preflight(
                event,
                "policy_default_isolation_mismatch",
                ExecError::PolicyDefaultIsolationMismatch {
                    requested: request.required_isolation(),
                    policy_default: self.policy.default_isolation,
                },
            ));
        }

        if matches!(request.required_isolation(), ExecutionIsolation::None)
            && !self.policy.allow_isolation_none
        {
            return Err(self.deny_preflight(
                event,
                "isolation_none_forbidden",
                ExecError::PolicyDenied("isolation none is forbidden by policy".to_string()),
            ));
        }

        if request.required_isolation() > self.supported_isolation {
            return Err(self.deny_preflight(
                event,
                "isolation_not_supported",
                ExecError::IsolationNotSupported {
                    requested: request.required_isolation(),
                    supported: self.supported_isolation,
                },
            ));
        }

        if let Some(audit_path) = self.policy.audit_log_path.as_ref()
            && !audit_path.is_absolute()
        {
            return Err(self.deny_preflight(
                event,
                "audit_log_path_invalid",
                ExecError::AuditLogPathInvalid {
                    path: audit_path.clone(),
                    detail: "audit_log_path must be absolute".to_string(),
                },
            ));
        }

        match resolve_request_paths(&request.cwd, &request.workspace_root) {
            Ok(resolved_paths) => match bind_program_path(&request.program) {
                Ok(bound_program) => {
                    event.cwd = resolved_paths.cwd.path.clone();
                    event.workspace_root = resolved_paths.workspace_root.path.clone();
                    event.program = bound_program.path.clone().into();

                    if self.policy.enforce_allowlisted_program_for_mutation {
                        if request_uses_opaque_command_launcher(
                            &request.program,
                            &request.args,
                            &bound_program,
                        ) {
                            return Err(self.deny_preflight(
                                event,
                                "opaque_command_forbidden",
                                ExecError::PolicyDenied(
                                    "opaque command launchers cannot be authorized by policy"
                                        .to_string(),
                                ),
                            ));
                        }
                        let request_program_is_explicit =
                            is_explicit_program_path(request.program.as_os_str());
                        if !request_program_is_explicit {
                            return Err(self.deny_preflight(
                                event,
                                "allowlisted_execution_requires_explicit_program_path",
                                ExecError::PolicyDenied(
                                    "mutation-controlled requests must use an explicit absolute program path"
                                        .to_string(),
                                ),
                            ));
                        }
                        if !request.declared_mutation_is_explicit() {
                            return Err(self.deny_preflight(
                                event,
                                "mutation_declaration_required",
                                ExecError::MutationDeclarationRequired,
                            ));
                        }
                        if let Some(name) = first_startup_sensitive_env_name(&request.env) {
                            return Err(self.deny_preflight(
                                event,
                                "startup_sensitive_env_forbidden",
                                ExecError::PolicyDenied(format!(
                                    "allowlisted execution forbids startup-sensitive environment variable `{name}`"
                                )),
                            ));
                        }
                        let mutating_allowlisted = request_program_is_explicit
                            && self
                                .policy
                                .is_mutating_program_allowlisted_path(&bound_program.path);
                        let non_mutating_allowlisted = request_program_is_explicit
                            && self
                                .policy
                                .is_non_mutating_program_allowlisted_path(&bound_program.path);

                        if request.declared_mutation() {
                            if !mutating_allowlisted {
                                return Err(self.deny_preflight(
                                    event,
                                    "mutation_requires_allowlisted_program",
                                    ExecError::PolicyDenied(
                                        "declared mutating command must use an allowlisted program"
                                            .to_string(),
                                    ),
                                ));
                            }
                        } else {
                            if mutating_allowlisted {
                                return Err(self.deny_preflight(
                                    event,
                                    "allowlisted_program_requires_declared_mutation",
                                    ExecError::PolicyDenied(
                                        "allowlisted mutating program must declare mutation"
                                            .to_string(),
                                    ),
                                ));
                            }
                            if !non_mutating_allowlisted {
                                return Err(self.deny_preflight(
                                    event,
                                    "non_mutating_requires_allowlisted_program",
                                    ExecError::PolicyDenied(
                                        "declared non-mutating command must use an allowlisted program"
                                            .to_string(),
                                    ),
                                ));
                            }
                        }
                    }

                    Ok(PreparedExecRequest {
                        event,
                        required_isolation: request.required_isolation(),
                        bound_program,
                        resolved_paths,
                    })
                }
                Err(err) => Err(classify_bind_program_preflight_error(self, event, err)),
            },
            Err(err) => Err(classify_request_path_preflight_error(self, event, err)),
        }
    }

    fn preflight_event(&self, request: &ExecRequest) -> ExecEvent {
        ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: request.required_isolation(),
            requested_policy_meta: requested_policy_meta(request.required_isolation()),
            supported_isolation: self.supported_isolation,
            program: request.program.clone(),
            args: request.args.clone(),
            env: request.env.clone(),
            cwd: request.cwd.clone(),
            workspace_root: request.workspace_root.clone(),
            declared_mutation: request.declared_mutation(),
            reason: None,
            sandbox_runtime: None,
        }
    }

    fn deny_event(&self, mut event: ExecEvent, reason: &str) -> ExecEvent {
        let _ = self;
        event.decision = ExecDecision::Deny;
        event.reason = Some(reason.to_string());
        event
    }

    fn deny_preflight(&self, event: ExecEvent, reason: &str, err: ExecError) -> PreflightError {
        PreflightError {
            event: Box::new(self.deny_event(event, reason)),
            error: err,
        }
    }

    #[allow(clippy::result_large_err)]
    fn prepare_audit_sink(
        &self,
        event: &ExecEvent,
    ) -> Result<Option<PreparedAuditSink>, PreflightError> {
        if let Some(audit) = &self.audit {
            return audit
                .prepare_sink()
                .map(Some)
                .map_err(|err| self.deny_preflight(event.clone(), "audit_log_unavailable", err));
        }

        Ok(None)
    }
}

fn classify_bind_program_preflight_error(
    gateway: &ExecGateway,
    event: ExecEvent,
    err: ExecError,
) -> PreflightError {
    match err {
        err @ ExecError::RelativeProgramPath { .. } => {
            gateway.deny_preflight(event, "relative_program_path_forbidden", err)
        }
        err @ ExecError::ProgramPathInvalid { .. }
        | err @ ExecError::ProgramLookupFailed { .. }
        | err @ ExecError::PathIdentityUnavailable { .. }
        | err @ ExecError::RequestPathChanged { .. }
        | err @ ExecError::WorkspaceRootInvalid { .. }
        | err @ ExecError::CwdInvalid { .. }
        | err @ ExecError::CwdOutsideWorkspace { .. }
        | err @ ExecError::MutationDeclarationRequired
        | err @ ExecError::PolicyDefaultIsolationMismatch { .. }
        | err @ ExecError::PolicyDenied(_)
        | err @ ExecError::IsolationNotSupported { .. }
        | err @ ExecError::AuditLogUnavailable { .. }
        | err @ ExecError::AuditLogPathInvalid { .. }
        | err @ ExecError::AuditLogWriteFailed { .. }
        | err @ ExecError::AuditLogWriteFailedAfterExecutionSuccess { .. }
        | err @ ExecError::AuditLogWriteFailedAfterExecutionError { .. }
        | err @ ExecError::Sandbox(_)
        | err @ ExecError::Spawn(_) => gateway.deny_preflight(event, "program_path_invalid", err),
    }
}

fn classify_request_path_preflight_error(
    gateway: &ExecGateway,
    event: ExecEvent,
    err: ExecError,
) -> PreflightError {
    match err {
        err @ ExecError::WorkspaceRootInvalid { .. } => {
            gateway.deny_preflight(event, "workspace_root_invalid", err)
        }
        err @ ExecError::CwdInvalid { .. } => gateway.deny_preflight(event, "cwd_invalid", err),
        err @ ExecError::CwdOutsideWorkspace { .. }
        | err @ ExecError::PathIdentityUnavailable { .. }
        | err @ ExecError::RequestPathChanged { .. }
        | err @ ExecError::RelativeProgramPath { .. }
        | err @ ExecError::ProgramPathInvalid { .. }
        | err @ ExecError::ProgramLookupFailed { .. }
        | err @ ExecError::MutationDeclarationRequired
        | err @ ExecError::PolicyDefaultIsolationMismatch { .. }
        | err @ ExecError::PolicyDenied(_)
        | err @ ExecError::IsolationNotSupported { .. }
        | err @ ExecError::AuditLogUnavailable { .. }
        | err @ ExecError::AuditLogPathInvalid { .. }
        | err @ ExecError::AuditLogWriteFailed { .. }
        | err @ ExecError::AuditLogWriteFailedAfterExecutionSuccess { .. }
        | err @ ExecError::AuditLogWriteFailedAfterExecutionError { .. }
        | err @ ExecError::Sandbox(_)
        | err @ ExecError::Spawn(_) => gateway.deny_preflight(event, "cwd_outside_workspace", err),
    }
}

fn uses_opaque_command_launcher(program: &OsStr) -> bool {
    program_basename_ascii(program)
        .is_some_and(|normalized| normalized_opaque_command_launcher_name(&normalized))
}

fn normalized_opaque_command_launcher_name(program: &str) -> bool {
    matches!(
        program,
        "env"
            | "sh"
            | "bash"
            | "dash"
            | "zsh"
            | "fish"
            | "ksh"
            | "csh"
            | "tcsh"
            | "cmd"
            | "powershell"
            | "pwsh"
            | "node"
            | "nodejs"
            | "deno"
            | "bun"
            | "ruby"
            | "perl"
            | "php"
            | "lua"
            | "npm"
            | "npx"
            | "pnpm"
            | "yarn"
    ) || matches_versioned_opaque_command_family(program, "python")
        || matches_versioned_opaque_command_family(program, "pythonw")
        || matches_versioned_opaque_command_family(program, "pip")
}

fn matches_versioned_opaque_command_family(program: &str, family: &str) -> bool {
    let Some(suffix) = program.strip_prefix(family) else {
        return false;
    };

    suffix.is_empty() || suffix.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
}

fn request_uses_opaque_command_launcher(
    program: &OsStr,
    args: &[OsString],
    bound_program: &BoundProgram,
) -> bool {
    if invocation_uses_opaque_command_launcher(program, args) {
        return true;
    }

    if !is_explicit_program_path(program) {
        return false;
    }

    invocation_uses_opaque_command_launcher(bound_program.path.as_os_str(), args)
        || bound_program_matches_trusted_opaque_launcher(bound_program)
}

fn invocation_uses_opaque_command_launcher(program: &OsStr, args: &[OsString]) -> bool {
    if uses_opaque_command_launcher(program) {
        return true;
    }

    wrapped_subcommand(program, args).is_some_and(|(subcommand, remaining_args)| {
        invocation_uses_opaque_command_launcher(subcommand, remaining_args)
    })
}

fn wrapped_subcommand<'a>(
    program: &OsStr,
    args: &'a [OsString],
) -> Option<(&'a OsStr, &'a [OsString])> {
    let normalized = program_basename_ascii(program)?;
    match normalized.as_str() {
        "timeout" => timeout_subcommand(args),
        "nice" => nice_subcommand(args),
        "nohup" => passthrough_wrapper_subcommand(args),
        "setsid" => setsid_subcommand(args),
        "stdbuf" => stdbuf_subcommand(args),
        _ => None,
    }
}

fn passthrough_wrapper_subcommand(args: &[OsString]) -> Option<(&OsStr, &[OsString])> {
    let (program, remaining) = args.split_first()?;
    if program == "--" {
        let (program, remaining) = remaining.split_first()?;
        return Some((program.as_os_str(), remaining));
    }
    Some((program.as_os_str(), remaining))
}

fn timeout_subcommand(args: &[OsString]) -> Option<(&OsStr, &[OsString])> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        let text = arg.to_str()?;
        if text == "--" {
            index += 1;
            break;
        }
        if !text.starts_with('-') || text == "-" {
            break;
        }
        if matches!(text, "-k" | "--kill-after" | "-s" | "--signal") {
            index += 2;
            continue;
        }
        if text.starts_with("--kill-after=") || text.starts_with("--signal=") {
            index += 1;
            continue;
        }
        index += 1;
    }

    // `timeout` requires a duration before the delegated command.
    let _duration = args.get(index)?;
    index += 1;
    let program = args.get(index)?;
    Some((program.as_os_str(), &args[index + 1..]))
}

fn nice_subcommand(args: &[OsString]) -> Option<(&OsStr, &[OsString])> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        let text = arg.to_str()?;
        if text == "--" {
            index += 1;
            break;
        }
        if !text.starts_with('-') || text == "-" {
            break;
        }
        if matches!(text, "-n" | "--adjustment") {
            index += 2;
            continue;
        }
        if text.starts_with("--adjustment=") {
            index += 1;
            continue;
        }
        index += 1;
    }
    let program = args.get(index)?;
    Some((program.as_os_str(), &args[index + 1..]))
}

fn setsid_subcommand(args: &[OsString]) -> Option<(&OsStr, &[OsString])> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        let text = arg.to_str()?;
        if text == "--" {
            index += 1;
            break;
        }
        if !text.starts_with('-') || text == "-" {
            break;
        }
        index += 1;
    }
    let program = args.get(index)?;
    Some((program.as_os_str(), &args[index + 1..]))
}

fn stdbuf_subcommand(args: &[OsString]) -> Option<(&OsStr, &[OsString])> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        let text = arg.to_str()?;
        if text == "--" {
            index += 1;
            break;
        }
        if !text.starts_with('-') || text == "-" {
            break;
        }
        if matches!(text, "-i" | "-o" | "-e") {
            index += 2;
            continue;
        }
        index += 1;
    }
    let program = args.get(index)?;
    Some((program.as_os_str(), &args[index + 1..]))
}

fn program_basename_ascii(program: &OsStr) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let basename = Path::new(program).file_name().unwrap_or(program).as_bytes();
        ascii_program_name_from_bytes(basename)
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        let basename = Path::new(program).file_name().unwrap_or(program);
        let mut ascii = String::new();
        for unit in basename.encode_wide() {
            let byte = u8::try_from(unit).ok()?;
            if !byte.is_ascii() {
                return None;
            }
            ascii.push(char::from(byte.to_ascii_lowercase()));
        }
        Some(strip_windows_exe_suffix_owned(ascii))
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        Path::new(program)
            .file_name()
            .unwrap_or(program)
            .to_str()
            .map(|value| strip_windows_exe_suffix_owned(value.to_ascii_lowercase()))
    }
}

#[cfg(unix)]
fn ascii_program_name_from_bytes(bytes: &[u8]) -> Option<String> {
    if !bytes.is_ascii() {
        return None;
    }
    let normalized = bytes
        .iter()
        .map(|byte| char::from(byte.to_ascii_lowercase()))
        .collect::<String>();
    Some(strip_windows_exe_suffix_owned(normalized))
}

fn strip_windows_exe_suffix_owned(value: String) -> String {
    [".exe", ".cmd", ".bat", ".com"]
        .iter()
        .find_map(|suffix| value.strip_suffix(suffix))
        .unwrap_or(&value)
        .to_string()
}

fn first_startup_sensitive_env_name(env: &[(OsString, OsString)]) -> Option<String> {
    env.iter().find_map(|(name, _)| {
        is_startup_sensitive_env_name(name).then(|| name.to_string_lossy().into_owned())
    })
}

fn is_startup_sensitive_env_name(name: &OsStr) -> bool {
    let Some(normalized) = normalized_env_name_ascii(name) else {
        return true;
    };

    matches!(
        normalized.as_str(),
        "PATH"
            | "ENV"
            | "BASH_ENV"
            | "CDPATH"
            | "GIT_EXEC_PATH"
            | "NODE_OPTIONS"
            | "NODE_PATH"
            | "PERL5LIB"
            | "PERLLIB"
            | "PERL5OPT"
            | "PYTHONHOME"
            | "PYTHONPATH"
            | "PYTHONSTARTUP"
            | "RUBYLIB"
            | "RUBYOPT"
    ) || normalized.starts_with("LD_")
        || normalized.starts_with("DYLD_")
}

#[cfg(unix)]
fn normalized_env_name_ascii(name: &OsStr) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = name.as_bytes();
    bytes.is_ascii().then(|| {
        bytes
            .iter()
            .map(|byte| char::from(byte.to_ascii_uppercase()))
            .collect()
    })
}

#[cfg(windows)]
fn normalized_env_name_ascii(name: &OsStr) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;

    let mut normalized = String::new();
    for unit in name.encode_wide() {
        let byte = u8::try_from(unit).ok()?;
        if !byte.is_ascii() {
            return None;
        }
        normalized.push(char::from(byte.to_ascii_uppercase()));
    }
    Some(normalized)
}

#[cfg(all(not(unix), not(windows)))]
fn normalized_env_name_ascii(name: &OsStr) -> Option<String> {
    let text = name.to_str()?;
    text.is_ascii().then(|| text.to_ascii_uppercase())
}

fn canonicalize_workspace_root(path: &Path) -> ExecResult<PathBuf> {
    canonicalize_directory_without_forbidden_ancestors(path).map_err(|_| {
        ExecError::WorkspaceRootInvalid {
            path: path.to_path_buf(),
        }
    })
}

fn resolve_request_paths(cwd: &Path, workspace_root: &Path) -> ExecResult<ResolvedRequestPaths> {
    let workspace_root = capture_bound_directory(
        canonicalize_workspace_root(workspace_root)?,
        "workspace_root",
    )?;
    let cwd_path = canonicalize_cwd_within_workspace(cwd, &workspace_root.path)?;
    let cwd = capture_bound_directory(cwd_path, "cwd")?;
    Ok(ResolvedRequestPaths {
        workspace_root,
        cwd,
    })
}

fn canonicalize_cwd_within_workspace(cwd: &Path, workspace_root: &Path) -> ExecResult<PathBuf> {
    let cwd = canonicalize_directory_without_forbidden_ancestors(cwd).map_err(|detail| {
        ExecError::CwdInvalid {
            cwd: cwd.to_path_buf(),
            detail,
        }
    })?;
    if !path_starts_with(&cwd, workspace_root) {
        return Err(ExecError::CwdOutsideWorkspace {
            cwd,
            workspace_root: workspace_root.to_path_buf(),
        });
    }

    Ok(cwd)
}

fn canonicalize_directory_without_forbidden_ancestors(path: &Path) -> Result<PathBuf, String> {
    let absolute = absolute_path_lexical(path)?;
    reject_forbidden_directory_ancestors(&absolute)?;
    let canonical = absolute.canonicalize().map_err(|err| err.to_string())?;
    let metadata = std::fs::metadata(&canonical).map_err(|err| err.to_string())?;
    if !metadata.is_dir() {
        return Err("path is not a directory".to_string());
    }
    Ok(canonical)
}

fn absolute_path_lexical(path: &Path) -> Result<PathBuf, String> {
    let mut absolute = if path.is_absolute() {
        PathBuf::new()
    } else {
        std::env::current_dir().map_err(|err| err.to_string())?
    };

    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => absolute.push(prefix.as_os_str()),
            std::path::Component::RootDir => absolute.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                absolute.pop();
            }
            std::path::Component::Normal(segment) => absolute.push(segment),
        }
    }

    Ok(absolute)
}

fn reject_forbidden_directory_ancestors(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            std::path::Component::RootDir => current.push(component.as_os_str()),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                current.pop();
            }
            std::path::Component::Normal(segment) => {
                current.push(segment);
                let metadata =
                    std::fs::symlink_metadata(&current).map_err(|err| err.to_string())?;
                if file_metadata_has_forbidden_link_ancestor(&metadata)
                    && !is_permitted_platform_root_alias(&current)
                {
                    return Err(format!(
                        "path must not traverse symlink or reparse-point ancestors: {}",
                        current.display()
                    ));
                }
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
fn file_metadata_has_forbidden_link_ancestor(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn file_metadata_has_forbidden_link_ancestor(metadata: &std::fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

#[cfg(target_os = "macos")]
fn is_permitted_platform_root_alias(path: &Path) -> bool {
    path.parent() == Some(Path::new("/"))
        && matches!(
            path.file_name(),
            Some(name) if name == OsStr::new("var") || name == OsStr::new("tmp")
        )
}

#[cfg(not(target_os = "macos"))]
fn is_permitted_platform_root_alias(_: &Path) -> bool {
    false
}

fn explicit_path_like_os(program: &OsStr) -> bool {
    let path = Path::new(program);
    path.is_absolute() || os_str_has_path_separator(program) || has_windows_drive_prefix(program)
}

#[cfg(unix)]
fn os_str_has_path_separator(value: &OsStr) -> bool {
    use std::os::unix::ffi::OsStrExt;

    value
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'/' | b'\\'))
}

#[cfg(windows)]
fn os_str_has_path_separator(value: &OsStr) -> bool {
    use std::os::windows::ffi::OsStrExt;

    value
        .encode_wide()
        .any(|unit| matches!(char::from_u32(u32::from(unit)), Some('/' | '\\')))
}

#[cfg(all(not(unix), not(windows)))]
fn os_str_has_path_separator(value: &OsStr) -> bool {
    value
        .to_str()
        .is_some_and(|text| text.chars().any(|ch| matches!(ch, '/' | '\\')))
}

fn has_windows_drive_prefix(value: &OsStr) -> bool {
    windows_drive_prefix_marker(value).is_some()
}

#[cfg(unix)]
fn windows_drive_prefix_marker(value: &OsStr) -> Option<u8> {
    use std::os::unix::ffi::OsStrExt;

    let bytes = value.as_bytes();
    let drive = *bytes.first()?;
    let colon = *bytes.get(1)?;
    let third = bytes.get(2).copied();
    if drive.is_ascii_alphabetic()
        && colon == b':'
        && third.is_none_or(|byte| !matches!(byte, b'/' | b'\\'))
    {
        Some(drive)
    } else {
        None
    }
}

#[cfg(windows)]
fn windows_drive_prefix_marker(value: &OsStr) -> Option<u16> {
    use std::os::windows::ffi::OsStrExt;

    let mut units = value.encode_wide();
    let drive = units.next()?;
    let colon = units.next()?;
    let third = units.next();
    let drive_char = char::from_u32(u32::from(drive))?;
    if drive_char.is_ascii_alphabetic()
        && colon == u16::from(b':')
        && third.is_none_or(|unit| !matches!(char::from_u32(u32::from(unit)), Some('/' | '\\')))
    {
        Some(drive)
    } else {
        None
    }
}

#[cfg(all(not(unix), not(windows)))]
fn windows_drive_prefix_marker(value: &OsStr) -> Option<char> {
    let text = value.to_string_lossy();
    let mut chars = text.chars();
    let drive = chars.next()?;
    let colon = chars.next()?;
    let third = chars.next();
    if drive.is_ascii_alphabetic()
        && colon == ':'
        && third.is_none_or(|ch| !matches!(ch, '/' | '\\'))
    {
        Some(drive)
    } else {
        None
    }
}

fn capture_bound_directory(path: PathBuf, kind: &'static str) -> ExecResult<BoundDirectory> {
    let identity =
        SameFileHandle::from_path(&path).map_err(|_| ExecError::PathIdentityUnavailable {
            kind,
            path: path.clone(),
        })?;
    Ok(BoundDirectory { path, identity })
}

fn bind_program_path(program: &OsStr) -> ExecResult<BoundProgram> {
    if is_explicit_program_path(program) {
        bind_explicit_program_path(program)
    } else {
        bind_bare_program_path(program)
    }
}

fn bind_explicit_program_path(program: &OsStr) -> ExecResult<BoundProgram> {
    let requested_path = Path::new(program);
    if !requested_path.is_absolute() {
        return Err(ExecError::RelativeProgramPath {
            program: program.to_string_lossy().into_owned(),
        });
    }

    bind_absolute_program_path(requested_path)
}

fn bind_bare_program_path(program: &OsStr) -> ExecResult<BoundProgram> {
    let resolved_path =
        resolve_bare_program_path(program).ok_or_else(|| ExecError::ProgramLookupFailed {
            program: program.to_string_lossy().into_owned(),
            detail: "program not found in PATH or standard locations".to_string(),
        })?;

    bind_absolute_program_path(&resolved_path)
}

fn bind_absolute_program_path(requested_path: &Path) -> ExecResult<BoundProgram> {
    let canonical_path =
        requested_path
            .canonicalize()
            .map_err(|err| ExecError::ProgramPathInvalid {
                path: requested_path.to_path_buf(),
                detail: err.to_string(),
            })?;
    let metadata =
        std::fs::metadata(&canonical_path).map_err(|err| ExecError::ProgramPathInvalid {
            path: requested_path.to_path_buf(),
            detail: err.to_string(),
        })?;
    if !metadata.is_file() {
        return Err(ExecError::ProgramPathInvalid {
            path: requested_path.to_path_buf(),
            detail: "program path must reference a regular file".to_string(),
        });
    }
    if !is_spawnable_program_path(&canonical_path) {
        return Err(ExecError::ProgramPathInvalid {
            path: requested_path.to_path_buf(),
            detail: "program path must reference a spawnable executable".to_string(),
        });
    }

    let identity = SameFileHandle::from_path(&canonical_path).map_err(|_| {
        ExecError::PathIdentityUnavailable {
            kind: "program",
            path: canonical_path.clone(),
        }
    })?;
    Ok(BoundProgram {
        path: canonical_path.clone(),
        identity,
        content_fingerprint: fingerprint_program_contents(&canonical_path)?,
    })
}

fn revalidate_prepared_request_paths(paths: &ResolvedRequestPaths) -> ExecResult<()> {
    revalidate_bound_directory(&paths.workspace_root, "workspace_root")?;
    revalidate_bound_directory(&paths.cwd, "cwd")?;
    if !path_starts_with(&paths.cwd.path, &paths.workspace_root.path) {
        return Err(ExecError::CwdOutsideWorkspace {
            cwd: paths.cwd.path.clone(),
            workspace_root: paths.workspace_root.path.clone(),
        });
    }
    Ok(())
}

fn revalidate_bound_program(program: &BoundProgram) -> ExecResult<()> {
    let metadata = std::fs::metadata(&program.path).map_err(|_| ExecError::RequestPathChanged {
        kind: "program",
        path: program.path.clone(),
        detail: "path is no longer accessible".to_string(),
    })?;
    if !metadata.is_file() {
        return Err(ExecError::RequestPathChanged {
            kind: "program",
            path: program.path.clone(),
            detail: "path is no longer a regular file".to_string(),
        });
    }
    if !is_spawnable_program_path(&program.path) {
        return Err(ExecError::RequestPathChanged {
            kind: "program",
            path: program.path.clone(),
            detail: "path is no longer executable".to_string(),
        });
    }

    let current_identity = SameFileHandle::from_path(&program.path).map_err(|_| {
        ExecError::PathIdentityUnavailable {
            kind: "program",
            path: program.path.clone(),
        }
    })?;
    if current_identity != program.identity {
        return Err(ExecError::RequestPathChanged {
            kind: "program",
            path: program.path.clone(),
            detail: "file identity changed".to_string(),
        });
    }
    let current_fingerprint = fingerprint_program_contents(&program.path)?;
    if current_fingerprint != program.content_fingerprint {
        return Err(ExecError::RequestPathChanged {
            kind: "program",
            path: program.path.clone(),
            detail: "file contents changed".to_string(),
        });
    }

    Ok(())
}

fn revalidate_bound_directory(bound: &BoundDirectory, kind: &'static str) -> ExecResult<()> {
    let current = bound
        .path
        .canonicalize()
        .map_err(|_| ExecError::RequestPathChanged {
            kind,
            path: bound.path.clone(),
            detail: "path is no longer accessible".to_string(),
        })?;
    if !path_equals(&current, &bound.path) {
        return Err(ExecError::RequestPathChanged {
            kind,
            path: bound.path.clone(),
            detail: format!("canonical path changed to {}", current.display()),
        });
    }
    let current_is_dir = std::fs::metadata(&current)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false);
    if !current_is_dir {
        return Err(ExecError::RequestPathChanged {
            kind,
            path: bound.path.clone(),
            detail: "path is no longer a directory".to_string(),
        });
    }
    let current_identity =
        SameFileHandle::from_path(&current).map_err(|_| ExecError::PathIdentityUnavailable {
            kind,
            path: bound.path.clone(),
        })?;
    if current_identity != bound.identity {
        return Err(ExecError::RequestPathChanged {
            kind,
            path: bound.path.clone(),
            detail: "directory identity changed".to_string(),
        });
    }
    Ok(())
}

fn revalidate_prepared_request(prepared: &PreparedExecRequest) -> ExecResult<()> {
    revalidate_bound_program(&prepared.bound_program)?;
    revalidate_prepared_request_paths(&prepared.resolved_paths)?;
    Ok(())
}

fn apply_prepared_request(
    prepared: &PreparedExecRequest,
    command: &mut Command,
) -> ExecResult<sandbox::SandboxMonitor> {
    configure_request_environment(&prepared.event.env, command);
    command.current_dir(&prepared.resolved_paths.cwd.path);
    sandbox::apply_sandbox(
        command,
        prepared.required_isolation,
        &prepared.resolved_paths.workspace_root.path,
    )
}

fn spawn_command_with_monitor(
    command: &mut Command,
    monitor: sandbox::SandboxMonitor,
) -> ExecResult<(std::process::Child, Option<SandboxRuntimeObservation>)> {
    let child = command.spawn().map_err(ExecError::Spawn)?;
    Ok((child, monitor.observe_after_spawn()))
}

fn build_prepared_spawn_command(prepared: &PreparedExecRequest, args: &[OsString]) -> Command {
    let mut command = Command::new(&prepared.bound_program.path);
    command.args(args);
    command
}

fn configure_noninteractive_stdio(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
}

fn configure_request_environment(env: &[(OsString, OsString)], command: &mut Command) {
    command.env_clear();
    for (name, value) in env {
        command.env(name, value);
    }
}

fn fingerprint_program_contents(path: &Path) -> ExecResult<[u8; 32]> {
    let mut file = std::fs::File::open(path).map_err(|err| ExecError::ProgramPathInvalid {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|err| ExecError::ProgramPathInvalid {
                path: path.to_path_buf(),
                detail: err.to_string(),
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn is_explicit_program_path(program: &OsStr) -> bool {
    explicit_path_like_os(program)
}

fn resolve_bare_program_path(program: &OsStr) -> Option<PathBuf> {
    resolve_bare_program_path_from_env(program)
        .or_else(|| resolve_bare_program_path_from_standard_locations(program))
}

fn resolve_bare_program_path_from_env(program: &OsStr) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        if let Some(path) = resolve_bare_program_in_dir(program, &dir) {
            return Some(path);
        }
    }
    None
}

fn resolve_bare_program_path_from_standard_locations(program: &OsStr) -> Option<PathBuf> {
    for dir in standard_program_search_dirs() {
        if let Some(path) = resolve_bare_program_in_dir(program, Path::new(dir)) {
            return Some(path);
        }
    }
    None
}

#[cfg(not(windows))]
fn standard_program_search_dirs() -> &'static [&'static str] {
    &[
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/opt/homebrew/bin",
        "/opt/local/bin",
    ]
}

#[cfg(windows)]
fn standard_program_search_dirs() -> &'static [&'static str] {
    &[]
}

fn resolve_bare_program_in_dir(program: &OsStr, dir: &Path) -> Option<PathBuf> {
    let candidate = dir.join(program);

    #[cfg(windows)]
    {
        let has_ext = Path::new(program).extension().is_some();
        if has_ext {
            return is_spawnable_program_path(&candidate).then_some(candidate);
        }

        let program_name = program.to_string_lossy();
        for ext in windows_path_extensions() {
            let ext_candidate = dir.join(format!("{program_name}{ext}"));
            if is_spawnable_program_path(&ext_candidate) {
                return Some(ext_candidate);
            }
        }

        is_spawnable_program_path(&candidate).then_some(candidate)
    }

    #[cfg(not(windows))]
    {
        is_spawnable_program_path(&candidate).then_some(candidate)
    }
}

fn is_spawnable_program_path(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let Ok(metadata) = std::fs::metadata(path) else {
            return false;
        };
        metadata.is_file() && (metadata.permissions().mode() & 0o111 != 0)
    }

    #[cfg(windows)]
    {
        path.is_file()
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        path.is_file()
    }
}

#[cfg(windows)]
fn windows_path_extensions() -> Vec<String> {
    std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string())
        .split(';')
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .collect()
}

#[cfg(windows)]
fn path_components(path: &Path) -> Vec<String> {
    path.components()
        .map(|component| {
            normalize_windows_component(component.as_os_str().to_string_lossy().as_ref())
        })
        .collect()
}

#[cfg(not(windows))]
fn path_components(path: &Path) -> Vec<OsString> {
    path.components()
        .map(|component| component.as_os_str().to_os_string())
        .collect()
}

#[cfg(windows)]
fn normalize_windows_component(component: &str) -> String {
    let component = component.replace('/', "\\");
    if let Some(rest) = component.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{}", rest).to_ascii_lowercase()
    } else if let Some(rest) = component.strip_prefix("\\\\?\\") {
        rest.to_ascii_lowercase()
    } else {
        component.to_ascii_lowercase()
    }
}

fn path_equals(lhs: &Path, rhs: &Path) -> bool {
    path_components(lhs) == path_components(rhs)
}

fn path_starts_with(path: &Path, prefix: &Path) -> bool {
    let path = path_components(path);
    let prefix = path_components(prefix);
    path.starts_with(&prefix)
}

fn explicit_program_paths_match(actual: &Path, requested: &Path) -> bool {
    same_file::is_same_file(actual, requested).unwrap_or(false) || path_equals(actual, requested)
}

fn bound_program_matches_trusted_opaque_launcher(program: &BoundProgram) -> bool {
    trusted_opaque_launcher_paths().iter().any(|trusted_path| {
        explicit_program_paths_match(&program.path, trusted_path)
            || trusted_opaque_launcher_fingerprint_matches(program, trusted_path)
    })
}

fn trusted_opaque_launcher_fingerprint_matches(
    program: &BoundProgram,
    trusted_path: &Path,
) -> bool {
    fingerprint_program_contents(trusted_path)
        .map(|trusted_fingerprint| trusted_fingerprint == program.content_fingerprint)
        .unwrap_or(false)
}

fn trusted_opaque_launcher_paths() -> &'static [PathBuf] {
    static TRUSTED_OPAQUE_LAUNCHER_PATHS: OnceLock<Vec<PathBuf>> = OnceLock::new();

    TRUSTED_OPAQUE_LAUNCHER_PATHS
        .get_or_init(discover_trusted_opaque_launcher_paths)
        .as_slice()
}

fn discover_trusted_opaque_launcher_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();

    for dir in standard_program_search_dirs() {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            if !uses_opaque_command_launcher(file_name.as_os_str()) {
                continue;
            }

            let path = entry.path();
            if !is_spawnable_program_path(&path) {
                continue;
            }
            if paths
                .iter()
                .any(|known| explicit_program_paths_match(known, &path))
            {
                continue;
            }
            paths.push(path);
        }
    }

    paths
}

fn combine_result_with_audit_write<T>(
    result: ExecResult<T>,
    audit_result: ExecResult<()>,
) -> ExecResult<T> {
    match (result, audit_result) {
        (Ok(_), Err(err)) => Err(err),
        (Err(result_err), Err(ExecError::AuditLogWriteFailed { path, detail })) => {
            Err(ExecError::AuditLogWriteFailedAfterExecutionError {
                path,
                detail,
                execution_error: result_err.to_string(),
            })
        }
        (Err(_), Err(err)) => Err(err),
        (result, _) => result,
    }
}

fn combine_exit_status_with_audit_write(
    result: ExecResult<ExitStatus>,
    audit_result: ExecResult<()>,
) -> ExecResult<ExitStatus> {
    match (result, audit_result) {
        (Ok(status), Err(ExecError::AuditLogWriteFailed { path, detail })) => {
            Err(ExecError::AuditLogWriteFailedAfterExecutionSuccess {
                path,
                detail,
                status,
            })
        }
        (result, audit_result) => combine_result_with_audit_write(result, audit_result),
    }
}

fn audit_error_already_reported<T>(result: &ExecResult<T>) -> bool {
    matches!(
        result,
        Err(ExecError::AuditLogUnavailable { .. }
            | ExecError::AuditLogWriteFailed { .. }
            | ExecError::AuditLogWriteFailedAfterExecutionSuccess { .. }
            | ExecError::AuditLogWriteFailedAfterExecutionError { .. })
    )
}

fn event_for_post_preflight_error(mut event: ExecEvent, err: &ExecError) -> ExecEvent {
    let Some(reason) = post_preflight_denial_reason(err) else {
        return event;
    };
    event.decision = ExecDecision::Deny;
    event.reason = Some(reason.to_string());
    event
}

fn post_preflight_denial_reason(err: &ExecError) -> Option<&'static str> {
    match err {
        ExecError::PathIdentityUnavailable {
            kind: "program", ..
        }
        | ExecError::RequestPathChanged {
            kind: "program", ..
        } => Some("program_path_invalid"),
        ExecError::CwdOutsideWorkspace { .. }
        | ExecError::PathIdentityUnavailable {
            kind: "cwd" | "workspace_root",
            ..
        }
        | ExecError::RequestPathChanged {
            kind: "cwd" | "workspace_root",
            ..
        } => Some("cwd_outside_workspace"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::process::ExitStatus;
    #[cfg(unix)]
    use std::process::Stdio;
    #[cfg(unix)]
    use std::time::{Duration, Instant};

    use tempfile::tempdir;

    use super::*;
    use crate::policy::GatewayPolicy;

    fn canonical_test_root(dir: &tempfile::TempDir) -> PathBuf {
        dir.path()
            .canonicalize()
            .unwrap_or_else(|_| dir.path().to_path_buf())
    }

    #[cfg(unix)]
    fn exit_status_from_code(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;

        ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn exit_status_from_code(code: u32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;

        ExitStatus::from_raw(code)
    }

    #[cfg(unix)]
    #[test]
    fn opaque_launcher_detection_rejects_non_utf8_basename() {
        let program = OsString::from_vec(vec![0x70, 0x79, 0x74, 0x68, 0x6f, 0x6e, 0x80]);
        assert!(!uses_opaque_command_launcher(program.as_os_str()));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_path_detection_keeps_non_utf8_separator_checks_native() {
        let program = OsString::from_vec(vec![0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x66, 0x6f, 0x80]);
        assert!(is_explicit_program_path(program.as_os_str()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn evaluate_does_not_allowlist_mutating_non_utf8_program_via_lossy_collision() {
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace
            .path()
            .join(OsString::from_vec(vec![0x66, 0x6f, 0x80]));
        write_test_executable_placeholder(&program);
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec![program.to_string_lossy().into_owned()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(true);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("mutation_requires_allowlisted_program")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn evaluate_does_not_allowlist_non_mutating_non_utf8_program_via_lossy_collision() {
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace
            .path()
            .join(OsString::from_vec(vec![0x66, 0x6f, 0x80]));
        write_test_executable_placeholder(&program);
        let policy = GatewayPolicy {
            non_mutating_program_allowlist: vec![program.to_string_lossy().into_owned()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("non_mutating_requires_allowlisted_program")
        );
    }

    #[test]
    fn fail_closed_when_required_isolation_exceeds_supported() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");

        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::Strict,
            workspace.path(),
        );

        let err = gateway
            .execute_status(&request)
            .expect_err("strict request should fail closed");

        match err {
            ExecError::IsolationNotSupported {
                requested,
                supported,
            } => {
                assert_eq!(requested, ExecutionIsolation::Strict);
                assert_eq!(supported, ExecutionIsolation::BestEffort);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn rejects_cwd_outside_workspace() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let outside = tempdir().expect("create outside cwd");

        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            outside.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let err = gateway
            .execute_status(&request)
            .expect_err("outside cwd should be blocked");

        match err {
            ExecError::CwdOutsideWorkspace { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn rejects_missing_cwd_as_cwd_invalid() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let missing = workspace.path().join("missing");

        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            &missing,
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let err = gateway
            .execute_status(&request)
            .expect_err("missing cwd should be rejected as invalid");

        match err {
            ExecError::CwdInvalid { cwd, .. } => assert_eq!(cwd, missing),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn rejects_relative_program_paths() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "./tool",
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        );

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("relative_program_path_forbidden")
        );
        assert!(matches!(result, Err(ExecError::RelativeProgramPath { .. })));
    }

    #[test]
    fn rejects_relative_program_paths_before_mutation_policy_checks() {
        let gateway = ExecGateway::with_supported_isolation(host_supported_test_isolation());
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "./tool",
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(false);

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("relative_program_path_forbidden")
        );
        assert!(matches!(result, Err(ExecError::RelativeProgramPath { .. })));
    }

    #[test]
    fn rejects_drive_relative_program_paths() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "C:tool.exe",
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        );

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("relative_program_path_forbidden")
        );
        assert!(matches!(result, Err(ExecError::RelativeProgramPath { .. })));
    }

    #[test]
    fn rejects_drive_relative_program_paths_before_mutation_policy_checks() {
        let gateway = ExecGateway::with_supported_isolation(host_supported_test_isolation());
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "C:tool.exe",
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(false);

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("relative_program_path_forbidden")
        );
        assert!(matches!(result, Err(ExecError::RelativeProgramPath { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn resolves_symlink_program_paths_to_real_execution_path_in_events() {
        use std::os::unix::fs::symlink;

        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let target = workspace.path().join("tool");
        let symlink_path = workspace.path().join("tool-link");
        write_unix_shell_executable(&target, "exit 0\n");
        symlink(&target, &symlink_path).expect("create symlink");

        let request = ExecRequest::new(
            &symlink_path,
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        );

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);
        assert_eq!(
            event.program,
            target.canonicalize().expect("canonicalize target")
        );
    }

    #[test]
    fn supports_none_even_when_host_is_none() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway =
            ExecGateway::with_policy_and_supported_isolation(policy, ExecutionIsolation::None);
        let workspace = tempdir().expect("create temp workspace");

        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        );

        let err = gateway.execute_status(&request);
        assert!(err.is_ok() || matches!(err, Err(ExecError::Spawn(_))));
    }

    #[cfg(unix)]
    #[test]
    fn allows_symlink_program_paths_when_target_is_stable() {
        use std::os::unix::fs::symlink;

        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let link = workspace.path().join("program-link");
        symlink(dummy_program_absolute_path(), &link).expect("create program symlink");

        let request = ExecRequest::new(
            &link,
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        );

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);
    }

    #[test]
    fn evaluate_denies_with_reason_for_unsupported_isolation() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            dummy_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::Strict,
            workspace.path(),
        );

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("isolation_not_supported"));
        assert_eq!(
            event.requested_policy_meta,
            crate::audit::requested_policy_meta(ExecutionIsolation::Strict)
        );
    }

    #[test]
    fn pure_request_projections_ignore_unavailable_audit_parent() {
        let workspace = tempdir().expect("create temp workspace");
        let parent_file = workspace.path().join("not-a-dir");
        fs::write(&parent_file, "blocker").expect("write parent file");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                audit_log_path: Some(parent_file.join("audit.jsonl")),
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let resolution = gateway.resolve_request(&request);
        assert!(Path::new(&resolution.program).is_absolute());

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);

        let event = gateway
            .preflight(&request)
            .expect("preflight should stay pure");
        assert_eq!(event.decision, ExecDecision::Run);
    }

    #[test]
    fn execute_denies_when_audit_log_parent_is_not_directory() {
        let workspace = tempdir().expect("create temp workspace");
        let parent_file = workspace.path().join("not-a-dir");
        fs::write(&parent_file, "blocker").expect("write parent file");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                audit_log_path: Some(parent_file.join("audit.jsonl")),
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("audit_log_unavailable"));
        assert!(matches!(result, Err(ExecError::AuditLogUnavailable { .. })));
    }

    #[test]
    fn preflight_rejects_relative_audit_log_path() {
        let workspace = tempdir().expect("create temp workspace");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                audit_log_path: Some(PathBuf::from("audit.jsonl")),
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let err = gateway
            .preflight(&request)
            .expect_err("relative audit log path must be rejected");
        let (event, err) = err.into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("audit_log_path_invalid"));
        match err {
            ExecError::AuditLogPathInvalid { path, .. } => {
                assert_eq!(path, PathBuf::from("audit.jsonl"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn pure_request_projections_ignore_rejected_audit_ancestor_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().expect("create temp workspace");
        let real_dir = workspace.path().join("real-audit");
        let alias_dir = workspace.path().join("alias-audit");
        fs::create_dir(&real_dir).expect("create real audit dir");
        symlink(&real_dir, &alias_dir).expect("create audit dir symlink");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                audit_log_path: Some(alias_dir.join("nested").join("audit.jsonl")),
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let resolution = gateway.resolve_request(&request);
        assert!(Path::new(&resolution.program).is_absolute());

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);

        let event = gateway
            .preflight(&request)
            .expect("preflight should stay pure");
        assert_eq!(event.decision, ExecDecision::Run);
        assert!(
            !real_dir.join("nested").exists(),
            "pure projections must not create audit directories behind a rejected symlink ancestor"
        );
    }

    #[cfg(unix)]
    #[test]
    fn execute_denies_when_audit_log_path_traverses_ancestor_symlink() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().expect("create temp workspace");
        let real_dir = workspace.path().join("real-audit");
        let alias_dir = workspace.path().join("alias-audit");
        fs::create_dir(&real_dir).expect("create real audit dir");
        symlink(&real_dir, &alias_dir).expect("create audit dir symlink");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                audit_log_path: Some(alias_dir.join("nested").join("audit.jsonl")),
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("audit_log_unavailable"));
        assert!(matches!(result, Err(ExecError::AuditLogUnavailable { .. })));
        assert!(
            !real_dir.join("nested").exists(),
            "execute must not create audit directories behind a rejected symlink ancestor"
        );
    }

    #[test]
    fn pure_request_projections_do_not_create_missing_audit_log_parent_directories() {
        let workspace = tempdir().expect("create temp workspace");
        let audit_path = canonical_test_root(&workspace)
            .join("logs")
            .join("audit")
            .join("gateway.jsonl");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                audit_log_path: Some(audit_path.clone()),
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            OsString::from(dummy_program()),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let resolution = gateway.resolve_request(&request);
        assert!(Path::new(&resolution.program).is_absolute());
        assert!(
            !audit_path.exists(),
            "resolve_request must stay side-effect free"
        );

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);
        assert!(!audit_path.exists(), "evaluate must stay side-effect free");

        let event = gateway.preflight(&request).expect("preflight should pass");
        assert_eq!(event.decision, ExecDecision::Run);
        assert!(!audit_path.exists(), "preflight must stay side-effect free");
    }

    #[test]
    fn execute_creates_missing_audit_log_parent_directories() {
        let workspace = tempdir().expect("create temp workspace");
        let audit_path = canonical_test_root(&workspace)
            .join("logs")
            .join("audit")
            .join("gateway.jsonl");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                enforce_allowlisted_program_for_mutation: false,
                audit_log_path: Some(audit_path.clone()),
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let request = ExecRequest::new(
            dummy_program_absolute_path(),
            vec![OsString::from(dummy_shell_flag()), OsString::from("exit 0")],
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        );

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Run);
        let status = result.expect("execute should still succeed");
        assert!(status.success(), "unexpected status: {status}");
        assert!(
            audit_path.exists(),
            "execute should prepare and write the audit file"
        );
    }

    #[test]
    fn prepare_command_creates_audit_log_and_writes_prepare_record() {
        let workspace = tempdir().expect("create temp workspace");
        let audit_path = canonical_test_root(&workspace)
            .join("logs")
            .join("audit")
            .join("gateway.jsonl");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                enforce_allowlisted_program_for_mutation: false,
                audit_log_path: Some(audit_path.clone()),
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let request = ExecRequest::new(
            non_mutating_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let (event, result) = gateway.prepare_command(&request);

        assert_eq!(event.decision, ExecDecision::Run);
        assert!(result.is_ok(), "prepare_command should succeed: {result:?}");
        assert!(
            audit_path.exists(),
            "prepare_command should prepare and write the audit file"
        );

        let content = fs::read_to_string(&audit_path).expect("read audit log");
        let record: serde_json::Value =
            serde_json::from_str(content.lines().next().expect("audit line"))
                .expect("parse audit json");
        assert_eq!(record["result"]["status"], "prepared");
        assert_eq!(record["event"]["decision"], "run");
    }

    #[cfg(unix)]
    #[test]
    fn prepared_child_wait_writes_execution_record() {
        let workspace = tempdir().expect("create temp workspace");
        let audit_path = canonical_test_root(&workspace)
            .join("logs")
            .join("audit")
            .join("gateway.jsonl");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                enforce_allowlisted_program_for_mutation: false,
                audit_log_path: Some(audit_path.clone()),
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let program = dummy_program_absolute_path();
        let request = ExecRequest::new(
            &program,
            vec![dummy_shell_flag(), "exit 0"],
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        )
        .with_declared_mutation(false);
        let (_event, result) = gateway.prepare_command(&request);
        let status = result
            .expect("prepare command")
            .spawn()
            .expect("spawn prepared command")
            .wait()
            .result
            .expect("wait prepared command");
        assert!(status.success(), "unexpected status: {status}");

        let content = fs::read_to_string(&audit_path).expect("read audit log");
        let records = content
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("parse audit line"))
            .collect::<Vec<_>>();
        assert_eq!(records.len(), 2, "expected prepare + execution record");
        assert_eq!(records[0]["result"]["status"], "prepared");
        assert_eq!(records[1]["result"]["status"], "exited");
        assert_eq!(records[1]["event"]["decision"], "run");
    }

    #[test]
    fn capability_report_matches_supported_isolation() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let report = gateway.capability_report();
        assert_eq!(report.supported_isolation, ExecutionIsolation::BestEffort);
        assert_eq!(
            report.policy_default_isolation,
            ExecutionIsolation::BestEffort
        );
    }

    #[test]
    fn default_gateway_policy_default_matches_none_only_hosts() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::None);
        let report = gateway.capability_report();
        assert_eq!(report.supported_isolation, ExecutionIsolation::None);
        assert_eq!(report.policy_default_isolation, ExecutionIsolation::None);
    }

    #[test]
    fn execute_with_event_preserves_deny_reason() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            dummy_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::Strict,
            workspace.path(),
        );

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.reason.as_deref(), Some("isolation_not_supported"));
        assert!(result.is_err());
    }

    #[test]
    fn prepare_command_denial_matches_evaluate_for_outside_workspace() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let outside = tempdir().expect("create outside cwd");

        let request = ExecRequest::new(
            dummy_program(),
            Vec::<OsString>::new(),
            outside.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let evaluated = gateway.evaluate(&request);
        let (event, result) = gateway.prepare_command(&request);

        assert_eq!(event.reason, evaluated.reason);
        assert_eq!(event.decision, evaluated.decision);
        assert!(matches!(result, Err(ExecError::CwdOutsideWorkspace { .. })));
    }

    #[test]
    fn denies_mutation_for_non_allowlisted_program() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let program = non_allowlisted_program_path(&workspace);
        write_test_executable_placeholder(&program);
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(true);
        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("mutation_requires_allowlisted_program")
        );
    }

    #[test]
    fn requires_explicit_mutation_declaration_for_non_allowlisted_explicit_programs() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let program = non_allowlisted_program_path(&workspace);
        write_test_executable_placeholder(&program);
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("mutation_declaration_required")
        );
        assert!(matches!(
            result,
            Err(ExecError::MutationDeclarationRequired)
        ));
    }

    #[test]
    fn denies_bare_programs_for_allowlisted_execution_even_without_mutation_declaration() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            non_mutating_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("allowlisted_execution_requires_explicit_program_path")
        );
        assert!(matches!(result, Err(ExecError::PolicyDenied(_))));
    }

    #[test]
    fn allows_mutation_for_explicitly_allowlisted_program_path() {
        let workspace = tempdir().expect("create temp workspace");
        let program = allowlisted_program_path(&workspace);
        write_test_executable_placeholder(&program);
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(true);
        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);
        assert_eq!(
            event.requested_policy_meta,
            crate::audit::requested_policy_meta(ExecutionIsolation::BestEffort)
        );
    }

    #[test]
    fn denies_non_mutating_for_non_allowlisted_program() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            resolved_non_mutating_program_path(),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("non_mutating_requires_allowlisted_program")
        );
    }

    #[test]
    fn allows_non_mutating_for_explicitly_allowlisted_program_path() {
        let program = resolved_non_mutating_program_path();
        let policy = GatewayPolicy {
            non_mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);
    }

    #[test]
    fn denies_non_mutating_allowlisted_program_with_startup_sensitive_env() {
        let program = resolved_non_mutating_program_path();
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                non_mutating_program_allowlist: vec![program.display().to_string()],
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_env([("PATH", "/tmp/shadow")])
        .with_declared_mutation(false);

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("startup_sensitive_env_forbidden")
        );
        assert!(matches!(
            result,
            Err(ExecError::PolicyDenied(detail))
                if detail.contains("startup-sensitive environment variable `PATH`")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn denies_mutating_allowlisted_program_with_loader_env() {
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("allowlisted.sh");
        write_unix_shell_executable(&program, "exit 0\n");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                mutating_program_allowlist: vec![program.display().to_string()],
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        )
        .with_env([("LD_PRELOAD", "/tmp/evil.so")])
        .with_declared_mutation(true);

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("startup_sensitive_env_forbidden")
        );
        assert!(matches!(
            result,
            Err(ExecError::PolicyDenied(detail))
                if detail.contains("startup-sensitive environment variable `LD_PRELOAD`")
        ));
    }

    #[test]
    fn allows_benign_env_for_allowlisted_non_mutating_program() {
        let program = resolved_non_mutating_program_path();
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                non_mutating_program_allowlist: vec![program.display().to_string()],
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_env([("LANG", "C")])
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);
    }

    #[cfg(unix)]
    #[test]
    fn prepared_allowlisted_program_rejects_in_place_content_change() {
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("allowlisted.sh");
        write_unix_shell_executable(&program, "exit 0\n");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                mutating_program_allowlist: vec![program.display().to_string()],
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        )
        .with_declared_mutation(true);
        let (_event, result) = gateway.prepare_command(&request);
        let prepared = result.expect("prepare command");

        write_unix_shell_executable(&program, "exit 1\n");

        let err = prepared
            .spawn()
            .expect_err("content drift should be rejected before spawn");
        assert!(matches!(
            err,
            ExecError::RequestPathChanged {
                kind: "program",
                ref detail,
                ..
            } if detail == "file contents changed"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_non_mutating_allowlisted_program_rejects_in_place_content_change() {
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("readonly-allowlisted.sh");
        write_unix_shell_executable(&program, "exit 0\n");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                non_mutating_program_allowlist: vec![program.display().to_string()],
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        )
        .with_declared_mutation(false);
        let (_event, result) = gateway.prepare_command(&request);
        let prepared = result.expect("prepare command");

        write_unix_shell_executable(&program, "exit 1\n");

        let err = prepared
            .spawn()
            .expect_err("content drift should be rejected before spawn");
        assert!(matches!(
            err,
            ExecError::RequestPathChanged {
                kind: "program",
                ref detail,
                ..
            } if detail == "file contents changed"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_program_rejects_in_place_content_change_even_without_allowlist_enforcement() {
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("rewritable.sh");
        write_unix_shell_executable(&program, "exit 0\n");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        );
        let (_event, result) = gateway.prepare_command(&request);
        let prepared = result.expect("prepare command");

        write_unix_shell_executable(&program, "exit 1\n");

        let err = prepared
            .spawn()
            .expect_err("content drift should be rejected before spawn");
        assert!(matches!(
            err,
            ExecError::RequestPathChanged {
                kind: "program",
                ref detail,
                ..
            } if detail == "file contents changed"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_unrestricted_program_rejects_in_place_content_change() {
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("unrestricted.sh");
        write_unix_shell_executable(&program, "exit 0\n");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        );
        let (_event, result) = gateway.prepare_command(&request);
        let prepared = result.expect("prepare command");

        write_unix_shell_executable(&program, "exit 1\n");

        let err = prepared
            .spawn()
            .expect_err("content drift should be rejected before spawn");
        assert!(matches!(
            err,
            ExecError::RequestPathChanged {
                kind: "program",
                ref detail,
                ..
            } if detail == "file contents changed"
        ));
    }

    #[test]
    fn denies_mutation_for_bare_program_even_when_same_name_is_allowlisted() {
        let resolved_program = resolved_non_mutating_program_path();
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec![resolved_program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            non_mutating_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(true);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("allowlisted_execution_requires_explicit_program_path")
        );
    }

    #[test]
    fn denies_non_mutating_for_bare_program_even_when_same_name_is_allowlisted() {
        let resolved_program = resolved_non_mutating_program_path();
        let policy = GatewayPolicy {
            non_mutating_program_allowlist: vec![resolved_program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            non_mutating_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("allowlisted_execution_requires_explicit_program_path")
        );
    }

    #[test]
    fn denies_mutation_for_explicit_path_that_only_matches_allowlisted_basename() {
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec!["omne-fs".to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let program = non_allowlisted_program_path(&workspace);
        write_test_executable_placeholder(&program);
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(true);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("mutation_requires_allowlisted_program")
        );
    }

    #[test]
    fn denies_opaque_command_launcher_without_allowlist() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            dummy_program(),
            vec![dummy_shell_flag(), "echo hello"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[test]
    fn detects_env_as_opaque_command_launcher() {
        assert!(uses_opaque_command_launcher(OsStr::new("env")));
        assert!(uses_opaque_command_launcher(OsStr::new("/usr/bin/env")));
    }

    #[cfg(windows)]
    #[test]
    fn detects_env_with_windows_executable_suffixes_as_opaque_command_launcher() {
        assert!(uses_opaque_command_launcher(OsStr::new("env.exe")));
        assert!(uses_opaque_command_launcher(OsStr::new(
            r"C:\Windows\System32\env.cmd"
        )));
        assert!(uses_opaque_command_launcher(OsStr::new("env.bat")));
    }

    #[test]
    fn detects_versioned_and_variant_opaque_launchers() {
        assert!(uses_opaque_command_launcher(OsStr::new("python3.12")));
        assert!(uses_opaque_command_launcher(OsStr::new("pip3.12")));
        assert!(uses_opaque_command_launcher(OsStr::new("nodejs")));
        assert!(!uses_opaque_command_launcher(OsStr::new("python-config")));
    }

    #[cfg(unix)]
    #[test]
    fn denies_env_launcher_without_allowlist() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "/usr/bin/env",
            vec!["sh", "-c", "echo hello"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[test]
    fn denies_non_mutating_allowlisted_wrapper_that_delegates_to_env() {
        let workspace = tempdir().expect("create temp workspace");
        let wrapper = test_program_path(&workspace, "timeout");
        let nested_env = test_program_path(&workspace, "env");
        write_test_executable_placeholder(&wrapper);
        write_test_executable_placeholder(&nested_env);
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                non_mutating_program_allowlist: vec![wrapper.display().to_string()],
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &wrapper,
            vec![
                OsString::from("1"),
                nested_env.into_os_string(),
                OsString::from("printenv"),
            ],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[test]
    fn allows_non_mutating_allowlisted_wrapper_when_nested_command_is_not_opaque() {
        let workspace = tempdir().expect("create temp workspace");
        let wrapper = test_program_path(&workspace, "timeout");
        let nested_tool = test_program_path(&workspace, "safe-tool");
        write_test_executable_placeholder(&wrapper);
        write_test_executable_placeholder(&nested_tool);
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                non_mutating_program_allowlist: vec![wrapper.display().to_string()],
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &wrapper,
            vec![
                OsString::from("1"),
                nested_tool.into_os_string(),
                OsString::from("--version"),
            ],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);
    }

    #[test]
    fn allows_known_tool_family_when_non_mutating_path_is_explicitly_allowlisted() {
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("git");
        write_test_executable_placeholder(&program);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = fs::metadata(&program)
                .expect("program metadata")
                .permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&program, permissions).expect("chmod program");
        }
        let policy = GatewayPolicy {
            non_mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &program,
            vec!["status"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);
    }

    #[test]
    fn audit_write_failure_after_execution_error_still_surfaces_audit_failure() {
        let result: ExecResult<()> = Err(ExecError::PolicyDenied("spawn denied".to_string()));
        let audit_result: ExecResult<()> = Err(ExecError::AuditLogWriteFailed {
            path: PathBuf::from("audit.jsonl"),
            detail: "disk full".to_string(),
        });

        let combined = combine_result_with_audit_write(result, audit_result);

        match combined {
            Err(ExecError::AuditLogWriteFailedAfterExecutionError {
                path,
                detail,
                execution_error,
            }) => {
                assert_eq!(path, PathBuf::from("audit.jsonl"));
                assert_eq!(detail, "disk full");
                assert_eq!(execution_error, "policy denied request: spawn denied");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn audit_write_failure_after_execution_success_preserves_exit_status() {
        let result = Ok(exit_status_from_code(7));
        let audit_result: ExecResult<()> = Err(ExecError::AuditLogWriteFailed {
            path: PathBuf::from("audit.jsonl"),
            detail: "disk full".to_string(),
        });

        let combined = combine_exit_status_with_audit_write(result, audit_result);

        match combined {
            Err(ExecError::AuditLogWriteFailedAfterExecutionSuccess {
                path,
                detail,
                status,
            }) => {
                assert_eq!(path, PathBuf::from("audit.jsonl"));
                assert_eq!(detail, "disk full");
                assert_eq!(status.code(), Some(7));
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn denies_interpreter_launcher_without_allowlist() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            interpreter_program(),
            vec![interpreter_inline_flag(), interpreter_mutating_snippet()],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[test]
    fn denies_versioned_python_launcher_when_explicitly_allowlisted_for_non_mutation() {
        let workspace = tempdir().expect("create temp workspace");
        let program = variant_opaque_program_path(&workspace, "python3.12");
        write_test_executable_placeholder(&program);
        let policy = GatewayPolicy {
            non_mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &program,
            vec![interpreter_inline_flag(), "print('hello')"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[test]
    fn denies_versioned_pip_frontend_when_explicitly_allowlisted_for_non_mutation() {
        let workspace = tempdir().expect("create temp workspace");
        let program = variant_opaque_program_path(&workspace, "pip3.12");
        write_test_executable_placeholder(&program);
        let policy = GatewayPolicy {
            non_mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &program,
            vec!["show", "setuptools"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[test]
    fn denies_opaque_command_launcher_when_explicitly_allowlisted_for_mutation() {
        let program = dummy_program_absolute_path();
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            &program,
            vec![dummy_shell_flag(), "echo hello"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(true);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[cfg(unix)]
    #[test]
    fn denies_opaque_command_launcher_alias_when_target_is_allowlisted_for_mutation() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().expect("create temp workspace");
        let program = dummy_program_absolute_path();
        let alias = workspace.path().join("trusted-tool");
        symlink(&program, &alias).expect("create program alias");

        let policy = GatewayPolicy {
            mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &alias,
            vec![dummy_shell_flag(), "echo hello"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(true);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[test]
    fn denies_opaque_command_launcher_when_explicitly_allowlisted_for_non_mutation() {
        let program = dummy_program_absolute_path();
        let policy = GatewayPolicy {
            non_mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            &program,
            vec![dummy_shell_flag(), "echo hello"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[cfg(unix)]
    #[test]
    fn denies_opaque_command_launcher_alias_when_target_is_allowlisted_for_non_mutation() {
        use std::os::unix::fs::symlink;

        let workspace = tempdir().expect("create temp workspace");
        let program = dummy_program_absolute_path();
        let alias = workspace.path().join("trusted-tool");
        symlink(&program, &alias).expect("create program alias");

        let policy = GatewayPolicy {
            non_mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &alias,
            vec![dummy_shell_flag(), "echo hello"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[cfg(unix)]
    #[test]
    fn denies_opaque_command_launcher_hard_link_when_alias_is_allowlisted_for_non_mutation() {
        use std::fs::hard_link;
        use std::os::unix::fs::PermissionsExt;

        let workspace = tempdir().expect("create temp workspace");
        let program = dummy_program_absolute_path();
        let copied = workspace.path().join("shell-copy");
        let alias = workspace.path().join("trusted-tool");
        fs::copy(&program, &copied).expect("copy opaque launcher into workspace");
        let mut permissions = fs::metadata(&copied)
            .expect("copied launcher metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&copied, permissions).expect("chmod copied launcher");
        hard_link(&copied, &alias).expect("create program hard-link alias");

        let policy = GatewayPolicy {
            non_mutating_program_allowlist: vec![alias.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &alias,
            vec![dummy_shell_flag(), "echo hello"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[cfg(unix)]
    #[test]
    fn denies_copied_opaque_command_launcher_alias_when_copy_is_allowlisted_for_non_mutation() {
        use std::os::unix::fs::PermissionsExt;

        let workspace = tempdir().expect("create temp workspace");
        let program = dummy_program_absolute_path();
        let alias = workspace.path().join("trusted-tool");
        fs::copy(&program, &alias).expect("copy program alias");
        let mut permissions = fs::metadata(&alias).expect("alias metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&alias, permissions).expect("chmod alias");

        let policy = GatewayPolicy {
            non_mutating_program_allowlist: vec![alias.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &alias,
            vec![dummy_shell_flag(), "echo hello"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("opaque_command_forbidden"));
    }

    #[test]
    fn denies_explicitly_allowlisted_program_without_declared_mutation() {
        let workspace = tempdir().expect("create temp workspace");
        let program = allowlisted_program_path(&workspace);
        write_test_executable_placeholder(&program);
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("allowlisted_program_requires_declared_mutation")
        );
    }

    #[test]
    fn denies_policy_default_isolation_mismatch() {
        let policy = GatewayPolicy {
            default_isolation: ExecutionIsolation::Strict,
            ..GatewayPolicy::default()
        };
        let gateway =
            ExecGateway::with_policy_and_supported_isolation(policy, ExecutionIsolation::Strict);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::with_policy_default_isolation(
            "echo",
            vec!["hello"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("policy_default_isolation_mismatch")
        );
        assert!(matches!(
            result,
            Err(ExecError::PolicyDefaultIsolationMismatch {
                requested: ExecutionIsolation::BestEffort,
                policy_default: ExecutionIsolation::Strict,
            })
        ));
    }

    #[test]
    fn denies_none_isolation_by_default_policy() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "omne-fs",
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        );
        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("isolation_none_forbidden"));
    }

    #[test]
    fn prepare_command_sets_current_dir() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            non_mutating_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(false);
        let (_event, result) = gateway.prepare_command(&request);
        let prepared = result.expect("prepare command");
        let expected_cwd = workspace
            .path()
            .canonicalize()
            .expect("canonicalize workspace");
        assert_eq!(prepared.current_dir(), Some(expected_cwd.as_path()));
    }

    #[cfg(unix)]
    #[test]
    fn execute_status_applies_audited_request_environment() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let workspace = tempdir().expect("create temp workspace");
        let program = dummy_program_absolute_path();
        let request = ExecRequest::new(
            &program,
            vec![
                "-c",
                "test \"$OMNE_GATEWAY_REQUEST\" = expected && test -z \"$OMNE_GATEWAY_AMBIENT\"",
            ],
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        )
        .with_env([("OMNE_GATEWAY_REQUEST", "expected")])
        .with_declared_mutation(false);

        let status = gateway
            .execute_status(&request)
            .expect("execute should apply request env");
        assert!(status.success(), "unexpected status: {status}");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_command_applies_audited_request_environment() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let workspace = tempdir().expect("create temp workspace");
        let program = dummy_program_absolute_path();
        let request = ExecRequest::new(
            &program,
            vec![
                "-c",
                "test \"$OMNE_GATEWAY_REQUEST\" = expected && test -z \"$OMNE_GATEWAY_AMBIENT\"",
            ],
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        )
        .with_env([("OMNE_GATEWAY_REQUEST", "expected")])
        .with_declared_mutation(false);
        let (_event, result) = gateway.prepare_command(&request);
        let status = result
            .expect("prepare command")
            .spawn()
            .expect("spawn prepared command")
            .wait()
            .result
            .expect("wait prepared command");
        assert!(status.success(), "unexpected status: {status}");
    }

    #[cfg(unix)]
    #[test]
    fn prepared_command_spawn_uses_noninteractive_stdio() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let workspace = tempdir().expect("create temp workspace");
        let program = dummy_program_absolute_path();
        let request = ExecRequest::new(
            &program,
            vec!["-c", "exit 0"],
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        )
        .with_declared_mutation(false);
        let (_event, result) = gateway.prepare_command(&request);
        let mut prepared_child = result
            .expect("prepare command")
            .spawn()
            .expect("spawn prepared command");

        assert!(
            prepared_child.stdin().is_none(),
            "prepared command should not expose stdin"
        );
        assert!(
            prepared_child.stdout().is_none(),
            "prepared command should not expose stdout"
        );
        assert!(
            prepared_child.stderr().is_none(),
            "prepared command should not expose stderr"
        );
        let status = prepared_child.wait().result.expect("wait prepared command");
        assert!(status.success(), "unexpected status: {status}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_executable_explicit_program_path() {
        use std::os::unix::fs::PermissionsExt;

        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("plain-tool");
        fs::write(&program, "echo hi\n").expect("write plain program");
        let mut permissions = fs::metadata(&program).expect("metadata").permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&program, permissions).expect("chmod plain program");

        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("program_path_invalid"));
        assert!(matches!(
            result,
            Err(ExecError::ProgramPathInvalid { ref detail, .. })
                if detail == "program path must reference a spawnable executable"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn preflight_rejects_non_executable_explicit_program_path() {
        use std::os::unix::fs::PermissionsExt;

        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("plain-tool");
        fs::write(&program, "echo hi\n").expect("write plain program");
        let mut permissions = fs::metadata(&program).expect("metadata").permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&program, permissions).expect("chmod plain program");

        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let err = gateway
            .preflight(&request)
            .expect_err("preflight should fail before execution");
        let (event, error) = err.into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("program_path_invalid"));
        assert!(matches!(
            error,
            ExecError::ProgramPathInvalid { ref detail, .. }
                if detail == "program path must reference a spawnable executable"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn mutation_policy_does_not_mask_non_executable_explicit_program_path() {
        use std::os::unix::fs::PermissionsExt;

        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::None);
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("plain-tool");
        fs::write(&program, "echo hi\n").expect("write plain program");
        let mut permissions = fs::metadata(&program).expect("metadata").permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&program, permissions).expect("chmod plain program");

        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("program_path_invalid"));
        assert!(matches!(
            result,
            Err(ExecError::ProgramPathInvalid { ref detail, .. })
                if detail == "program path must reference a spawnable executable"
        ));
    }

    #[test]
    fn post_preflight_request_path_errors_flip_event_to_deny() {
        let event = ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: host_supported_test_isolation(),
            requested_policy_meta: requested_policy_meta(host_supported_test_isolation()),
            supported_isolation: host_supported_test_isolation(),
            program: OsString::from("echo"),
            args: Vec::new(),
            env: Vec::new(),
            cwd: PathBuf::from("."),
            workspace_root: PathBuf::from("."),
            declared_mutation: false,
            reason: None,
            sandbox_runtime: None,
        };

        let program_event = event_for_post_preflight_error(
            event.clone(),
            &ExecError::RequestPathChanged {
                kind: "program",
                path: PathBuf::from("/tmp/tool"),
                detail: "file identity changed".to_string(),
            },
        );
        assert_eq!(program_event.decision, ExecDecision::Deny);
        assert_eq!(
            program_event.reason.as_deref(),
            Some("program_path_invalid")
        );

        let cwd_event = event_for_post_preflight_error(
            event,
            &ExecError::RequestPathChanged {
                kind: "cwd",
                path: PathBuf::from("/tmp/cwd"),
                detail: "directory identity changed".to_string(),
            },
        );
        assert_eq!(cwd_event.decision, ExecDecision::Deny);
        assert_eq!(cwd_event.reason.as_deref(), Some("cwd_outside_workspace"));
    }

    #[test]
    fn bind_program_error_classifier_fails_closed_for_unexpected_errors() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy::default(),
            ExecutionIsolation::BestEffort,
        );
        let event = ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: ExecutionIsolation::BestEffort,
            requested_policy_meta: requested_policy_meta(ExecutionIsolation::BestEffort),
            supported_isolation: ExecutionIsolation::BestEffort,
            program: OsString::from("tool"),
            args: Vec::new(),
            env: Vec::new(),
            cwd: PathBuf::from("/tmp"),
            workspace_root: PathBuf::from("/tmp"),
            declared_mutation: false,
            reason: None,
            sandbox_runtime: None,
        };

        let err = classify_bind_program_preflight_error(
            &gateway,
            event,
            ExecError::WorkspaceRootInvalid {
                path: PathBuf::from("/tmp"),
            },
        );

        assert_eq!(err.event.reason.as_deref(), Some("program_path_invalid"));
        assert!(matches!(err.error, ExecError::WorkspaceRootInvalid { .. }));
    }

    #[test]
    fn request_path_error_classifier_fails_closed_for_unexpected_errors() {
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy::default(),
            ExecutionIsolation::BestEffort,
        );
        let event = ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: ExecutionIsolation::BestEffort,
            requested_policy_meta: requested_policy_meta(ExecutionIsolation::BestEffort),
            supported_isolation: ExecutionIsolation::BestEffort,
            program: OsString::from("tool"),
            args: Vec::new(),
            env: Vec::new(),
            cwd: PathBuf::from("/tmp"),
            workspace_root: PathBuf::from("/tmp"),
            declared_mutation: false,
            reason: None,
            sandbox_runtime: None,
        };

        let err = classify_request_path_preflight_error(
            &gateway,
            event,
            ExecError::ProgramLookupFailed {
                program: "tool".to_string(),
                detail: "unexpected".to_string(),
            },
        );

        assert_eq!(err.event.reason.as_deref(), Some("cwd_outside_workspace"));
        assert!(matches!(err.error, ExecError::ProgramLookupFailed { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_command_fails_closed_when_program_identity_changes_before_spawn() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let workspace = tempdir().expect("create temp workspace");
        let workspace_root = canonical_test_root(&workspace);
        let audit_path = workspace_root.join("audit.jsonl");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                audit_log_path: Some(audit_path.clone()),
                ..policy
            },
            host_supported_test_isolation(),
        );
        let program = workspace_root.join("tool.sh");
        let replacement = workspace_root.join("tool-replacement.sh");
        write_unix_shell_executable(&program, "exit 0\n");
        write_unix_shell_executable(&replacement, "exit 1\n");

        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            &workspace_root,
            host_supported_test_isolation(),
            &workspace_root,
        )
        .with_declared_mutation(false);
        let (_event, result) = gateway.prepare_command(&request);
        let prepared = result.expect("prepare command");

        fs::remove_file(&program).expect("remove original program");
        fs::rename(&replacement, &program).expect("replace program");

        let err = prepared
            .spawn()
            .expect_err("identity change should fail closed");
        match err {
            ExecError::RequestPathChanged { kind, .. } => assert_eq!(kind, "program"),
            other => panic!("unexpected error: {other}"),
        }

        let audit = fs::read_to_string(audit_path).expect("read audit log");
        let record: serde_json::Value =
            serde_json::from_str(audit.lines().last().expect("execution error record"))
                .expect("parse audit record");
        assert_eq!(record["event"]["decision"], "deny");
        assert_eq!(record["event"]["reason"], "program_path_invalid");
        assert_eq!(record["result"]["status"], "execution_error");
    }

    #[cfg(unix)]
    #[test]
    fn prepare_command_rejects_symlink_cwd_ancestor() {
        use std::os::unix::fs::symlink;

        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let real_dir = workspace.path().join("real");
        let link_dir = workspace.path().join("link");
        fs::create_dir_all(&real_dir).expect("create real dir");
        symlink(&real_dir, &link_dir).expect("create symlink");

        let request = ExecRequest::new(
            non_mutating_program(),
            Vec::<OsString>::new(),
            &link_dir,
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(false);
        let (event, result) = gateway.prepare_command(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("cwd_invalid"));
        match result.expect_err("symlink cwd ancestor should fail closed") {
            ExecError::CwdInvalid { cwd, detail } => {
                assert_eq!(cwd, link_dir);
                assert!(
                    detail.contains("must not traverse symlink"),
                    "unexpected detail: {detail}"
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn resolve_request_rejects_symlink_workspace_root_ancestor() {
        use std::os::unix::fs::symlink;

        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let real_root = workspace.path().join("real");
        let alias_root = workspace.path().join("alias");
        let cwd = real_root.join("cwd");
        fs::create_dir_all(&cwd).expect("create real cwd");
        symlink(&real_root, &alias_root).expect("create workspace-root symlink");

        let request = ExecRequest::new(
            non_mutating_program(),
            Vec::<OsString>::new(),
            &cwd,
            host_supported_test_isolation(),
            &alias_root,
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("workspace_root_invalid"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn evaluate_allows_macos_system_temp_root_alias() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let cwd = workspace.path().join("cwd");
        fs::create_dir_all(&cwd).expect("create cwd");

        let request = ExecRequest::new(
            non_mutating_program(),
            Vec::<OsString>::new(),
            &cwd,
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);
    }

    #[test]
    fn resolve_request_uses_validated_canonical_paths() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let cwd = workspace.path().join("cwd");
        fs::create_dir_all(&cwd).expect("create cwd");

        let request = ExecRequest::new(
            dummy_program(),
            Vec::<OsString>::new(),
            cwd.join(".."),
            host_supported_test_isolation(),
            cwd.join(".."),
        );

        let resolution = gateway.resolve_request(&request);
        let canonical_workspace = workspace
            .path()
            .canonicalize()
            .expect("canonical workspace");

        assert_eq!(resolution.cwd, canonical_workspace);
        assert_eq!(resolution.workspace_root, canonical_workspace);
    }

    #[test]
    fn resolve_request_resolves_bare_program_to_absolute_path() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            non_mutating_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(false);

        let resolution = gateway.resolve_request(&request);

        assert_eq!(resolution.program, resolved_non_mutating_program_path());
    }

    #[test]
    fn evaluate_resolves_bare_program_to_absolute_path_in_event() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            non_mutating_program(),
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);

        assert_eq!(event.program, resolved_non_mutating_program_path());
    }

    #[cfg(unix)]
    #[test]
    fn prepared_command_fails_closed_when_cwd_identity_changes_before_spawn() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let workspace = tempdir().expect("create temp workspace");
        let workspace_root = canonical_test_root(&workspace);
        let audit_path = workspace_root.join("audit.jsonl");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                audit_log_path: Some(audit_path.clone()),
                ..policy
            },
            host_supported_test_isolation(),
        );
        let cwd = workspace_root.join("cwd");
        let moved = workspace_root.join("cwd-moved");
        fs::create_dir_all(&cwd).expect("create cwd");

        let request = ExecRequest::new(
            "sh",
            vec!["-c", "exit 0"],
            &cwd,
            host_supported_test_isolation(),
            &workspace_root,
        );
        let mut command = Command::new(dummy_program_absolute_path());
        command.args(["-c", "exit 0"]);

        let (_event, result) = gateway.prepare_command(&request);
        let prepared = result.expect("prepare command");

        fs::rename(&cwd, &moved).expect("move original cwd away");
        fs::create_dir_all(&cwd).expect("replace cwd with different directory");

        let err = prepared
            .spawn()
            .expect_err("identity change should fail closed");
        match err {
            ExecError::RequestPathChanged { kind, .. } => assert_eq!(kind, "cwd"),
            other => panic!("unexpected error: {other}"),
        }

        let audit = fs::read_to_string(audit_path).expect("read audit log");
        let record: serde_json::Value =
            serde_json::from_str(audit.lines().last().expect("execution error record"))
                .expect("parse audit record");
        assert_eq!(record["event"]["decision"], "deny");
        assert_eq!(record["event"]["reason"], "cwd_outside_workspace");
        assert_eq!(record["result"]["status"], "execution_error");
    }

    #[cfg(windows)]
    #[test]
    fn windows_path_boundary_checks_are_case_insensitive() {
        let cases = [
            (r"C:\Root\Sub", r"c:\root"),
            (r"\\?\C:\Root\Sub", r"c:\root"),
            (r"\\server\share\Root\Sub", r"\\SERVER\SHARE\root"),
            (r"\\?\UNC\Server\Share\Root\Sub", r"\\server\share\root"),
        ];

        for (path, prefix) in cases {
            assert!(
                path_starts_with(Path::new(path), Path::new(prefix)),
                "expected {path} to stay within {prefix}"
            );
        }
    }

    #[test]
    fn execute_status_audit_records_nonzero_exit() {
        let workspace = tempdir().expect("create temp workspace");
        let audit_path = canonical_test_root(&workspace).join("audit.jsonl");
        let (program, args) = shell_exit_nonzero_command(&workspace);
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            audit_log_path: Some(audit_path.clone()),
            mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let request = ExecRequest::new(
            &program,
            args,
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(true);

        let status = gateway
            .execute_status(&request)
            .expect("command should execute");
        assert!(!status.success());

        let content = fs::read_to_string(audit_path).expect("read audit");
        assert!(content.contains("\"status\":\"exited\""));
        assert!(content.contains("\"exit_code\":1"));
        assert!(content.contains("\"success\":false"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_detected_capability_fails_closed_for_best_effort_requests() {
        let workspace = tempdir().expect("create temp workspace");
        let policy = GatewayPolicy {
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy(policy);
        let request = ExecRequest::new(
            "sh",
            vec!["-c", "exit 0"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        );

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("isolation_not_supported"));
        assert!(matches!(
            result,
            Err(ExecError::IsolationNotSupported {
                requested: ExecutionIsolation::BestEffort,
                supported: ExecutionIsolation::None,
            })
        ));
    }

    #[test]
    fn execute_status_audit_records_spawn_failure() {
        let workspace = tempdir().expect("create temp workspace");
        let audit_path = canonical_test_root(&workspace).join("audit.jsonl");
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            audit_log_path: Some(audit_path.clone()),
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let request = ExecRequest::new(
            "__omne_exec_gateway_missing_program__",
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(false);

        let err = gateway
            .execute_status(&request)
            .expect_err("spawn should fail");
        assert!(matches!(err, ExecError::ProgramLookupFailed { .. }));

        let content = fs::read_to_string(audit_path).expect("read audit");
        assert!(content.contains("\"status\":\"prepare_error\""));
    }

    #[cfg(unix)]
    #[test]
    fn execute_status_reuses_prepared_audit_sink_after_path_replacement() {
        let workspace = tempdir().expect("create temp workspace");
        let audit_path = canonical_test_root(&workspace).join("audit.jsonl");
        let moved_audit_path = canonical_test_root(&workspace).join("audit.moved.jsonl");
        let (program, args) =
            audit_rebinding_shell_command(&workspace, &audit_path, &moved_audit_path);
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            audit_log_path: Some(audit_path.clone()),
            mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let request = ExecRequest::new(
            &program,
            args,
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(true);

        let status = gateway
            .execute_status(&request)
            .expect("prepared audit sink should survive path replacement");
        assert!(status.success());
        assert!(
            audit_path.is_dir(),
            "original audit path should now be a directory"
        );

        let content = fs::read_to_string(&moved_audit_path).expect("read moved audit file");
        assert!(content.contains("\"status\":\"exited\""));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_command_reuses_prepared_audit_sink_after_path_replacement() {
        let workspace = tempdir().expect("create temp workspace");
        let audit_path = canonical_test_root(&workspace).join("audit.jsonl");
        let moved_audit_path = canonical_test_root(&workspace).join("audit.moved.jsonl");
        let (program, args) =
            audit_rebinding_shell_command(&workspace, &audit_path, &moved_audit_path);
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            audit_log_path: Some(audit_path.clone()),
            mutating_program_allowlist: vec![program.display().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let request = ExecRequest::new(
            &program,
            args,
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(true);
        let (_event, result) = gateway.prepare_command(&request);
        let outcome = result
            .expect("prepare command should succeed")
            .spawn()
            .expect("prepared audit sink should survive path replacement")
            .wait();
        let status = outcome.result.expect("wait prepared command");
        assert!(status.success());
        assert!(
            audit_path.is_dir(),
            "original audit path should now be a directory"
        );

        let records = fs::read_to_string(&moved_audit_path).expect("read moved audit file");
        assert!(records.contains("\"status\":\"prepared\""));
        assert!(records.contains("\"status\":\"exited\""));
    }

    #[cfg(unix)]
    #[test]
    fn execute_status_detaches_stdio_from_open_parent_stdin() {
        run_noninteractive_stdin_helper("execute");
    }

    #[cfg(unix)]
    #[test]
    fn prepared_command_spawn_detaches_stdio_from_open_parent_stdin() {
        run_noninteractive_stdin_helper("prepare");
    }

    #[cfg(unix)]
    #[test]
    fn spawn_command_with_monitor_returns_sandbox_runtime_observation() {
        let observation = crate::audit::SandboxRuntimeObservation {
            mechanism: crate::audit::SandboxRuntimeMechanism::Landlock,
            outcome: crate::audit::SandboxRuntimeOutcome::NotEnforced,
            detail: Some("test observation".to_string()),
        };
        let mut command = Command::new(dummy_program_absolute_path());
        command.arg(dummy_shell_flag()).arg("exit 0");

        let (mut child, sandbox_runtime) = spawn_command_with_monitor(
            &mut command,
            sandbox::SandboxMonitor::with_observation(Some(observation.clone())),
        )
        .expect("spawn command with test monitor");

        assert_eq!(sandbox_runtime.as_ref(), Some(&observation));
        let status = child.wait().expect("wait for spawned child");
        assert!(status.success());
    }

    #[cfg(windows)]
    fn dummy_program() -> &'static str {
        "cmd"
    }

    #[cfg(not(windows))]
    fn dummy_program() -> &'static str {
        "sh"
    }

    fn non_mutating_program() -> &'static str {
        "uname"
    }

    fn resolved_non_mutating_program_path() -> PathBuf {
        resolve_bare_program_path(OsStr::new(non_mutating_program()))
            .expect("resolve non-mutating test program")
            .canonicalize()
            .expect("canonicalize non-mutating test program")
    }

    fn dummy_program_absolute_path() -> PathBuf {
        resolve_bare_program_path(OsStr::new(dummy_program()))
            .expect("resolve dummy test program to absolute path")
    }

    #[cfg(windows)]
    fn interpreter_program() -> &'static str {
        "python.exe"
    }

    #[cfg(not(windows))]
    fn interpreter_program() -> &'static str {
        "python3"
    }

    fn non_allowlisted_program_path(workspace: &tempfile::TempDir) -> PathBuf {
        test_program_path(workspace, "other")
    }

    fn allowlisted_program_path(workspace: &tempfile::TempDir) -> PathBuf {
        test_program_path(workspace, "allowlisted-tool")
    }

    #[cfg(windows)]
    fn shell_exit_nonzero_command(workspace: &tempfile::TempDir) -> (PathBuf, Vec<OsString>) {
        let program = test_program_path(workspace, "exit-one");
        write_windows_script_executable(&program, "exit /b 1\r\n");
        (program, Vec::new())
    }

    #[cfg(not(windows))]
    fn shell_exit_nonzero_command(workspace: &tempfile::TempDir) -> (PathBuf, Vec<OsString>) {
        let program = test_program_path(workspace, "exit-one");
        write_unix_shell_executable(&program, "exit 1\n");
        (program, Vec::new())
    }

    #[cfg(not(windows))]
    fn audit_rebinding_shell_command(
        workspace: &tempfile::TempDir,
        audit_path: &Path,
        moved_path: &Path,
    ) -> (PathBuf, Vec<OsString>) {
        let program = test_program_path(workspace, "audit-rebind");
        write_unix_shell_executable(
            &program,
            &format!(
                "mv \"{0}\" \"{1}\" && mkdir \"{0}\"\n",
                audit_path.display(),
                moved_path.display()
            ),
        );
        (program, Vec::new())
    }

    #[cfg(windows)]
    fn dummy_shell_flag() -> &'static str {
        "/C"
    }

    #[cfg(not(windows))]
    fn dummy_shell_flag() -> &'static str {
        "-c"
    }

    #[cfg(windows)]
    fn interpreter_inline_flag() -> &'static str {
        "-c"
    }

    #[cfg(not(windows))]
    fn interpreter_inline_flag() -> &'static str {
        "-c"
    }

    #[cfg(windows)]
    fn interpreter_mutating_snippet() -> &'static str {
        "open('deleteme.txt','w').write('x')"
    }

    #[cfg(not(windows))]
    fn interpreter_mutating_snippet() -> &'static str {
        "open('deleteme.txt','w').write('x')"
    }

    #[cfg(unix)]
    fn write_unix_executable(path: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, body).expect("write executable");
        let mut permissions = fs::metadata(path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("set permissions");
    }

    #[cfg(unix)]
    fn write_unix_shell_executable(path: &Path, body: &str) {
        write_unix_executable(
            path,
            &format!("#!{}\n{body}", dummy_program_absolute_path().display()),
        );
    }

    #[cfg(unix)]
    fn write_test_executable_placeholder(path: &Path) {
        write_unix_shell_executable(path, "exit 0\n");
    }

    #[cfg(windows)]
    fn write_test_executable_placeholder(path: &Path) {
        write_windows_script_executable(path, "exit /b 0\r\n");
    }

    #[cfg(windows)]
    fn write_windows_script_executable(path: &Path, body: &str) {
        fs::write(path, format!("@echo off\r\n{body}")).expect("write executable placeholder");
    }

    #[cfg(windows)]
    fn test_program_path(workspace: &tempfile::TempDir, stem: &str) -> PathBuf {
        workspace.path().join(format!("{stem}.cmd"))
    }

    #[cfg(not(windows))]
    fn test_program_path(workspace: &tempfile::TempDir, stem: &str) -> PathBuf {
        workspace.path().join(stem)
    }

    #[cfg(windows)]
    fn variant_opaque_program_path(workspace: &tempfile::TempDir, stem: &str) -> PathBuf {
        workspace.path().join(format!("{stem}.exe"))
    }

    #[cfg(not(windows))]
    fn variant_opaque_program_path(workspace: &tempfile::TempDir, stem: &str) -> PathBuf {
        workspace.path().join(stem)
    }

    fn host_supported_test_isolation() -> ExecutionIsolation {
        ExecutionIsolation::None
    }

    #[cfg(unix)]
    const NONINTERACTIVE_STDIN_HELPER_ENV: &str = "OMNE_EXEC_GATEWAY_NONINTERACTIVE_STDIN_HELPER";
    #[cfg(unix)]
    const NONINTERACTIVE_STDIN_MODE_ENV: &str = "OMNE_EXEC_GATEWAY_NONINTERACTIVE_STDIN_MODE";

    #[cfg(unix)]
    #[test]
    fn noninteractive_stdin_helper() {
        if std::env::var_os(NONINTERACTIVE_STDIN_HELPER_ENV).is_none() {
            return;
        }
        let mode = std::env::var_os(NONINTERACTIVE_STDIN_MODE_ENV)
            .expect("helper mode environment must be set");

        let workspace = tempdir().expect("create temp workspace");
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            GatewayPolicy {
                allow_isolation_none: true,
                enforce_allowlisted_program_for_mutation: false,
                ..GatewayPolicy::default()
            },
            ExecutionIsolation::None,
        );
        #[cfg(windows)]
        let program = workspace.path().join("stdin-helper.exe");
        #[cfg(not(windows))]
        let program = workspace.path().join("stdin-helper");
        write_test_executable_placeholder(&program);
        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        );

        match mode.to_string_lossy().as_ref() {
            "execute" => {
                let status = gateway
                    .execute_status(&request)
                    .expect("execute should not inherit blocking stdin");
                assert!(status.success());
            }
            "prepare" => {
                let (_event, result) = gateway.prepare_command(&request);
                let prepared = result.expect("prepare command");
                let mut prepared_child = prepared.spawn().expect("prepared command should spawn");
                let status = prepared_child
                    .child
                    .wait()
                    .expect("wait for prepared command");
                assert!(status.success());
            }
            other => panic!("unexpected helper mode: {other}"),
        }
    }

    #[cfg(unix)]
    fn run_noninteractive_stdin_helper(mode: &str) {
        let current_exe = std::env::current_exe().expect("current exe");
        let mut child = Command::new(current_exe)
            .arg("--exact")
            .arg("gateway::tests::noninteractive_stdin_helper")
            .arg("--nocapture")
            .env(NONINTERACTIVE_STDIN_HELPER_ENV, "1")
            .env(NONINTERACTIVE_STDIN_MODE_ENV, mode)
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn helper test process");
        let _blocking_stdin = child.stdin.take().expect("helper stdin");
        let status = wait_for_child_with_timeout(&mut child, Duration::from_secs(10));
        assert!(
            status.success(),
            "helper process should exit successfully, got {status}"
        );
    }

    #[cfg(unix)]
    fn wait_for_child_with_timeout(
        child: &mut std::process::Child,
        timeout: Duration,
    ) -> std::process::ExitStatus {
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait().expect("poll child status") {
                return status;
            }
            if start.elapsed() >= timeout {
                let _ = child.kill();
                let _ = child.wait();
                panic!("helper child did not exit before timeout");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_executable_explicit_program_paths() {
        use std::os::unix::fs::PermissionsExt;

        let policy = GatewayPolicy {
            allow_isolation_none: true,
            enforce_allowlisted_program_for_mutation: false,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("plain-script");
        fs::write(&program, "#!/usr/bin/env sh\nexit 0\n").expect("write plain script");
        let mut permissions = fs::metadata(&program).expect("metadata").permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(&program, permissions).expect("set permissions");

        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            ExecutionIsolation::None,
            workspace.path(),
        );

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("program_path_invalid"));
        assert!(matches!(
            result,
            Err(ExecError::ProgramPathInvalid { ref detail, .. })
                if detail == "program path must reference a spawnable executable"
        ));
    }
}
