use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use crate::audit::{ExecDecision, ExecEvent, requested_policy_meta};
use crate::audit_log::AuditLogger;
use crate::error::{ExecError, ExecResult};
use crate::policy::GatewayPolicy;
use crate::sandbox;
use crate::types::{ExecRequest, RequestResolution, RequestedIsolationSource};
use policy_meta::ExecutionIsolation;
use same_file::Handle as SameFileHandle;
use serde::Serialize;

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
#[must_use = "prepared commands must be spawned to apply validated cwd and sandbox state"]
pub struct PreparedCommand {
    command: Command,
    prepared: PreparedExecRequest,
}

impl ExecutionOutcome {
    pub fn into_parts(self) -> (ExecEvent, ExecResult<ExitStatus>) {
        (self.event, self.result)
    }
}

impl PreparedCommand {
    pub fn current_dir(&self) -> Option<&Path> {
        self.command.get_current_dir()
    }

    pub fn spawn(mut self) -> ExecResult<std::process::Child> {
        configure_noninteractive_stdio(&mut self.command);
        apply_prepared_request(&self.prepared, &mut self.command)
            .and_then(|_monitor| self.command.spawn().map_err(ExecError::Spawn))
    }
}

impl Default for ExecGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecGateway {
    pub fn new() -> Self {
        let policy = GatewayPolicy::default();
        Self::with_policy_and_supported_isolation(policy, sandbox::detect_supported_isolation())
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

    pub fn with_supported_isolation(supported_isolation: ExecutionIsolation) -> Self {
        Self::with_policy_and_supported_isolation(GatewayPolicy::default(), supported_isolation)
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
        let (event, result) = match self.prepare_request(request) {
            Ok(prepared) => {
                let mut command = Command::new(&prepared.bound_program.path);
                command.args(&request.args);
                configure_noninteractive_stdio(&mut command);
                let result = apply_prepared_request(&prepared, &mut command).and_then(|monitor| {
                    let mut child = command.spawn().map_err(ExecError::Spawn)?;
                    let sandbox_runtime = monitor.observe_after_spawn();
                    let status = child.wait().map_err(ExecError::Spawn)?;
                    Ok((sandbox_runtime, status))
                });
                match result {
                    Ok((sandbox_runtime, status)) => {
                        let mut event = prepared.event;
                        event.sandbox_runtime = sandbox_runtime;
                        (event, Ok(status))
                    }
                    Err(err) => (prepared.event, Err(err)),
                }
            }
            Err(err) => {
                let (event, err) = err.into_parts();
                (event, Err(err))
            }
        };
        let result = if let Some(audit) = &self.audit {
            let audit_result = audit.write_execution_record(&event, &result);
            combine_result_with_audit_write(result, audit_result)
        } else {
            result
        };
        ExecutionOutcome { event, result }
    }

    /// Convenience helper for callers that intentionally discard policy/audit metadata.
    pub fn execute_status(&self, request: &ExecRequest) -> ExecResult<ExitStatus> {
        self.execute(request).result
    }

    /// Validate command identity and return a spawn-only prepared wrapper.
    pub fn prepare_command(
        &self,
        request: &ExecRequest,
        command: Command,
    ) -> (ExecEvent, ExecResult<PreparedCommand>) {
        let (event, result) = match self.prepare_request(request) {
            Ok(prepared) => {
                match validate_prepared_command_matches_request(
                    prepared.bound_program.path.as_os_str(),
                    &request.args,
                    &command,
                ) {
                    Ok(()) => {
                        let mut command = command;
                        configure_noninteractive_stdio(&mut command);
                        command.current_dir(&prepared.resolved_paths.cwd.path);
                        let event = prepared.event.clone();
                        (event, Ok(PreparedCommand { command, prepared }))
                    }
                    Err(err) => {
                        let event = self.deny_event(prepared.event, "prepared_command_mismatch");
                        (event, Err(err))
                    }
                }
            }
            Err(err) => {
                let (event, err) = err.into_parts();
                (event, Err(err))
            }
        };
        let result = if let Some(audit) = &self.audit {
            let audit_result = audit.write_prepare_record(&event, &result);
            combine_result_with_audit_write(result, audit_result)
        } else {
            result
        };
        (event, result)
    }

    pub fn preflight(&self, request: &ExecRequest) -> Result<ExecEvent, PreflightError> {
        self.prepare_request(request).map(|prepared| prepared.event)
    }

    fn prepare_request(
        &self,
        request: &ExecRequest,
    ) -> Result<PreparedExecRequest, PreflightError> {
        let mut event = self.preflight_event(request);

        if matches!(
            request.requested_isolation_source,
            RequestedIsolationSource::PolicyDefault
        ) && request.required_isolation != self.policy.default_isolation
        {
            return Err(self.deny_preflight(
                event,
                "policy_default_isolation_mismatch",
                ExecError::PolicyDefaultIsolationMismatch {
                    requested: request.required_isolation,
                    policy_default: self.policy.default_isolation,
                },
            ));
        }

        if matches!(request.required_isolation, ExecutionIsolation::None)
            && !self.policy.allow_isolation_none
        {
            return Err(self.deny_preflight(
                event,
                "isolation_none_forbidden",
                ExecError::PolicyDenied("isolation none is forbidden by policy".to_string()),
            ));
        }

        if self.policy.enforce_allowlisted_program_for_mutation {
            if !request.declared_mutation_is_explicit() {
                return Err(self.deny_preflight(
                    event,
                    "mutation_declaration_required",
                    ExecError::MutationDeclarationRequired,
                ));
            }
            let program_is_allowlisted = self
                .policy
                .is_mutating_program_allowlisted_path(Path::new(&request.program));
            if request.declared_mutation && !program_is_allowlisted {
                return Err(self.deny_preflight(
                    event,
                    "mutation_requires_allowlisted_program",
                    ExecError::PolicyDenied(
                        "declared mutating command must use an allowlisted program".to_string(),
                    ),
                ));
            }
            if uses_opaque_command_launcher(&request.program) && !program_is_allowlisted {
                return Err(self.deny_preflight(
                    event,
                    "opaque_command_requires_allowlisted_program",
                    ExecError::PolicyDenied(
                        "opaque command launchers must use an allowlisted program".to_string(),
                    ),
                ));
            }
            if uses_known_mutating_program(&request.program) && !request.declared_mutation {
                return Err(self.deny_preflight(
                    event,
                    "known_mutating_program_requires_declared_mutation",
                    ExecError::PolicyDenied(
                        "known mutating tools must declare mutation".to_string(),
                    ),
                ));
            }
            if program_is_allowlisted && !request.declared_mutation {
                return Err(self.deny_preflight(
                    event,
                    "allowlisted_program_requires_declared_mutation",
                    ExecError::PolicyDenied(
                        "allowlisted mutating program must declare mutation".to_string(),
                    ),
                ));
            }
        }

        if request.required_isolation > self.supported_isolation {
            return Err(self.deny_preflight(
                event,
                "isolation_not_supported",
                ExecError::IsolationNotSupported {
                    requested: request.required_isolation,
                    supported: self.supported_isolation,
                },
            ));
        }

        if let Some(audit) = &self.audit
            && let Err(err) = audit.ensure_ready()
        {
            return Err(self.deny_preflight(event, "audit_log_unavailable", err));
        }

        match resolve_request_paths(&request.cwd, &request.workspace_root) {
            Ok(resolved_paths) => match bind_program_path(&request.program) {
                Ok(bound_program) => {
                    event.cwd = resolved_paths.cwd.path.clone();
                    event.workspace_root = resolved_paths.workspace_root.path.clone();
                    event.program = bound_program.path.clone().into();
                    Ok(PreparedExecRequest {
                        event,
                        required_isolation: request.required_isolation,
                        bound_program,
                        resolved_paths,
                    })
                }
                Err(err @ ExecError::RelativeProgramPath { .. }) => {
                    Err(self.deny_preflight(event, "relative_program_path_forbidden", err))
                }
                Err(
                    err @ ExecError::ProgramPathInvalid { .. }
                    | err @ ExecError::ProgramLookupFailed { .. },
                ) => Err(self.deny_preflight(event, "program_path_invalid", err)),
                Err(
                    err @ ExecError::PathIdentityUnavailable { .. }
                    | err @ ExecError::RequestPathChanged { .. },
                ) => Err(self.deny_preflight(event, "program_path_invalid", err)),
                Err(err) => {
                    unreachable!("bind_explicit_program_path returned unexpected error: {err}")
                }
            },
            Err(err @ ExecError::WorkspaceRootInvalid { .. }) => {
                Err(self.deny_preflight(event, "workspace_root_invalid", err))
            }
            Err(err @ ExecError::CwdInvalid { .. }) => {
                Err(self.deny_preflight(event, "cwd_invalid", err))
            }
            Err(
                err @ ExecError::CwdOutsideWorkspace { .. }
                | err @ ExecError::PathIdentityUnavailable { .. }
                | err @ ExecError::RequestPathChanged { .. },
            ) => Err(self.deny_preflight(event, "cwd_outside_workspace", err)),
            Err(err) => unreachable!("resolve_request_paths returned unexpected error: {err}"),
        }
    }

    fn preflight_event(&self, request: &ExecRequest) -> ExecEvent {
        ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: request.required_isolation,
            requested_policy_meta: requested_policy_meta(request.required_isolation),
            supported_isolation: self.supported_isolation,
            program: request.program.clone(),
            args: request.args.clone(),
            cwd: request.cwd.clone(),
            workspace_root: request.workspace_root.clone(),
            declared_mutation: request.declared_mutation,
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
}

fn uses_opaque_command_launcher(program: &OsStr) -> bool {
    program_basename_ascii(program).is_some_and(|normalized| {
        matches!(
            normalized.as_str(),
            "sh" | "bash"
                | "dash"
                | "zsh"
                | "fish"
                | "ksh"
                | "cmd"
                | "powershell"
                | "pwsh"
                | "python"
                | "python2"
                | "python3"
                | "node"
                | "deno"
                | "bun"
                | "ruby"
                | "perl"
                | "php"
                | "lua"
        )
    })
}

fn uses_known_mutating_program(program: &OsStr) -> bool {
    program_basename_ascii(program).is_some_and(|normalized| {
        matches!(
            normalized.as_str(),
            "git"
                | "make"
                | "gmake"
                | "cargo"
                | "go"
                | "npm"
                | "npx"
                | "pnpm"
                | "yarn"
                | "bun"
                | "pip"
                | "pip3"
                | "uv"
                | "apt"
                | "apt-get"
                | "dnf"
                | "yum"
                | "pacman"
                | "zypper"
                | "apk"
                | "brew"
                | "winget"
                | "choco"
                | "scoop"
                | "rm"
                | "mv"
                | "cp"
                | "install"
                | "mkdir"
                | "rmdir"
                | "touch"
                | "chmod"
                | "chown"
                | "chgrp"
                | "ln"
        )
    })
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
    value.strip_suffix(".exe").unwrap_or(&value).to_string()
}

fn canonicalize_workspace_root(path: &Path) -> ExecResult<PathBuf> {
    let canonical = path
        .canonicalize()
        .map_err(|_| ExecError::WorkspaceRootInvalid {
            path: path.to_path_buf(),
        })?;
    if !std::fs::metadata(&canonical)
        .map(|metadata| metadata.is_dir())
        .unwrap_or(false)
    {
        return Err(ExecError::WorkspaceRootInvalid { path: canonical });
    }
    Ok(canonical)
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
    let cwd = cwd.canonicalize().map_err(|err| ExecError::CwdInvalid {
        cwd: cwd.to_path_buf(),
        detail: err.to_string(),
    })?;
    let metadata = std::fs::metadata(&cwd).map_err(|err| ExecError::CwdInvalid {
        cwd: cwd.clone(),
        detail: err.to_string(),
    })?;
    if !metadata.is_dir() {
        return Err(ExecError::CwdInvalid {
            cwd,
            detail: "path is not a directory".to_string(),
        });
    }
    if !path_starts_with(&cwd, workspace_root) {
        return Err(ExecError::CwdOutsideWorkspace {
            cwd,
            workspace_root: workspace_root.to_path_buf(),
        });
    }

    Ok(cwd)
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
    let metadata =
        std::fs::metadata(requested_path).map_err(|err| ExecError::ProgramPathInvalid {
            path: requested_path.to_path_buf(),
            detail: err.to_string(),
        })?;
    if !metadata.is_file() {
        return Err(ExecError::ProgramPathInvalid {
            path: requested_path.to_path_buf(),
            detail: "program path must reference a regular file".to_string(),
        });
    }

    let identity = SameFileHandle::from_path(requested_path).map_err(|_| {
        ExecError::PathIdentityUnavailable {
            kind: "program",
            path: requested_path.to_path_buf(),
        }
    })?;
    Ok(BoundProgram {
        path: requested_path.to_path_buf(),
        identity,
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

fn apply_prepared_request(
    prepared: &PreparedExecRequest,
    command: &mut Command,
) -> ExecResult<sandbox::SandboxMonitor> {
    revalidate_bound_program(&prepared.bound_program)?;
    revalidate_prepared_request_paths(&prepared.resolved_paths)?;
    command.current_dir(&prepared.resolved_paths.cwd.path);
    sandbox::apply_sandbox(
        command,
        prepared.required_isolation,
        &prepared.resolved_paths.workspace_root.path,
    )
}

fn configure_noninteractive_stdio(command: &mut Command) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
}

fn validate_prepared_command_matches_request(
    requested_program: &OsStr,
    requested_args: &[OsString],
    command: &Command,
) -> ExecResult<()> {
    let actual_program = command.get_program();
    let actual_args = command.get_args().collect::<Vec<&OsStr>>();
    let requested_args = requested_args
        .iter()
        .map(OsString::as_os_str)
        .collect::<Vec<_>>();

    if !programs_match(actual_program, requested_program) || actual_args != requested_args {
        return Err(ExecError::PreparedCommandMismatch {
            requested_program: requested_program.to_string_lossy().into_owned(),
            requested_args: requested_args
                .iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect(),
            actual_program: actual_program.to_string_lossy().into_owned(),
            actual_args: actual_args
                .into_iter()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect(),
        });
    }

    Ok(())
}

fn is_explicit_program_path(program: &OsStr) -> bool {
    let path = Path::new(program);
    path.is_absolute()
        || program
            .to_string_lossy()
            .chars()
            .any(|ch| ch == '/' || ch == '\\')
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
    #[cfg(not(windows))]
    let candidate_dirs = [
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/opt/homebrew/bin",
        "/opt/local/bin",
    ];
    #[cfg(windows)]
    let candidate_dirs: [&str; 0] = [];

    for dir in candidate_dirs {
        if let Some(path) = resolve_bare_program_in_dir(program, Path::new(dir)) {
            return Some(path);
        }
    }
    None
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

#[cfg(windows)]
fn programs_match(actual: &OsStr, requested: &OsStr) -> bool {
    let actual_path = Path::new(actual);
    let requested_path = Path::new(requested);
    if actual_path.is_absolute() && requested_path.is_absolute() {
        return explicit_program_paths_match(actual_path, requested_path);
    }
    if actual_path.components().count() > 1 || requested_path.components().count() > 1 {
        return path_equals(actual_path, requested_path);
    }

    let actual = actual.to_string_lossy();
    let requested = requested.to_string_lossy();
    actual.eq_ignore_ascii_case(&requested)
        || strip_windows_exe_suffix(&actual)
            .eq_ignore_ascii_case(strip_windows_exe_suffix(&requested))
}

#[cfg(not(windows))]
fn programs_match(actual: &OsStr, requested: &OsStr) -> bool {
    let actual_path = Path::new(actual);
    let requested_path = Path::new(requested);
    if actual_path.is_absolute() && requested_path.is_absolute() {
        return explicit_program_paths_match(actual_path, requested_path);
    }
    actual == requested
}

#[cfg(windows)]
fn strip_windows_exe_suffix(value: &str) -> &str {
    value.strip_suffix(".exe").unwrap_or(value)
}

fn explicit_program_paths_match(actual: &Path, requested: &Path) -> bool {
    same_file::is_same_file(actual, requested).unwrap_or(false) || path_equals(actual, requested)
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

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;
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
    #[test]
    fn known_mutating_detection_rejects_non_utf8_basename() {
        let program = OsString::from_vec(vec![0x67, 0x69, 0x74, 0x80]);
        assert!(!uses_known_mutating_program(program.as_os_str()));
    }

    #[cfg(unix)]
    #[test]
    fn opaque_launcher_detection_rejects_non_utf8_basename() {
        let program = OsString::from_vec(vec![0x70, 0x79, 0x74, 0x68, 0x6f, 0x6e, 0x80]);
        assert!(!uses_opaque_command_launcher(program.as_os_str()));
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

    #[cfg(unix)]
    #[test]
    fn preserves_requested_symlink_program_paths_in_events() {
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
        fs::write(&target, "#!/bin/sh\nexit 0\n").expect("write tool");
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
        assert_eq!(event.program, symlink_path);
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
    fn preflight_denies_when_audit_log_parent_is_not_directory() {
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

        let err = gateway
            .preflight(&request)
            .expect_err("unwritable audit log should deny request");
        let (event, err) = err.into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("audit_log_unavailable"));
        match err {
            ExecError::AuditLogUnavailable { .. } => {}
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn preflight_creates_missing_audit_log_parent_directories() {
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

        let event = gateway.preflight(&request).expect("preflight should pass");
        assert_eq!(event.decision, ExecDecision::Run);
        assert!(
            audit_path.exists(),
            "audit file should be created during preflight"
        );
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
        let command = Command::new(dummy_program());
        let (event, result) = gateway.prepare_command(&request, command);

        assert_eq!(event.reason, evaluated.reason);
        assert_eq!(event.decision, evaluated.decision);
        assert!(matches!(result, Err(ExecError::CwdOutsideWorkspace { .. })));
    }

    #[test]
    fn denies_mutation_for_non_allowlisted_program() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            dummy_program(),
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
    fn requires_explicit_mutation_declaration_for_non_allowlisted_programs() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
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
            Some("mutation_declaration_required")
        );
        assert!(matches!(
            result,
            Err(ExecError::MutationDeclarationRequired)
        ));
    }

    #[test]
    fn allows_mutation_for_explicitly_allowlisted_program_path() {
        let program = allowlisted_program_path();
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec![program.to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            program,
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
    fn denies_mutation_for_bare_program_even_when_same_name_is_allowlisted() {
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec!["omne-fs".to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "omne-fs",
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
        fs::write(&program, "placeholder").expect("write program placeholder");
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
        assert_eq!(
            event.reason.as_deref(),
            Some("opaque_command_requires_allowlisted_program")
        );
    }

    #[test]
    fn denies_known_mutating_bare_program_without_declared_mutation() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "git",
            vec!["status"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let (event, result) = gateway.execute(&request).into_parts();
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("known_mutating_program_requires_declared_mutation")
        );
        assert!(matches!(result, Err(ExecError::PolicyDenied(_))));
    }

    #[test]
    fn denies_known_mutating_explicit_program_without_declared_mutation() {
        let gateway = ExecGateway::with_supported_isolation(ExecutionIsolation::BestEffort);
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("git");
        fs::write(&program, "placeholder").expect("write program placeholder");
        let request = ExecRequest::new(
            &program,
            vec!["status"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(false);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(
            event.reason.as_deref(),
            Some("known_mutating_program_requires_declared_mutation")
        );
    }

    #[test]
    fn allows_known_mutating_program_when_declared_and_allowlisted() {
        let workspace = tempdir().expect("create temp workspace");
        let program = workspace.path().join("git");
        fs::write(&program, "placeholder").expect("write program placeholder");
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
            vec!["status"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(true);

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
        assert_eq!(
            event.reason.as_deref(),
            Some("opaque_command_requires_allowlisted_program")
        );
    }

    #[test]
    fn allows_opaque_command_launcher_when_explicitly_allowlisted() {
        #[cfg(windows)]
        let program = r"C:\Windows\System32\cmd.exe";
        #[cfg(not(windows))]
        let program = "/bin/sh";
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec![program.to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            program,
            vec![dummy_shell_flag(), "echo hello"],
            workspace.path(),
            ExecutionIsolation::BestEffort,
            workspace.path(),
        )
        .with_declared_mutation(true);

        let event = gateway.evaluate(&request);
        assert_eq!(event.decision, ExecDecision::Run);
    }

    #[test]
    fn denies_explicitly_allowlisted_program_without_declared_mutation() {
        let program = allowlisted_program_path();
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec![program.to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            ExecutionIsolation::BestEffort,
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            program,
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
        let command = Command::new(resolved_non_mutating_program_path());
        let (_event, result) = gateway.prepare_command(&request, command);
        let prepared = result.expect("prepare command");
        let expected_cwd = workspace
            .path()
            .canonicalize()
            .expect("canonicalize workspace");
        assert_eq!(prepared.current_dir(), Some(expected_cwd.as_path()));
    }

    #[test]
    fn prepare_command_denies_unbound_bare_command() {
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

        let command = Command::new(non_mutating_program());
        let (event, result) = gateway.prepare_command(&request, command);

        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("prepared_command_mismatch"));
        assert!(matches!(
            result,
            Err(ExecError::PreparedCommandMismatch { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn prepared_command_fails_closed_when_program_identity_changes_before_spawn() {
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
        let program = workspace.path().join("tool.sh");
        let replacement = workspace.path().join("tool-replacement.sh");
        fs::write(&program, "#!/bin/sh\nexit 0\n").expect("write program");
        fs::write(&replacement, "#!/bin/sh\nexit 1\n").expect("write replacement");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755)).expect("chmod program");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755))
            .expect("chmod replacement");

        let request = ExecRequest::new(
            &program,
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(false);
        let command = Command::new(&program);

        let (_event, result) = gateway.prepare_command(&request, command);
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
    }

    #[test]
    fn prepare_command_denies_mismatched_command_identity() {
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let workspace = tempdir().expect("create temp workspace");
        let request = ExecRequest::new(
            "echo",
            vec!["hello"],
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(false);
        let mut command = Command::new("printf");
        command.arg("hello");

        let (event, result) = gateway.prepare_command(&request, command);
        assert_eq!(event.decision, ExecDecision::Deny);
        assert_eq!(event.reason.as_deref(), Some("prepared_command_mismatch"));
        assert!(matches!(
            result,
            Err(ExecError::PreparedCommandMismatch { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_command_canonicalizes_symlink_cwd() {
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
        let command = Command::new(resolved_non_mutating_program_path());
        let (event, result) = gateway.prepare_command(&request, command);
        let prepared = result.expect("prepare command");
        let expected_cwd = real_dir.canonicalize().expect("canonicalize real dir");
        assert_eq!(event.cwd, expected_cwd);
        assert_eq!(prepared.current_dir(), Some(expected_cwd.as_path()));
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

    #[cfg(unix)]
    #[test]
    fn prepared_command_fails_closed_when_cwd_identity_changes_before_spawn() {
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
        let moved = workspace.path().join("cwd-moved");
        fs::create_dir_all(&cwd).expect("create cwd");

        let request = ExecRequest::new(
            "sh",
            vec!["-c", "exit 0"],
            &cwd,
            host_supported_test_isolation(),
            workspace.path(),
        );
        let mut command = Command::new(dummy_program_absolute_path());
        command.args(["-c", "exit 0"]);

        let (_event, result) = gateway.prepare_command(&request, command);
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
    }

    #[cfg(windows)]
    #[test]
    fn prepare_command_allows_case_insensitive_windows_program_match() {
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
            r"C:\Windows\System32\CMD.EXE",
            Vec::<OsString>::new(),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        );
        let command = Command::new(r"c:\windows\system32\cmd.exe");

        let (event, result) = gateway.prepare_command(&request, command);
        assert_eq!(event.decision, ExecDecision::Run);
        assert!(result.is_ok());
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
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            audit_log_path: Some(audit_path.clone()),
            mutating_program_allowlist: vec![shell_exit_nonzero_command().0.to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let (program, args) = shell_exit_nonzero_command();
        let request = ExecRequest::new(
            program,
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

    #[test]
    fn execute_status_fails_when_audit_write_breaks_after_preflight() {
        let workspace = tempdir().expect("create temp workspace");
        let audit_path = canonical_test_root(&workspace).join("audit.jsonl");
        let policy = GatewayPolicy {
            allow_isolation_none: true,
            audit_log_path: Some(audit_path.clone()),
            mutating_program_allowlist: vec![audit_breaking_shell_program().to_string()],
            ..GatewayPolicy::default()
        };
        let gateway = ExecGateway::with_policy_and_supported_isolation(
            policy,
            host_supported_test_isolation(),
        );
        let request = ExecRequest::new(
            audit_breaking_shell_program(),
            audit_breaking_shell_args(&audit_path),
            workspace.path(),
            host_supported_test_isolation(),
            workspace.path(),
        )
        .with_declared_mutation(true);

        let err = gateway
            .execute_status(&request)
            .expect_err("audit write failure should be surfaced");
        match err {
            ExecError::AuditLogWriteFailed { path, .. } => assert_eq!(path, audit_path),
            other => panic!("unexpected error: {other}"),
        }
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

    #[cfg(windows)]
    fn dummy_program() -> &'static str {
        "cmd"
    }

    #[cfg(not(windows))]
    fn dummy_program() -> &'static str {
        "sh"
    }

    fn non_mutating_program() -> &'static str {
        "whoami"
    }

    fn resolved_non_mutating_program_path() -> PathBuf {
        resolve_bare_program_path(OsStr::new(non_mutating_program()))
            .expect("resolve non-mutating test program")
    }

    #[cfg(windows)]
    fn dummy_program_absolute_path() -> &'static str {
        r"C:\Windows\System32\cmd.exe"
    }

    #[cfg(not(windows))]
    fn dummy_program_absolute_path() -> &'static str {
        "/bin/sh"
    }

    #[cfg(windows)]
    fn interpreter_program() -> &'static str {
        "python.exe"
    }

    #[cfg(not(windows))]
    fn interpreter_program() -> &'static str {
        "python3"
    }

    fn allowlisted_program_path() -> &'static str {
        dummy_program_absolute_path()
    }

    #[cfg(windows)]
    fn non_allowlisted_program_path(workspace: &tempfile::TempDir) -> PathBuf {
        workspace.path().join("other.exe")
    }

    #[cfg(not(windows))]
    fn non_allowlisted_program_path(workspace: &tempfile::TempDir) -> PathBuf {
        workspace.path().join("other")
    }

    #[cfg(windows)]
    fn shell_exit_nonzero_command() -> (&'static str, Vec<&'static str>) {
        (r"C:\Windows\System32\cmd.exe", vec!["/C", "exit 1"])
    }

    #[cfg(not(windows))]
    fn shell_exit_nonzero_command() -> (&'static str, Vec<&'static str>) {
        ("/bin/sh", vec!["-c", "exit 1"])
    }

    #[cfg(windows)]
    fn audit_breaking_shell_program() -> &'static str {
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    }

    #[cfg(not(windows))]
    fn audit_breaking_shell_program() -> &'static str {
        "/bin/sh"
    }

    #[cfg(windows)]
    fn audit_breaking_shell_args(audit_path: &Path) -> Vec<OsString> {
        let quoted_audit_path = audit_path.to_string_lossy().replace('\'', "''");
        vec![
            OsString::from("-NoProfile"),
            OsString::from("-Command"),
            OsString::from(format!(
                "if (Test-Path -LiteralPath '{0}') {{ Remove-Item -LiteralPath '{0}' -Force }}; New-Item -ItemType Directory -Path '{0}' | Out-Null; exit 0",
                quoted_audit_path
            )),
        ]
    }

    #[cfg(not(windows))]
    fn audit_breaking_shell_args(audit_path: &Path) -> Vec<OsString> {
        vec![
            OsString::from("-c"),
            OsString::from(format!("rm \"{0}\" && mkdir \"{0}\"", audit_path.display())),
        ]
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
        let request = ExecRequest::new(
            "/bin/sh",
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
                let command = Command::new("/bin/sh");
                let (_event, result) = gateway.prepare_command(&request, command);
                let prepared = result.expect("prepare command");
                let status = prepared
                    .spawn()
                    .expect("prepared command should spawn")
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
        let status = wait_for_child_with_timeout(&mut child, Duration::from_secs(3));
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
}
