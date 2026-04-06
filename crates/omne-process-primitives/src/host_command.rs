use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use omne_system_package_primitives::SystemPackageManager;
use tempfile::tempfile;

use crate::command_path::{
    is_spawnable_command_path, resolve_command_path_in_standard_locations_os,
    resolve_command_path_os, resolve_command_path_os_with_path_var_and_base_dir,
};

const DEFAULT_CAPTURED_OUTPUT_BYTES_PER_STREAM: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCommandSudoMode {
    Never,
    IfNonRootSystemCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCommandExecution {
    Direct,
    Sudo,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HostCommandRunOptions<'a> {
    pub env_remove: &'a [OsString],
    pub timeout: Option<Duration>,
}

impl<'a> HostCommandRunOptions<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_env_remove(mut self, env_remove: &'a [OsString]) -> Self {
        self.env_remove = env_remove;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HostCommandCaptureOptions {
    pub max_captured_output_bytes_per_stream: Option<usize>,
}

impl Default for HostCommandCaptureOptions {
    fn default() -> Self {
        Self {
            max_captured_output_bytes_per_stream: Some(DEFAULT_CAPTURED_OUTPUT_BYTES_PER_STREAM),
        }
    }
}

impl HostCommandCaptureOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capture_limit_bytes_per_stream(mut self, max_bytes: usize) -> Self {
        self.max_captured_output_bytes_per_stream = Some(max_bytes);
        self
    }

    pub fn without_capture_limit(mut self) -> Self {
        self.max_captured_output_bytes_per_stream = None;
        self
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HostCommandRequest<'a> {
    pub program: &'a OsStr,
    pub args: &'a [OsString],
    pub env: &'a [(OsString, OsString)],
    pub working_directory: Option<&'a Path>,
    pub sudo_mode: HostCommandSudoMode,
}

#[derive(Debug)]
pub struct HostCommandOutput {
    pub execution: HostCommandExecution,
    pub output: Output,
}

#[derive(Debug, Clone, Copy)]
pub struct HostRecipeRequest<'a> {
    pub program: &'a OsStr,
    pub args: &'a [OsString],
    pub env: &'a [(OsString, OsString)],
    pub working_directory: Option<&'a Path>,
    pub sudo_mode: HostCommandSudoMode,
}

impl<'a> HostRecipeRequest<'a> {
    pub fn new(program: &'a OsStr, args: &'a [OsString]) -> Self {
        Self {
            program,
            args,
            env: &[],
            working_directory: None,
            sudo_mode: default_recipe_sudo_mode_for_program(program),
        }
    }

    pub fn with_env(mut self, env: &'a [(OsString, OsString)]) -> Self {
        self.env = env;
        self
    }

    pub fn with_working_directory(mut self, working_directory: &'a Path) -> Self {
        self.working_directory = Some(working_directory);
        self
    }

    pub fn with_sudo_mode(mut self, sudo_mode: HostCommandSudoMode) -> Self {
        self.sudo_mode = sudo_mode;
        self
    }
}

#[derive(Debug)]
pub enum HostCommandError {
    CommandNotFound {
        program: OsString,
    },
    SpawnFailed {
        program: OsString,
        execution: HostCommandExecution,
        source: io::Error,
    },
    CaptureFailed {
        program: OsString,
        execution: HostCommandExecution,
        source: io::Error,
    },
    TimedOut {
        program: OsString,
        execution: HostCommandExecution,
        timeout: Duration,
        output: Output,
    },
}

#[derive(Debug)]
pub enum HostRecipeError {
    Command(HostCommandError),
    NonZeroExit {
        program: OsString,
        execution: HostCommandExecution,
        output: Output,
    },
}

impl fmt::Display for HostCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandNotFound { program } => {
                write!(f, "command not found: {}", program.to_string_lossy())
            }
            Self::SpawnFailed {
                program,
                execution,
                source,
            } => match execution {
                HostCommandExecution::Direct => {
                    write!(f, "run {} failed: {source}", program.to_string_lossy())
                }
                HostCommandExecution::Sudo => {
                    write!(
                        f,
                        "run sudo -n {} failed: {source}",
                        program.to_string_lossy()
                    )
                }
            },
            Self::CaptureFailed {
                program,
                execution,
                source,
            } => match execution {
                HostCommandExecution::Direct => write!(
                    f,
                    "capture output from {} failed: {source}",
                    program.to_string_lossy()
                ),
                HostCommandExecution::Sudo => write!(
                    f,
                    "capture output from sudo -n {} failed: {source}",
                    program.to_string_lossy()
                ),
            },
            Self::TimedOut {
                program,
                execution,
                timeout,
                output,
            } => match execution {
                HostCommandExecution::Direct => write!(
                    f,
                    "run {} timed out after {timeout:?}: status={} stderr_bytes={} stdout_bytes={}",
                    program.to_string_lossy(),
                    output.status,
                    output.stderr.len(),
                    output.stdout.len(),
                ),
                HostCommandExecution::Sudo => write!(
                    f,
                    "run sudo -n {} timed out after {timeout:?}: status={} stderr_bytes={} stdout_bytes={}",
                    program.to_string_lossy(),
                    output.status,
                    output.stderr.len(),
                    output.stdout.len(),
                ),
            },
        }
    }
}

impl std::error::Error for HostCommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CommandNotFound { .. } => None,
            Self::SpawnFailed { source, .. } | Self::CaptureFailed { source, .. } => Some(source),
            Self::TimedOut { .. } => None,
        }
    }
}

impl fmt::Display for HostRecipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(source) => fmt::Display::fmt(source, f),
            Self::NonZeroExit {
                program,
                execution,
                output,
            } => match execution {
                HostCommandExecution::Direct => write!(
                    f,
                    "run {} failed: status={} stderr_bytes={} stdout_bytes={}",
                    program.to_string_lossy(),
                    output.status,
                    output.stderr.len(),
                    output.stdout.len(),
                ),
                HostCommandExecution::Sudo => write!(
                    f,
                    "run sudo -n {} failed: status={} stderr_bytes={} stdout_bytes={}",
                    program.to_string_lossy(),
                    output.status,
                    output.stderr.len(),
                    output.stdout.len(),
                ),
            },
        }
    }
}

impl std::error::Error for HostRecipeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Command(source) => Some(source),
            Self::NonZeroExit { .. } => None,
        }
    }
}

pub fn run_host_command(
    request: &HostCommandRequest<'_>,
) -> Result<HostCommandOutput, HostCommandError> {
    run_host_command_with_capture_options(
        request,
        HostCommandRunOptions::default(),
        HostCommandCaptureOptions::default(),
    )
}

pub fn run_host_command_with_options(
    request: &HostCommandRequest<'_>,
    options: HostCommandRunOptions<'_>,
) -> Result<HostCommandOutput, HostCommandError> {
    run_host_command_with_capture_options(request, options, HostCommandCaptureOptions::default())
}

pub fn run_host_command_with_capture_options(
    request: &HostCommandRequest<'_>,
    options: HostCommandRunOptions<'_>,
    capture_options: HostCommandCaptureOptions,
) -> Result<HostCommandOutput, HostCommandError> {
    validate_direct_request_program(request)?;
    let execution = if should_try_sudo(request) {
        HostCommandExecution::Sudo
    } else {
        HostCommandExecution::Direct
    };
    if execution == HostCommandExecution::Sudo {
        ensure_sudo_target_is_available(request)?;
    }
    let output = run_command_output(request, execution, options, capture_options)
        .map_err(|source| map_command_output_error(request, execution, source))?;
    Ok(HostCommandOutput { execution, output })
}

pub fn run_host_recipe(
    request: &HostRecipeRequest<'_>,
) -> Result<HostCommandOutput, HostRecipeError> {
    run_host_recipe_with_capture_options(
        request,
        HostCommandRunOptions::default(),
        HostCommandCaptureOptions::default(),
    )
}

pub fn run_host_recipe_with_options(
    request: &HostRecipeRequest<'_>,
    options: HostCommandRunOptions<'_>,
) -> Result<HostCommandOutput, HostRecipeError> {
    run_host_recipe_with_capture_options(request, options, HostCommandCaptureOptions::default())
}

pub fn run_host_recipe_with_capture_options(
    request: &HostRecipeRequest<'_>,
    options: HostCommandRunOptions<'_>,
    capture_options: HostCommandCaptureOptions,
) -> Result<HostCommandOutput, HostRecipeError> {
    let output = run_host_command_with_capture_options(
        &HostCommandRequest {
            program: request.program,
            args: request.args,
            env: request.env,
            working_directory: request.working_directory,
            sudo_mode: request.sudo_mode,
        },
        options,
        capture_options,
    )
    .map_err(HostRecipeError::Command)?;

    if output.output.status.success() {
        return Ok(output);
    }

    Err(HostRecipeError::NonZeroExit {
        program: request.program.to_os_string(),
        execution: output.execution,
        output: output.output,
    })
}

pub fn command_exists(command: &str) -> bool {
    command_exists_os(OsStr::new(command))
}

pub fn command_exists_os(command: &OsStr) -> bool {
    if is_explicit_command_path(command) {
        return is_spawnable_command_path(Path::new(command));
    }
    resolve_command_path_os(command).is_some()
}

pub fn command_path_exists(command: &Path) -> bool {
    is_spawnable_command_path(command)
}

pub fn command_available(command: &str) -> bool {
    let command_os = OsStr::new(command);
    if is_explicit_command_path(command_os) {
        return is_spawnable_command_path(Path::new(command_os));
    }
    resolve_command_path_os(command_os).is_some()
}

pub fn command_available_os(command: &OsStr) -> bool {
    if is_explicit_command_path(command) {
        return is_spawnable_command_path(Path::new(command));
    }
    resolve_command_path_os(command).is_some()
}

pub fn command_exists_for_request(request: &HostCommandRequest<'_>) -> bool {
    resolve_program_for_direct_command(request).is_some_and(|path| is_spawnable_command_path(&path))
}

pub fn command_available_for_request(request: &HostCommandRequest<'_>) -> bool {
    resolve_program_for_direct_command(request).is_some_and(|path| is_spawnable_command_path(&path))
}

pub fn default_recipe_sudo_mode_for_program(program: &OsStr) -> HostCommandSudoMode {
    sudo_mode_system_package_manager(program)
        .filter(|manager| manager_requires_privileged_install(*manager))
        .map_or(HostCommandSudoMode::Never, |_| {
            HostCommandSudoMode::IfNonRootSystemCommand
        })
}

#[cfg(test)]
fn build_command(request: &HostCommandRequest<'_>, execution: HostCommandExecution) -> Command {
    build_command_with_options(request, execution, HostCommandRunOptions::default())
}

fn build_command_with_options(
    request: &HostCommandRequest<'_>,
    execution: HostCommandExecution,
    options: HostCommandRunOptions<'_>,
) -> Command {
    let mut cmd = match execution {
        HostCommandExecution::Direct => Command::new(resolve_program_for_direct_spawn(request)),
        HostCommandExecution::Sudo => {
            let mut cmd = Command::new(resolve_sudo_program());
            cmd.arg("-n");
            append_sudo_target_command(
                &mut cmd,
                &resolve_program_for_sudo_target(request),
                request,
            );
            cmd
        }
    };
    for name in options.env_remove {
        cmd.env_remove(name);
    }
    if execution == HostCommandExecution::Direct {
        for arg in request.args {
            cmd.arg(arg);
        }
        for (name, value) in request.env {
            cmd.env(name, value);
        }
    }
    if let Some(working_directory) = resolved_working_directory_for_request(request) {
        cmd.current_dir(working_directory);
    }
    cmd.stdin(Stdio::null());
    cmd
}

fn append_sudo_target_command(
    command: &mut Command,
    program: &Path,
    request: &HostCommandRequest<'_>,
) {
    let _ = request;
    command.arg(program);
    for arg in request.args {
        command.arg(arg);
    }
}

fn run_command_output(
    request: &HostCommandRequest<'_>,
    execution: HostCommandExecution,
    options: HostCommandRunOptions<'_>,
    capture_options: HostCommandCaptureOptions,
) -> Result<Output, CommandOutputError> {
    #[cfg(unix)]
    {
        const EXECUTABLE_BUSY_RETRIES: usize = 3;
        const EXECUTABLE_BUSY_BACKOFF_MS: u64 = 10;

        for attempt in 0..=EXECUTABLE_BUSY_RETRIES {
            match spawn_and_capture_output(request, execution, options, capture_options) {
                Ok(output) => return Ok(output),
                Err(err) if err.is_executable_file_busy() && attempt < EXECUTABLE_BUSY_RETRIES => {
                    std::thread::sleep(std::time::Duration::from_millis(
                        EXECUTABLE_BUSY_BACKOFF_MS,
                    ));
                }
                Err(err) => return Err(err),
            }
        }

        unreachable!("retry loop must return on success or final error");
    }

    #[cfg(not(unix))]
    {
        spawn_and_capture_output(request, execution, options, capture_options)
    }
}

fn spawn_and_capture_output(
    request: &HostCommandRequest<'_>,
    execution: HostCommandExecution,
    options: HostCommandRunOptions<'_>,
    capture_options: HostCommandCaptureOptions,
) -> Result<Output, CommandOutputError> {
    let (stdout_capture, stdout_writer) =
        create_output_capture_file().map_err(CommandOutputError::Spawn)?;
    let (stderr_capture, stderr_writer) =
        create_output_capture_file().map_err(CommandOutputError::Spawn)?;
    let mut command = build_command_with_options(request, execution, options);
    command.stdout(Stdio::from(stdout_writer));
    command.stderr(Stdio::from(stderr_writer));
    let mut child = command.spawn().map_err(CommandOutputError::Spawn)?;
    let status = match wait_for_child(
        &mut child,
        options.timeout,
        capture_options.max_captured_output_bytes_per_stream,
        &stdout_capture,
        &stderr_capture,
    ) {
        Ok(status) => status,
        Err(CommandOutputError::TimedOut {
            timeout,
            output: timed_out_output,
        }) => {
            let stdout = read_captured_output(
                stdout_capture,
                "stdout",
                capture_options.max_captured_output_bytes_per_stream,
            )
            .map_err(CommandOutputError::Capture)?;
            let stderr = read_captured_output(
                stderr_capture,
                "stderr",
                capture_options.max_captured_output_bytes_per_stream,
            )
            .map_err(CommandOutputError::Capture)?;
            return Err(CommandOutputError::TimedOut {
                timeout,
                output: Output {
                    status: timed_out_output.status,
                    stdout,
                    stderr,
                },
            });
        }
        Err(err) => return Err(err),
    };
    Ok(Output {
        status,
        stdout: read_captured_output(
            stdout_capture,
            "stdout",
            capture_options.max_captured_output_bytes_per_stream,
        )
        .map_err(CommandOutputError::Capture)?,
        stderr: read_captured_output(
            stderr_capture,
            "stderr",
            capture_options.max_captured_output_bytes_per_stream,
        )
        .map_err(CommandOutputError::Capture)?,
    })
}

fn create_output_capture_file() -> io::Result<(File, File)> {
    let capture = tempfile()?;
    let writer = capture.try_clone()?;
    Ok((capture, writer))
}

fn wait_for_child(
    child: &mut std::process::Child,
    timeout: Option<Duration>,
    capture_limit_bytes_per_stream: Option<usize>,
    stdout_capture: &File,
    stderr_capture: &File,
) -> Result<std::process::ExitStatus, CommandOutputError> {
    const POLL_INTERVAL: Duration = Duration::from_millis(50);

    let deadline = timeout.map(|timeout| Instant::now() + timeout);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(source) => return Err(CommandOutputError::Spawn(source)),
        }

        if let Some(stream_name) = capture_limit_exceeded(
            stdout_capture,
            stderr_capture,
            capture_limit_bytes_per_stream,
        )
        .map_err(CommandOutputError::Spawn)?
        {
            terminate_child_after_capture_limit(
                child,
                stream_name,
                capture_limit_bytes_per_stream,
            )?;
            return Err(CommandOutputError::Capture(capture_limit_error(
                stream_name,
                capture_limit_bytes_per_stream,
            )));
        }

        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            let timeout = timeout.expect("deadline implies timeout");
            let _ = child.kill();
            let status = child.wait().map_err(|source| {
                CommandOutputError::Spawn(io::Error::other(format!(
                    "timed out after {timeout:?} and wait failed: {source}"
                )))
            })?;
            return Err(CommandOutputError::TimedOut {
                timeout,
                output: Output {
                    status,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                },
            });
        }

        std::thread::sleep(POLL_INTERVAL);
    }
}

fn capture_limit_exceeded(
    stdout_capture: &File,
    stderr_capture: &File,
    capture_limit_bytes_per_stream: Option<usize>,
) -> io::Result<Option<&'static str>> {
    if capture_file_exceeded_limit(stdout_capture, capture_limit_bytes_per_stream)? {
        return Ok(Some("stdout"));
    }
    if capture_file_exceeded_limit(stderr_capture, capture_limit_bytes_per_stream)? {
        return Ok(Some("stderr"));
    }
    Ok(None)
}

fn capture_file_exceeded_limit(capture: &File, max_bytes: Option<usize>) -> io::Result<bool> {
    let Some(max_bytes) = max_bytes else {
        return Ok(false);
    };
    Ok(capture.metadata()?.len() > max_bytes as u64)
}

fn terminate_child_after_capture_limit(
    child: &mut std::process::Child,
    stream_name: &'static str,
    capture_limit_bytes_per_stream: Option<usize>,
) -> Result<(), CommandOutputError> {
    let _ = child.kill();
    child.wait().map_err(|source| {
        CommandOutputError::Spawn(io::Error::other(format!(
            "{} and wait failed: {source}",
            capture_limit_message(stream_name, capture_limit_bytes_per_stream),
        )))
    })?;
    Ok(())
}

fn capture_limit_error(
    stream_name: &'static str,
    capture_limit_bytes_per_stream: Option<usize>,
) -> io::Error {
    io::Error::other(capture_limit_message(
        stream_name,
        capture_limit_bytes_per_stream,
    ))
}

fn capture_limit_message(
    stream_name: &'static str,
    capture_limit_bytes_per_stream: Option<usize>,
) -> String {
    let limit = capture_limit_bytes_per_stream.unwrap_or(DEFAULT_CAPTURED_OUTPUT_BYTES_PER_STREAM);
    format!("{stream_name} exceeded capture limit of {limit} bytes")
}

fn read_captured_output(
    mut capture: File,
    stream_name: &'static str,
    capture_limit_bytes_per_stream: Option<usize>,
) -> io::Result<Vec<u8>> {
    capture.seek(SeekFrom::Start(0))?;
    read_stream_limited(&mut capture, stream_name, capture_limit_bytes_per_stream)
}

fn read_stream_limited<R>(
    mut reader: R,
    stream_name: &'static str,
    capture_limit_bytes_per_stream: Option<usize>,
) -> io::Result<Vec<u8>>
where
    R: Read,
{
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];
    let mut exceeded_capture_limit = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        match capture_limit_bytes_per_stream {
            Some(limit) => {
                let remaining = limit.saturating_sub(bytes.len());
                let to_copy = remaining.min(read);
                bytes.extend_from_slice(&buffer[..to_copy]);
                if to_copy < read {
                    exceeded_capture_limit = true;
                }
            }
            None => bytes.extend_from_slice(&buffer[..read]),
        }
    }
    if exceeded_capture_limit {
        return Err(capture_limit_error(
            stream_name,
            capture_limit_bytes_per_stream,
        ));
    }
    Ok(bytes)
}

fn should_try_sudo(request: &HostCommandRequest<'_>) -> bool {
    should_try_sudo_for_request_with_status(request, unix_process_is_non_root())
}

fn should_try_sudo_for_request_with_status(
    request: &HostCommandRequest<'_>,
    process_is_non_root: bool,
) -> bool {
    should_try_sudo_with_status(
        request.program,
        request.sudo_mode,
        process_is_non_root,
        sudo_available(),
    )
}

fn should_try_sudo_with_status(
    program: &OsStr,
    sudo_mode: HostCommandSudoMode,
    process_is_non_root: bool,
    sudo_available: bool,
) -> bool {
    if sudo_mode != HostCommandSudoMode::IfNonRootSystemCommand {
        return false;
    }
    if !process_is_non_root || !sudo_available {
        return false;
    }
    sudo_eligible_program(program)
}

#[cfg(unix)]
fn unix_process_is_non_root() -> bool {
    !rustix::process::geteuid().is_root()
}

#[cfg(not(unix))]
fn unix_process_is_non_root() -> bool {
    false
}

fn has_path_separator(command: &OsStr) -> bool {
    command
        .to_string_lossy()
        .chars()
        .any(|ch| ch == '/' || ch == '\\')
}

fn sudo_eligible_program(program: &OsStr) -> bool {
    let Some(manager) = sudo_mode_system_package_manager(program) else {
        return false;
    };
    if !manager_requires_privileged_install(manager) {
        return false;
    }
    if !is_explicit_command_path(program) {
        return true;
    }
    explicit_system_package_manager_path(Path::new(program))
}

fn sudo_mode_program_name(program: &OsStr) -> Option<&str> {
    if !is_explicit_command_path(program) {
        return program.to_str();
    }

    let path = Path::new(program);
    explicit_system_package_manager_path(path)
        .then_some(path.file_name()?.to_str())
        .flatten()
}

fn sudo_mode_system_package_manager(program: &OsStr) -> Option<SystemPackageManager> {
    sudo_mode_program_name(program).and_then(SystemPackageManager::parse)
}

fn manager_requires_privileged_install(manager: SystemPackageManager) -> bool {
    !matches!(manager, SystemPackageManager::Brew)
}

fn explicit_system_package_manager_path(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }

    if !is_spawnable_command_path(path) {
        return false;
    }

    let Some(file_name) = path.file_name() else {
        return false;
    };
    explicit_system_package_manager_path_with_resolved(
        path,
        resolve_host_system_package_manager_path(file_name),
    )
}

fn explicit_system_package_manager_path_with_resolved(
    path: &Path,
    resolved_path: Option<PathBuf>,
) -> bool {
    let Some(host_path) = resolved_path else {
        return false;
    };

    let Ok(path) = std::fs::canonicalize(path) else {
        return false;
    };
    let Ok(host_path) = std::fs::canonicalize(host_path) else {
        return false;
    };

    path == host_path
}

#[cfg(windows)]
fn is_path_env_name(name: &OsStr) -> bool {
    name.to_string_lossy().eq_ignore_ascii_case("PATH")
}

#[cfg(not(windows))]
fn is_path_env_name(name: &OsStr) -> bool {
    name == OsStr::new("PATH")
}

fn resolve_sudo_program() -> PathBuf {
    resolve_sudo_path().unwrap_or_else(|| PathBuf::from("sudo"))
}

fn sudo_available() -> bool {
    resolve_sudo_path().is_some()
}

fn resolve_sudo_path() -> Option<PathBuf> {
    resolve_command_path_in_standard_locations_os(OsStr::new("sudo"))
}

fn effective_path_var(env: &[(OsString, OsString)]) -> Option<OsString> {
    env.iter()
        .rev()
        .find_map(|(name, value)| is_path_env_name(name).then(|| value.clone()))
        .or_else(|| std::env::var_os("PATH"))
}

fn resolve_program_for_direct_command(request: &HostCommandRequest<'_>) -> Option<PathBuf> {
    let program = Path::new(request.program);
    if program.is_absolute() {
        return Some(program.to_path_buf());
    }
    let working_directory = resolved_working_directory_for_request(request);
    if is_explicit_command_path(request.program) {
        return working_directory.map(|working_directory| working_directory.join(program));
    }
    resolve_command_path_os_with_path_var_and_base_dir(
        request.program,
        effective_path_var(request.env),
        working_directory.as_deref(),
    )
}

fn resolve_program_for_direct_spawn(request: &HostCommandRequest<'_>) -> PathBuf {
    resolve_program_for_direct_command(request).unwrap_or_else(|| PathBuf::from(request.program))
}

fn validate_direct_request_program(
    request: &HostCommandRequest<'_>,
) -> Result<(), HostCommandError> {
    if is_explicit_relative_program_without_working_directory(request) {
        return Err(HostCommandError::SpawnFailed {
            program: request.program.to_os_string(),
            execution: HostCommandExecution::Direct,
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "explicit relative program paths require working_directory",
            ),
        });
    }

    Ok(())
}

fn resolved_working_directory_for_request(request: &HostCommandRequest<'_>) -> Option<PathBuf> {
    request
        .working_directory
        .map(resolve_working_directory_for_spawn)
}

fn resolve_working_directory_for_spawn(working_directory: &Path) -> PathBuf {
    if working_directory.is_absolute() {
        return working_directory.to_path_buf();
    }

    std::env::current_dir()
        .map(|current_dir| current_dir.join(working_directory))
        .unwrap_or_else(|_| working_directory.to_path_buf())
}

fn resolve_program_for_sudo_target(request: &HostCommandRequest<'_>) -> PathBuf {
    if is_explicit_command_path(request.program) {
        return resolve_program_for_direct_spawn(request);
    }

    resolve_host_system_package_manager_path(request.program)
        .unwrap_or_else(|| PathBuf::from(request.program))
}

fn resolve_host_system_package_manager_path(program: &OsStr) -> Option<PathBuf> {
    if is_explicit_command_path(program) {
        return None;
    }
    let manager = SystemPackageManager::parse(program.to_str()?)?;
    manager_requires_privileged_install(manager)
        .then_some(resolve_command_path_in_standard_locations_os(program))
        .flatten()
}

fn ensure_sudo_target_is_available(
    request: &HostCommandRequest<'_>,
) -> Result<(), HostCommandError> {
    if is_explicit_command_path(request.program) {
        return ensure_explicit_sudo_target_is_available(request);
    }

    if resolve_host_system_package_manager_path(request.program).is_some() {
        return Ok(());
    }

    Err(HostCommandError::CommandNotFound {
        program: request.program.to_os_string(),
    })
}

fn ensure_explicit_sudo_target_is_available(
    request: &HostCommandRequest<'_>,
) -> Result<(), HostCommandError> {
    let target = resolve_program_for_sudo_target(request);
    if !target.exists() {
        return Err(HostCommandError::CommandNotFound {
            program: request.program.to_os_string(),
        });
    }
    if !is_spawnable_command_path(&target) {
        return Err(HostCommandError::SpawnFailed {
            program: request.program.to_os_string(),
            execution: HostCommandExecution::Sudo,
            source: io::Error::new(
                io::ErrorKind::PermissionDenied,
                "sudo target must be an executable regular file",
            ),
        });
    }
    if !explicit_system_package_manager_path(&target) {
        return Err(HostCommandError::SpawnFailed {
            program: request.program.to_os_string(),
            execution: HostCommandExecution::Sudo,
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "sudo target must resolve to the trusted system package manager path",
            ),
        });
    }

    Ok(())
}

fn is_explicit_command_path(command: &OsStr) -> bool {
    has_path_separator(command)
        || Path::new(command).is_absolute()
        || has_windows_drive_prefix(command)
}

fn is_explicit_relative_program_without_working_directory(
    request: &HostCommandRequest<'_>,
) -> bool {
    is_explicit_command_path(request.program)
        && !Path::new(request.program).is_absolute()
        && request.working_directory.is_none()
}

#[cfg(windows)]
fn has_windows_drive_prefix(command: &OsStr) -> bool {
    use std::path::{Component, Prefix};

    matches!(
        Path::new(command).components().next(),
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
    )
}

#[cfg(not(windows))]
fn has_windows_drive_prefix(_command: &OsStr) -> bool {
    false
}

#[derive(Debug)]
enum CommandOutputError {
    Spawn(io::Error),
    Capture(io::Error),
    TimedOut { timeout: Duration, output: Output },
}

impl CommandOutputError {
    #[cfg(unix)]
    fn is_executable_file_busy(&self) -> bool {
        match self {
            Self::Spawn(source) => source.kind() == io::ErrorKind::ExecutableFileBusy,
            Self::Capture(_) | Self::TimedOut { .. } => false,
        }
    }
}

fn map_command_output_error(
    request: &HostCommandRequest<'_>,
    execution: HostCommandExecution,
    source: CommandOutputError,
) -> HostCommandError {
    match source {
        CommandOutputError::Spawn(source)
            if source.kind() == io::ErrorKind::NotFound
                && spawn_error_is_missing_program(request, execution) =>
        {
            HostCommandError::CommandNotFound {
                program: request.program.to_os_string(),
            }
        }
        CommandOutputError::Spawn(source) => HostCommandError::SpawnFailed {
            program: request.program.to_os_string(),
            execution,
            source,
        },
        CommandOutputError::Capture(source) => HostCommandError::CaptureFailed {
            program: request.program.to_os_string(),
            execution,
            source,
        },
        CommandOutputError::TimedOut { timeout, output } => HostCommandError::TimedOut {
            program: request.program.to_os_string(),
            execution,
            timeout,
            output,
        },
    }
}

fn spawn_error_is_missing_program(
    request: &HostCommandRequest<'_>,
    execution: HostCommandExecution,
) -> bool {
    match execution {
        HostCommandExecution::Sudo => !is_explicit_command_path(request.program),
        HostCommandExecution::Direct => {
            resolve_program_for_direct_command(request).is_none_or(|path| !path.exists())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::io;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};
    #[cfg(unix)]
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    use super::command_available_os;
    use super::command_exists_os;
    #[cfg(unix)]
    use super::ensure_sudo_target_is_available;
    #[cfg(unix)]
    use super::explicit_system_package_manager_path_with_resolved;
    use super::is_explicit_relative_program_without_working_directory;
    #[cfg(unix)]
    use super::resolve_command_path_in_standard_locations_os;
    #[cfg(unix)]
    use super::resolve_host_system_package_manager_path;
    #[cfg(unix)]
    use super::resolve_sudo_path;
    #[cfg(unix)]
    use super::should_try_sudo_for_request_with_status;
    use super::{
        HostCommandCaptureOptions, HostCommandError, HostCommandExecution, HostCommandRequest,
        HostCommandRunOptions, HostCommandSudoMode, HostRecipeError, HostRecipeRequest,
        build_command, build_command_with_options, command_available,
        command_available_for_request, command_exists, command_exists_for_request,
        command_path_exists, default_recipe_sudo_mode_for_program,
        resolve_program_for_direct_spawn, run_host_command, run_host_recipe,
        should_try_sudo_with_status,
    };
    #[cfg(unix)]
    use super::{
        run_host_command_with_capture_options, run_host_command_with_options,
        run_host_recipe_with_options,
    };

    #[test]
    fn command_probe_reports_missing_command_as_absent() {
        let command = "omne-process-primitives-missing-command";
        assert!(!command_exists(command));
        assert!(!command_available(command));
    }

    #[test]
    fn path_command_probe_accepts_executable_path() {
        let command_path = std::env::current_exe().expect("current exe");
        assert!(command_path_exists(&command_path));
    }

    #[test]
    fn run_host_command_captures_stdout_and_environment() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_test_command(temp.path(), "echoenv");
        let args = vec![OsString::from("hello")];
        let env = vec![(OsString::from("OMNE_TEST_VALUE"), OsString::from("world"))];
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        let output = run_host_command(&request).expect("run host command");
        assert_eq!(output.execution, HostCommandExecution::Direct);
        assert!(output.output.status.success());
        let stdout = String::from_utf8_lossy(&output.output.stdout);
        assert!(stdout.contains("arg=hello"));
        assert!(stdout.contains("env=world"));
    }

    #[test]
    fn sudo_mode_only_applies_to_non_root_bare_commands() {
        assert!(should_try_sudo_with_status(
            OsStr::new("apt-get"),
            HostCommandSudoMode::IfNonRootSystemCommand,
            true,
            true,
        ));
        #[cfg(target_os = "linux")]
        assert!(should_try_sudo_with_status(
            OsStr::new("/usr/bin/apt-get"),
            HostCommandSudoMode::IfNonRootSystemCommand,
            true,
            true,
        ));
        assert!(!should_try_sudo_with_status(
            OsStr::new("sh"),
            HostCommandSudoMode::IfNonRootSystemCommand,
            true,
            true,
        ));
        assert!(!should_try_sudo_with_status(
            OsStr::new("brew"),
            HostCommandSudoMode::IfNonRootSystemCommand,
            true,
            true,
        ));
        assert!(!should_try_sudo_with_status(
            OsStr::new("./apt-get"),
            HostCommandSudoMode::IfNonRootSystemCommand,
            true,
            true,
        ));
        assert!(!should_try_sudo_with_status(
            OsStr::new("apt-get"),
            HostCommandSudoMode::Never,
            true,
            true,
        ));
        assert!(!should_try_sudo_with_status(
            OsStr::new("apt-get"),
            HostCommandSudoMode::IfNonRootSystemCommand,
            false,
            true,
        ));
    }

    #[cfg(unix)]
    #[test]
    fn sudo_detection_ignores_request_path_override() {
        let temp = tempfile::tempdir().expect("tempdir");
        let sudo_path = write_test_command(temp.path(), "sudo");
        let env = vec![(
            OsString::from("PATH"),
            temp.path().as_os_str().to_os_string(),
        )];
        let request = HostCommandRequest {
            program: OsStr::new("apt-get"),
            args: &[],
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        let command = build_command(&request, HostCommandExecution::Sudo);
        assert_ne!(Path::new(command.get_program()), sudo_path.as_path());
        assert!(should_try_sudo_for_request_with_status(&request, true) == super::sudo_available());
    }

    #[cfg(unix)]
    #[test]
    fn resolve_sudo_path_uses_trusted_standard_location() {
        let resolved = resolve_sudo_path();
        assert_eq!(
            resolved,
            resolve_command_path_in_standard_locations_os(OsStr::new("sudo"))
        );
    }

    #[test]
    fn sudo_command_drops_request_environment_at_privilege_boundary() {
        let explicit_program = std::env::current_exe().expect("current exe");
        let args = vec![OsString::from("-c"), OsString::from("exit 0")];
        let env = vec![
            (
                OsString::from("PATH"),
                OsString::from("/tmp/not-trusted:/usr/bin"),
            ),
            (OsString::from("OMNE_TEST_VALUE"), OsString::from("world")),
            (OsString::from("OMNE_SECOND"), OsString::from("value")),
        ];
        let request = HostCommandRequest {
            program: explicit_program.as_os_str(),
            args: &args,
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        let command = build_command(&request, HostCommandExecution::Sudo);
        let collected_args = command
            .get_args()
            .map(|arg: &OsStr| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(collected_args[0], "-n");
        assert_eq!(Path::new(&collected_args[1]), explicit_program.as_path());
        assert_eq!(collected_args[2], "-c");
        assert_eq!(collected_args[3], "exit 0");
        assert!(
            collected_args.iter().all(|arg| !arg.contains('=')),
            "sudo target must not receive request env assignments: {collected_args:?}"
        );

        let collected_env = command
            .get_envs()
            .map(|(name, value): (&OsStr, Option<&OsStr>)| {
                (
                    name.to_string_lossy().into_owned(),
                    value
                        .map(|value: &OsStr| value.to_string_lossy().into_owned())
                        .expect("explicit env value should exist"),
                )
            })
            .collect::<Vec<_>>();
        assert!(collected_env.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn sudo_command_uses_trusted_target_path_instead_of_request_path_shadow() {
        let temp = tempfile::tempdir().expect("tempdir");
        let package_manager = ["apt-get", "dnf", "yum", "apk", "pacman", "zypper"]
            .into_iter()
            .find_map(|name| {
                resolve_host_system_package_manager_path(OsStr::new(name))
                    .map(|resolved| (name, resolved))
            });
        let Some((package_manager, resolved_path)) = package_manager else {
            return;
        };

        let shadowed_program = write_test_command(temp.path(), package_manager);
        let env = vec![(
            OsString::from("PATH"),
            temp.path().as_os_str().to_os_string(),
        )];
        let request = HostCommandRequest {
            program: OsStr::new(package_manager),
            args: &[],
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        let command = build_command(&request, HostCommandExecution::Sudo);
        let target = command
            .get_args()
            .last()
            .expect("sudo target should be present");

        assert_ne!(Path::new(target), shadowed_program.as_path());
        assert_eq!(Path::new(target), resolved_path.as_path());
    }

    #[cfg(unix)]
    #[test]
    fn sudo_target_resolution_uses_trusted_standard_location() {
        let package_manager = ["apt-get", "dnf", "yum", "apk", "pacman", "zypper"]
            .into_iter()
            .find_map(|name| {
                resolve_command_path_in_standard_locations_os(OsStr::new(name))
                    .map(|resolved| (name, resolved))
            });
        let Some((package_manager, resolved_path)) = package_manager else {
            return;
        };

        let resolved = resolve_host_system_package_manager_path(OsStr::new(package_manager));

        assert_eq!(resolved, Some(resolved_path));
    }

    #[test]
    fn direct_command_keeps_explicit_environment_on_spawned_process() {
        let env = vec![(OsString::from("OMNE_TEST_VALUE"), OsString::from("world"))];
        let request = HostCommandRequest {
            program: OsStr::new("echo"),
            args: &[],
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let command = build_command(&request, HostCommandExecution::Direct);
        let collected_env = command
            .get_envs()
            .map(|(name, value): (&OsStr, Option<&OsStr>)| {
                (
                    name.to_string_lossy().into_owned(),
                    value
                        .map(|value: &OsStr| value.to_string_lossy().into_owned())
                        .expect("explicit env value should exist"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            collected_env,
            vec![("OMNE_TEST_VALUE".to_string(), "world".to_string())]
        );
    }

    #[test]
    fn direct_command_supports_request_scoped_env_removals() {
        let env = vec![(OsString::from("OMNE_TEST_VALUE"), OsString::from("world"))];
        let removed = vec![OsString::from("UV_INDEX"), OsString::from("UV_PYTHON")];
        let request = HostCommandRequest {
            program: OsStr::new("echo"),
            args: &[],
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let command = build_command_with_options(
            &request,
            HostCommandExecution::Direct,
            HostCommandRunOptions::new().with_env_remove(&removed),
        );
        let collected_env = command
            .get_envs()
            .map(|(name, value): (&OsStr, Option<&OsStr>)| {
                (
                    name.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<Vec<_>>();
        assert!(collected_env.contains(&("UV_INDEX".to_string(), None)));
        assert!(collected_env.contains(&("UV_PYTHON".to_string(), None)));
        assert!(
            collected_env.contains(&("OMNE_TEST_VALUE".to_string(), Some("world".to_string())))
        );
    }

    #[cfg(unix)]
    #[test]
    fn sudo_missing_target_is_classified_as_command_not_found() {
        let temp = tempfile::tempdir().expect("tempdir");
        let _sudo_path = write_test_command(temp.path(), "sudo");
        let env = vec![(
            OsString::from("PATH"),
            temp.path().as_os_str().to_os_string(),
        )];
        let request = HostCommandRequest {
            program: OsStr::new("omne-process-primitives-missing-command"),
            args: &[],
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        let err =
            ensure_sudo_target_is_available(&request).expect_err("missing target should fail");
        assert!(matches!(err, HostCommandError::CommandNotFound { .. }));
    }

    #[test]
    fn default_recipe_sudo_mode_recognizes_common_package_managers() {
        assert_eq!(
            default_recipe_sudo_mode_for_program(OsStr::new("apt-get")),
            HostCommandSudoMode::IfNonRootSystemCommand
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            default_recipe_sudo_mode_for_program(OsStr::new("/usr/bin/apt-get")),
            HostCommandSudoMode::IfNonRootSystemCommand
        );
        assert_eq!(
            default_recipe_sudo_mode_for_program(OsStr::new("dnf")),
            HostCommandSudoMode::IfNonRootSystemCommand
        );
        assert_eq!(
            default_recipe_sudo_mode_for_program(OsStr::new("brew")),
            HostCommandSudoMode::Never
        );
        assert_eq!(
            default_recipe_sudo_mode_for_program(OsStr::new("cargo")),
            HostCommandSudoMode::Never
        );
        assert_eq!(
            default_recipe_sudo_mode_for_program(OsStr::new("./apt-get")),
            HostCommandSudoMode::Never
        );
    }

    #[test]
    fn run_host_command_uses_working_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_pwd_command(temp.path(), "pwd");
        let working_directory = temp.path().join("cwd");
        std::fs::create_dir_all(&working_directory).expect("create working directory");
        let args = Vec::new();
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &[],
            working_directory: Some(&working_directory),
            sudo_mode: HostCommandSudoMode::Never,
        };

        let output = run_host_command(&request).expect("run host command");
        assert!(output.output.status.success());
        let stdout = String::from_utf8_lossy(&output.output.stdout);
        assert!(stdout.contains(&working_directory.display().to_string()));
    }

    #[test]
    fn run_host_command_classifies_missing_program_as_not_found() {
        let args = Vec::new();
        let request = HostCommandRequest {
            program: OsStr::new("omne-process-primitives-missing-command"),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let error = run_host_command(&request).expect_err("missing command should fail");
        assert!(matches!(error, HostCommandError::CommandNotFound { .. }));
    }

    #[test]
    fn run_host_command_does_not_probe_by_executing_the_program_twice() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_count_command(temp.path(), "count");
        let count_file = temp.path().join("count.txt");
        let args = Vec::new();
        let env = vec![(
            OsString::from("OMNE_COUNT_FILE"),
            count_file.as_os_str().to_os_string(),
        )];
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let output = run_host_command(&request).expect("run host command");
        assert!(output.output.status.success());

        let recorded = std::fs::read_to_string(&count_file).expect("read count file");
        assert_eq!(recorded.lines().count(), 1);
    }

    #[test]
    fn run_host_command_rejects_unbounded_stdout_capture() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_large_stdout_command(temp.path(), "loud");
        let args = Vec::new();
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let err = run_host_command(&request).expect_err("oversized stdout should fail");
        match err {
            HostCommandError::CaptureFailed { source, .. } => {
                assert!(
                    source.to_string().contains("stdout exceeded capture limit"),
                    "unexpected error: {source}"
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn run_host_command_rejects_large_oversized_stdout_without_hanging() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_very_large_stdout_command(temp.path(), "very-loud");
        let args = Vec::new();
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let err = run_host_command(&request).expect_err("oversized stdout should fail");
        match err {
            HostCommandError::CaptureFailed { source, .. } => {
                assert!(
                    source.to_string().contains("stdout exceeded capture limit"),
                    "unexpected error: {source}"
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn run_host_command_fails_fast_when_stdout_exceeds_limit_before_exit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_oversized_stdout_then_sleep_command(temp.path(), "very-loud-slow");
        let args = Vec::new();
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let started = Instant::now();
        let err = run_host_command(&request).expect_err("oversized stdout should fail");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "capture overflow should terminate the child instead of waiting for normal exit"
        );
        match err {
            HostCommandError::CaptureFailed { source, .. } => {
                assert!(
                    source.to_string().contains("stdout exceeded capture limit"),
                    "unexpected error: {source}"
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn run_host_command_allows_stdout_exactly_at_capture_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_exact_limit_stdout_command(temp.path(), "exact-limit");
        let args = Vec::new();
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let output = run_host_command(&request).expect("exact-limit stdout should succeed");
        assert!(output.output.status.success());
        assert_eq!(
            output.output.stdout.len(),
            super::DEFAULT_CAPTURED_OUTPUT_BYTES_PER_STREAM
        );
    }

    #[test]
    fn run_host_command_with_options_allows_disabling_capture_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_very_large_stdout_command(temp.path(), "unbounded");
        let args = Vec::new();
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let output = run_host_command_with_capture_options(
            &request,
            HostCommandRunOptions::new(),
            HostCommandCaptureOptions::new().without_capture_limit(),
        )
        .expect("disabling the capture limit should allow large output");
        assert!(output.output.status.success());
        assert!(output.output.stdout.len() > super::DEFAULT_CAPTURED_OUTPUT_BYTES_PER_STREAM);
    }

    #[test]
    fn run_host_command_with_options_uses_custom_capture_limit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_large_stdout_command(temp.path(), "custom-limit");
        let args = Vec::new();
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let err = run_host_command_with_capture_options(
            &request,
            HostCommandRunOptions::new(),
            HostCommandCaptureOptions::new().with_capture_limit_bytes_per_stream(1024),
        )
        .expect_err("custom capture limit should be enforced");
        match err {
            HostCommandError::CaptureFailed { source, .. } => {
                assert!(
                    source
                        .to_string()
                        .contains("stdout exceeded capture limit of 1024 bytes"),
                    "unexpected error: {source}"
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn run_host_command_rejects_unbounded_stderr_capture() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_large_stderr_command(temp.path(), "loud-stderr");
        let args = Vec::new();
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let err = run_host_command(&request).expect_err("oversized stderr should fail");
        match err {
            HostCommandError::CaptureFailed { source, .. } => {
                assert!(
                    source.to_string().contains("stderr exceeded capture limit"),
                    "unexpected error: {source}"
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn run_host_command_with_options_times_out_and_keeps_captured_output() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_shell_executable(
            temp.path(),
            "slow-stdout-stderr",
            "printf 'stdout-before-timeout'\nprintf 'stderr-before-timeout' >&2\nsleep 5\n",
        );
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &[],
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let err = run_host_command_with_options(
            &request,
            HostCommandRunOptions::new().with_timeout(Duration::from_millis(50)),
        )
        .expect_err("slow command should time out");
        match err {
            HostCommandError::TimedOut {
                timeout, output, ..
            } => {
                assert_eq!(timeout, Duration::from_millis(50));
                assert!(String::from_utf8_lossy(&output.stdout).contains("stdout-before-timeout"));
                assert!(String::from_utf8_lossy(&output.stderr).contains("stderr-before-timeout"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn run_host_command_resolves_relative_program_against_working_directory() {
        let working_directory = tempfile::tempdir().expect("working directory tempdir");
        let command_root = working_directory.path().join("bin");
        std::fs::create_dir_all(&command_root).expect("create relative command root");
        let command_path = write_pwd_command(&command_root, "pwd");
        let relative_program = command_path
            .strip_prefix(working_directory.path())
            .expect("relative command path")
            .to_path_buf();
        let args = Vec::new();
        let request = HostCommandRequest {
            program: relative_program.as_os_str(),
            args: &args,
            env: &[],
            working_directory: Some(working_directory.path()),
            sudo_mode: HostCommandSudoMode::Never,
        };

        assert!(!command_exists_os(relative_program.as_os_str()));
        assert_eq!(
            resolve_program_for_direct_spawn(&request),
            working_directory.path().join(&relative_program)
        );

        let output = run_host_command(&request).expect("run host command");
        assert!(output.output.status.success());
        let stdout = String::from_utf8_lossy(&output.output.stdout);
        assert!(stdout.contains(&working_directory.path().display().to_string()));
    }

    #[test]
    fn request_scoped_relative_path_entries_follow_relative_working_directory() {
        struct CurrentDirGuard(PathBuf);

        impl Drop for CurrentDirGuard {
            fn drop(&mut self) {
                let _ = std::env::set_current_dir(&self.0);
            }
        }

        let _lock = current_dir_lock().lock().expect("lock current_dir");
        let temp = tempfile::tempdir().expect("tempdir");
        let original_cwd = std::env::current_dir().expect("current_dir");
        let _restore_current_dir = CurrentDirGuard(original_cwd);
        std::env::set_current_dir(temp.path()).expect("set current_dir");

        {
            let working_directory = PathBuf::from("cwd");
            let relative_bin = temp.path().join("cwd").join("bin");
            std::fs::create_dir_all(&relative_bin).expect("create relative PATH dir");
            let expected_program = write_pwd_command(&relative_bin, "pwd");
            let env = vec![(OsString::from("PATH"), OsString::from("bin"))];
            let request = HostCommandRequest {
                program: OsStr::new("pwd"),
                args: &[],
                env: &env,
                working_directory: Some(&working_directory),
                sudo_mode: HostCommandSudoMode::Never,
            };

            assert!(command_exists_for_request(&request));
            assert!(command_available_for_request(&request));
            assert_eq!(
                resolve_program_for_direct_spawn(&request)
                    .canonicalize()
                    .expect("canonicalize resolved program"),
                expected_program
                    .canonicalize()
                    .expect("canonicalize expected program")
            );

            let output = run_host_command(&request).expect("run request-scoped PATH command");
            assert!(output.output.status.success());
            let stdout = String::from_utf8_lossy(&output.output.stdout);
            assert!(stdout.contains(&temp.path().join("cwd").display().to_string()));
        }
    }

    #[cfg(unix)]
    #[test]
    fn direct_command_resolves_bare_request_path_before_spawn() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_test_command(temp.path(), "echoenv");
        let env = vec![
            (
                OsString::from("PATH"),
                temp.path().as_os_str().to_os_string(),
            ),
            (OsString::from("OMNE_TEST_VALUE"), OsString::from("world")),
        ];
        let request = HostCommandRequest {
            program: OsStr::new("echoenv"),
            args: &[],
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let command = build_command(&request, HostCommandExecution::Direct);
        assert_eq!(Path::new(command.get_program()), command_path.as_path());
        assert_eq!(
            command.get_envs().find_map(|(name, value)| {
                (name == OsStr::new("PATH"))
                    .then(|| value.expect("PATH value should exist").to_os_string())
            }),
            Some(temp.path().as_os_str().to_os_string())
        );
    }

    #[test]
    fn request_scoped_probe_resolves_relative_program_against_working_directory() {
        let working_directory = tempfile::tempdir().expect("working directory tempdir");
        let command_root = working_directory.path().join("bin");
        std::fs::create_dir_all(&command_root).expect("create relative command root");
        let command_path = write_pwd_command(&command_root, "pwd");
        let relative_program = command_path
            .strip_prefix(working_directory.path())
            .expect("relative command path")
            .to_path_buf();
        let request = HostCommandRequest {
            program: relative_program.as_os_str(),
            args: &[],
            env: &[],
            working_directory: Some(working_directory.path()),
            sudo_mode: HostCommandSudoMode::Never,
        };

        assert!(command_exists_for_request(&request));
        assert!(command_available_for_request(&request));
        assert_eq!(
            resolve_program_for_direct_spawn(&request),
            working_directory.path().join(&relative_program)
        );
    }

    #[test]
    fn request_scoped_probe_resolves_relative_path_entry_against_working_directory() {
        let working_directory = tempfile::tempdir().expect("working directory tempdir");
        let command_root = working_directory.path().join("bin");
        std::fs::create_dir_all(&command_root).expect("create relative command root");
        let command_path = write_test_command(&command_root, "echoenv");
        let env = vec![(OsString::from("PATH"), OsString::from("bin"))];
        let request = HostCommandRequest {
            program: OsStr::new("echoenv"),
            args: &[],
            env: &env,
            working_directory: Some(working_directory.path()),
            sudo_mode: HostCommandSudoMode::Never,
        };

        assert!(!command_exists_os(request.program));
        assert!(command_exists_for_request(&request));
        assert!(command_available_for_request(&request));
        assert_eq!(resolve_program_for_direct_spawn(&request), command_path);
    }

    #[test]
    fn request_scoped_probe_rejects_relative_program_without_working_directory() {
        let request = HostCommandRequest {
            program: OsStr::new("./tool"),
            args: &[],
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        assert!(!command_exists_for_request(&request));
        assert!(!command_available_for_request(&request));
        assert!(is_explicit_relative_program_without_working_directory(
            &request
        ));
    }

    #[test]
    fn run_host_command_rejects_relative_program_without_working_directory() {
        let args = Vec::new();
        let request = HostCommandRequest {
            program: OsStr::new("./tool"),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let err = run_host_command(&request).expect_err("relative program should fail closed");
        match err {
            HostCommandError::SpawnFailed {
                execution, source, ..
            } => {
                assert_eq!(execution, HostCommandExecution::Direct);
                assert_eq!(source.kind(), io::ErrorKind::InvalidInput);
                assert!(
                    source
                        .to_string()
                        .contains("explicit relative program paths require working_directory")
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn run_host_command_resolves_relative_path_entry_against_working_directory() {
        let working_directory = tempfile::tempdir().expect("working directory tempdir");
        let command_root = working_directory.path().join("bin");
        std::fs::create_dir_all(&command_root).expect("create relative command root");
        write_test_command(&command_root, "echoenv");
        let env = vec![
            (OsString::from("PATH"), OsString::from("bin")),
            (OsString::from("OMNE_TEST_VALUE"), OsString::from("world")),
        ];
        let request = HostCommandRequest {
            program: OsStr::new("echoenv"),
            args: &[],
            env: &env,
            working_directory: Some(working_directory.path()),
            sudo_mode: HostCommandSudoMode::Never,
        };

        let output = run_host_command(&request).expect("run host command");
        assert!(output.output.status.success());
        let stdout = String::from_utf8_lossy(&output.output.stdout);
        assert!(stdout.contains("env=world"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_drive_relative_programs_are_not_treated_as_bare_commands() {
        let args = Vec::new();
        let request = HostCommandRequest {
            program: OsStr::new("C:tool.cmd"),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        assert!(!command_exists_for_request(&request));
        assert!(!command_available_for_request(&request));
        assert!(super::is_explicit_command_path(request.program));
        assert!(is_explicit_relative_program_without_working_directory(
            &request
        ));

        let err = run_host_command(&request).expect_err("drive-relative path should fail closed");
        match err {
            HostCommandError::SpawnFailed {
                execution, source, ..
            } => {
                assert_eq!(execution, HostCommandExecution::Direct);
                assert_eq!(source.kind(), io::ErrorKind::InvalidInput);
                assert!(
                    source
                        .to_string()
                        .contains("explicit relative program paths require working_directory")
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn explicit_system_package_manager_path_requires_same_binary_as_host_resolution() {
        let temp = tempfile::tempdir().expect("tempdir");
        let host_program = write_test_command(temp.path(), "apt-get");
        let alias = temp.path().join("apt-get-alias");
        symlink(&host_program, &alias).expect("symlink alias");

        assert!(explicit_system_package_manager_path_with_resolved(
            &host_program,
            Some(host_program.clone()),
        ));
        assert!(explicit_system_package_manager_path_with_resolved(
            &alias,
            Some(host_program),
        ));
    }

    #[test]
    fn run_host_recipe_captures_success_output() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_test_command(temp.path(), "echoenv");
        let args = vec![OsString::from("hello")];
        let env = vec![(OsString::from("OMNE_TEST_VALUE"), OsString::from("world"))];

        let output = run_host_recipe(
            &HostRecipeRequest::new(command_path.as_os_str(), &args).with_env(&env),
        )
        .expect("run host recipe");
        assert_eq!(output.execution, HostCommandExecution::Direct);
        assert!(output.output.status.success());
        let stdout = String::from_utf8_lossy(&output.output.stdout);
        assert!(stdout.contains("arg=hello"));
        assert!(stdout.contains("env=world"));
    }

    #[test]
    fn run_host_recipe_returns_non_zero_exit_as_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_failing_command(temp.path(), "failcmd");
        let args = Vec::new();

        let err = run_host_recipe(&HostRecipeRequest::new(command_path.as_os_str(), &args))
            .expect_err("recipe should fail");
        let rendered = err.to_string();
        match err {
            HostRecipeError::NonZeroExit {
                execution, output, ..
            } => {
                assert_eq!(execution, HostCommandExecution::Direct);
                assert_eq!(output.status.code(), Some(7));
                assert_eq!(String::from_utf8_lossy(&output.stdout), "stdout-message");
                assert_eq!(String::from_utf8_lossy(&output.stderr), "stderr-message");
                assert!(rendered.contains("stdout_bytes=14"));
                assert!(rendered.contains("stderr_bytes=14"));
                assert!(!rendered.contains("stdout-message"));
                assert!(!rendered.contains("stderr-message"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn run_host_recipe_with_options_surfaces_timeout_as_command_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_shell_executable(
            temp.path(),
            "slow-recipe",
            "printf 'stdout-before-timeout'\nprintf 'stderr-before-timeout' >&2\nsleep 5\n",
        );
        let args = Vec::new();

        let err = run_host_recipe_with_options(
            &HostRecipeRequest::new(command_path.as_os_str(), &args),
            HostCommandRunOptions::new().with_timeout(Duration::from_millis(50)),
        )
        .expect_err("slow recipe should time out");
        match err {
            HostRecipeError::Command(HostCommandError::TimedOut {
                timeout, output, ..
            }) => {
                assert_eq!(timeout, Duration::from_millis(50));
                assert!(String::from_utf8_lossy(&output.stdout).contains("stdout-before-timeout"));
                assert!(String::from_utf8_lossy(&output.stderr).contains("stderr-before-timeout"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn run_host_command_returns_after_direct_child_exit_even_when_background_keeps_stdout_open() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_background_writer_command(temp.path(), "daemonize", "stdout");
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &[],
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let started = std::time::Instant::now();
        let output = run_host_command(&request).expect("run host command");

        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "background descendants must not keep run_host_command blocked"
        );
        assert!(output.output.status.success());
        let stdout = String::from_utf8_lossy(&output.output.stdout);
        assert!(stdout.contains("parent-ready"));
    }

    #[cfg(unix)]
    #[test]
    fn run_host_command_returns_after_direct_child_exit_even_when_background_keeps_stderr_open() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path =
            write_background_writer_command(temp.path(), "daemonize-stderr", "stderr");
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &[],
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let started = std::time::Instant::now();
        let output = run_host_command(&request).expect("run host command");

        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "background descendants must not keep run_host_command blocked"
        );
        assert!(output.output.status.success());
        let stderr = String::from_utf8_lossy(&output.output.stderr);
        assert!(stderr.contains("parent-ready"));
    }

    #[cfg(unix)]
    #[test]
    fn build_command_preserves_non_utf8_arguments() {
        let non_utf8_arg = OsString::from_vec(vec![0x66, 0x6f, 0x80]);
        let args = vec![non_utf8_arg.clone()];
        let request = HostCommandRequest {
            program: OsStr::new("echo"),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let command = build_command(&request, HostCommandExecution::Direct);
        let collected_args = command
            .get_args()
            .map(|arg| arg.to_os_string())
            .collect::<Vec<_>>();
        assert_eq!(collected_args, vec![non_utf8_arg]);
    }

    #[cfg(unix)]
    #[test]
    fn build_command_preserves_non_utf8_environment_values() {
        let non_utf8_value = OsString::from_vec(vec![0x66, 0x6f, 0x80]);
        let env = vec![(OsString::from("OMNE_TEST_VALUE"), non_utf8_value.clone())];
        let request = HostCommandRequest {
            program: OsStr::new("echo"),
            args: &[],
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let command = build_command(&request, HostCommandExecution::Direct);
        let collected_env = command
            .get_envs()
            .map(|(name, value)| {
                (
                    name.to_os_string(),
                    value
                        .expect("explicit env value should exist")
                        .to_os_string(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            collected_env,
            vec![(OsString::from("OMNE_TEST_VALUE"), non_utf8_value.clone())]
        );
    }

    #[cfg(unix)]
    #[test]
    fn sudo_discards_non_utf8_request_environment_values() {
        let non_utf8_value = OsString::from_vec(vec![0x66, 0x6f, 0x80]);
        let env = vec![(OsString::from("OMNE_TEST_VALUE"), non_utf8_value)];
        let explicit_program = std::env::current_exe().expect("current exe");
        let request = HostCommandRequest {
            program: explicit_program.as_os_str(),
            args: &[],
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        let command = build_command(&request, HostCommandExecution::Sudo);
        let collected_args = command
            .get_args()
            .map(OsStr::to_os_string)
            .collect::<Vec<_>>();

        assert_eq!(collected_args[0], OsString::from("-n"));
        assert_eq!(collected_args[1], explicit_program.into_os_string());
        assert_eq!(collected_args.len(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn non_executable_paths_are_not_reported_as_available() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = temp.path().join("plain-script");
        std::fs::write(&command_path, "#!/bin/sh\nexit 0\n").expect("write plain script");
        let mut permissions = std::fs::metadata(&command_path)
            .expect("stat plain script")
            .permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&command_path, permissions).expect("chmod plain script");

        let command_path_string = command_path.to_string_lossy().into_owned();
        assert!(!command_available(&command_path_string));
        assert!(!command_available_os(command_path.as_os_str()));
        assert!(!command_path_exists(&command_path));

        let args = Vec::new();
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let error = run_host_command(&request).expect_err("non-executable path should fail");
        match error {
            HostCommandError::CommandNotFound { .. } => {
                panic!("non-executable path must not be classified as not found");
            }
            HostCommandError::SpawnFailed { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            HostCommandError::CaptureFailed { .. } => {
                panic!("non-executable path must not reach output capture");
            }
            HostCommandError::TimedOut { .. } => {
                panic!("non-executable path must fail before timeout handling");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn bare_request_path_shadow_preserves_missing_interpreter_as_spawn_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_unix_executable(
            temp.path(),
            "bad-loader",
            "#!/definitely/missing/interpreter\nexit 0\n",
        );
        let env = vec![(
            OsString::from("PATH"),
            temp.path().as_os_str().to_os_string(),
        )];
        let request = HostCommandRequest {
            program: OsStr::new("bad-loader"),
            args: &[],
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        assert!(command_available_for_request(&request));
        assert_eq!(resolve_program_for_direct_spawn(&request), command_path);

        let error = run_host_command(&request).expect_err("missing interpreter should fail spawn");
        match error {
            HostCommandError::CommandNotFound { .. } => {
                panic!("missing interpreter must not be mislabeled as command not found");
            }
            HostCommandError::SpawnFailed { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
            HostCommandError::CaptureFailed { .. } => {
                panic!("missing interpreter must fail before output capture starts");
            }
            HostCommandError::TimedOut { .. } => {
                panic!("missing interpreter must fail before timeout handling");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn explicit_system_package_manager_path_rejects_different_binary() {
        let temp = tempfile::tempdir().expect("tempdir");
        let host_program = write_test_command(temp.path(), "apt-get");
        let other_program = write_test_command(temp.path(), "apt-get-other");

        assert!(!explicit_system_package_manager_path_with_resolved(
            &other_program,
            Some(host_program),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn resolve_host_system_package_manager_path_ignores_non_package_managers() {
        assert!(resolve_host_system_package_manager_path(OsStr::new("sh")).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn explicit_system_package_manager_path_rejects_non_matching_explicit_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let host_program = write_test_command(temp.path(), "apt-get");
        let mismatched_name = write_test_command(temp.path(), "dnf");

        assert!(!explicit_system_package_manager_path_with_resolved(
            &mismatched_name,
            Some(host_program),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_system_package_manager_path_rejects_lexical_prefix_escape() {
        let temp = tempfile::tempdir().expect("tempdir");
        let trusted_root = temp.path().join("usr").join("bin");
        let escaped_root = temp.path().join("tmp");
        std::fs::create_dir_all(&trusted_root).expect("create trusted root");
        std::fs::create_dir_all(&escaped_root).expect("create escaped root");
        let trusted_program = write_test_command(&trusted_root, "apt-get");
        let escaped_program = write_test_command(&escaped_root, "apt-get");
        let lexical_escape = trusted_root
            .join("..")
            .join("..")
            .join("tmp")
            .join("apt-get");

        assert_eq!(
            lexical_escape
                .canonicalize()
                .expect("canonicalize lexical escape"),
            escaped_program
                .canonicalize()
                .expect("canonicalize escaped program")
        );
        assert!(!explicit_system_package_manager_path_with_resolved(
            &lexical_escape,
            Some(trusted_program),
        ));
    }

    #[cfg(unix)]
    #[test]
    fn lexical_prefix_escape_does_not_trigger_auto_sudo() {
        let temp = tempfile::tempdir().expect("tempdir");
        let trusted_root = temp.path().join("usr").join("bin");
        let escaped_root = temp.path().join("tmp");
        std::fs::create_dir_all(&trusted_root).expect("create trusted root");
        std::fs::create_dir_all(&escaped_root).expect("create escaped root");
        let _trusted_program = write_test_command(&trusted_root, "apt-get");
        let _escaped_program = write_test_command(&escaped_root, "apt-get");
        let lexical_escape = trusted_root
            .join("..")
            .join("..")
            .join("tmp")
            .join("apt-get");
        let request = HostCommandRequest {
            program: lexical_escape.as_os_str(),
            args: &[],
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        assert!(
            !should_try_sudo_for_request_with_status(&request, true),
            "lexical prefix escapes must not regain IfNonRootSystemCommand semantics"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_sudo_target_rejects_missing_explicit_path() {
        let Some(program_name) = available_privileged_package_manager_name() else {
            return;
        };
        let temp = tempfile::tempdir().expect("tempdir");
        let missing = temp.path().join(program_name);
        let request = HostCommandRequest {
            program: missing.as_os_str(),
            args: &[],
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        let err =
            ensure_sudo_target_is_available(&request).expect_err("missing sudo target must fail");
        assert!(matches!(err, HostCommandError::CommandNotFound { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_sudo_target_rejects_missing_relative_explicit_path() {
        let Some(program_name) = available_privileged_package_manager_name() else {
            return;
        };
        let temp = tempfile::tempdir().expect("tempdir");
        let relative_program = Path::new("bin").join(program_name);
        let request = HostCommandRequest {
            program: relative_program.as_os_str(),
            args: &[],
            env: &[],
            working_directory: Some(temp.path()),
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        let err = ensure_sudo_target_is_available(&request)
            .expect_err("missing relative sudo target must fail");
        assert!(matches!(err, HostCommandError::CommandNotFound { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_sudo_target_rejects_non_executable_explicit_path() {
        use std::os::unix::fs::PermissionsExt;

        let Some(program_name) = available_privileged_package_manager_name() else {
            return;
        };
        let temp = tempfile::tempdir().expect("tempdir");
        let target = temp.path().join(program_name);
        std::fs::write(&target, "#!/bin/sh\nexit 0\n").expect("write target");
        let mut permissions = std::fs::metadata(&target)
            .expect("stat target")
            .permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&target, permissions).expect("chmod target");
        let request = HostCommandRequest {
            program: target.as_os_str(),
            args: &[],
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        let err = ensure_sudo_target_is_available(&request)
            .expect_err("non-executable sudo target must fail");
        match err {
            HostCommandError::SpawnFailed {
                execution, source, ..
            } => {
                assert_eq!(execution, HostCommandExecution::Sudo);
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn ensure_sudo_target_rejects_untrusted_explicit_path() {
        let Some(program_name) = available_privileged_package_manager_name() else {
            return;
        };
        let temp = tempfile::tempdir().expect("tempdir");
        let target = write_shell_executable(temp.path(), program_name, "exit 0\n");
        let request = HostCommandRequest {
            program: target.as_os_str(),
            args: &[],
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        let err =
            ensure_sudo_target_is_available(&request).expect_err("untrusted sudo target must fail");
        match err {
            HostCommandError::SpawnFailed {
                execution, source, ..
            } => {
                assert_eq!(execution, HostCommandExecution::Sudo);
                assert_eq!(source.kind(), io::ErrorKind::InvalidInput);
                assert!(
                    source
                        .to_string()
                        .contains("trusted system package manager path")
                );
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    fn write_test_command(dir: &Path, name: &str) -> PathBuf {
        write_shell_executable(
            dir,
            name,
            "printf 'arg=%s\\n' \"$1\"\nprintf 'env=%s\\n' \"$OMNE_TEST_VALUE\"\n",
        )
    }

    #[cfg(unix)]
    fn write_pwd_command(dir: &Path, name: &str) -> PathBuf {
        write_shell_executable(dir, name, "pwd\n")
    }

    #[cfg(unix)]
    fn write_count_command(dir: &Path, name: &str) -> PathBuf {
        write_shell_executable(dir, name, "printf 'run\\n' >> \"$OMNE_COUNT_FILE\"\n")
    }

    #[cfg(unix)]
    fn write_failing_command(dir: &Path, name: &str) -> PathBuf {
        write_shell_executable(
            dir,
            name,
            "printf 'stdout-message'\nprintf 'stderr-message' >&2\nexit 7\n",
        )
    }

    #[cfg(unix)]
    fn write_large_stdout_command(dir: &Path, name: &str) -> PathBuf {
        write_payload_cat_command(dir, name, "stdout", 8 * 1024 * 1024 + 1)
    }

    #[cfg(unix)]
    fn write_background_writer_command(dir: &Path, name: &str, stream: &str) -> PathBuf {
        let body = match stream {
            "stdout" => "(sleep 2; printf 'late-child\\n') &\nprintf 'parent-ready\\n'\n",
            "stderr" => "(sleep 2; printf 'late-child\\n' >&2) &\nprintf 'parent-ready\\n' >&2\n",
            other => panic!("unexpected background stream: {other}"),
        };
        write_shell_executable(dir, name, body)
    }

    #[cfg(unix)]
    fn write_very_large_stdout_command(dir: &Path, name: &str) -> PathBuf {
        write_payload_cat_command(dir, name, "stdout", 32 * 1024 * 1024)
    }

    #[cfg(unix)]
    fn write_oversized_stdout_then_sleep_command(dir: &Path, name: &str) -> PathBuf {
        let payload_path = dir.join(format!("{name}.payload"));
        std::fs::write(&payload_path, vec![b'x'; 8 * 1024 * 1024 + 1]).expect("write payload");
        let payload = shell_quote_path(&payload_path);
        write_shell_executable(dir, name, &format!("cat {payload}\nsleep 5\n"))
    }

    #[cfg(unix)]
    fn write_exact_limit_stdout_command(dir: &Path, name: &str) -> PathBuf {
        write_payload_cat_command(dir, name, "stdout", 8 * 1024 * 1024)
    }

    #[cfg(unix)]
    fn write_large_stderr_command(dir: &Path, name: &str) -> PathBuf {
        write_payload_cat_command(dir, name, "stderr", 8 * 1024 * 1024 + 1)
    }

    #[cfg(unix)]
    fn write_payload_cat_command(dir: &Path, name: &str, stream: &str, size: usize) -> PathBuf {
        let payload_path = dir.join(format!("{name}.payload"));
        std::fs::write(&payload_path, vec![b'x'; size]).expect("write payload");
        let payload = shell_quote_path(&payload_path);
        let body = match stream {
            "stdout" => format!("cat {payload}\n"),
            "stderr" => format!("cat {payload} >&2\n"),
            other => panic!("unexpected payload stream: {other}"),
        };
        write_shell_executable(dir, name, &body)
    }

    #[cfg(unix)]
    fn write_shell_executable(dir: &Path, name: &str, body: &str) -> PathBuf {
        let shell = unix_test_shell_path();
        write_unix_executable(dir, name, &format!("#!{}\n{body}", shell.display()))
    }

    #[cfg(unix)]
    fn unix_test_shell_path() -> PathBuf {
        crate::command_path::resolve_command_path_or_standard_location_os(OsStr::new("sh"))
            .expect("resolve test shell")
    }

    #[cfg(unix)]
    fn available_privileged_package_manager_name() -> Option<&'static str> {
        ["apt-get", "dnf", "yum", "apk", "pacman", "zypper"]
            .into_iter()
            .find(|name| resolve_host_system_package_manager_path(OsStr::new(name)).is_some())
    }

    #[cfg(unix)]
    fn shell_quote_path(path: &Path) -> String {
        let escaped = path.display().to_string().replace('\'', "'\"'\"'");
        format!("'{escaped}'")
    }

    #[cfg(unix)]
    fn write_unix_executable(dir: &Path, name: &str, content: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(name);
        let temp_path = dir.join(format!("{name}.tmp"));
        std::fs::write(&temp_path, content).expect("write unix command");
        let mut perms = std::fs::metadata(&temp_path)
            .expect("stat unix command")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&temp_path, perms).expect("chmod unix command");
        std::fs::rename(&temp_path, &path).expect("rename unix command");
        path
    }

    #[cfg(windows)]
    fn write_test_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(
            &path,
            "@echo off\r\necho arg=%1\r\necho env=%OMNE_TEST_VALUE%\r\n",
        )
        .expect("write windows command");
        path
    }

    #[cfg(windows)]
    fn write_pwd_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(&path, "@echo off\r\ncd\r\n").expect("write windows pwd command");
        path
    }

    #[cfg(windows)]
    fn write_count_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(&path, "@echo off\r\necho run>> \"%OMNE_COUNT_FILE%\"\r\n")
            .expect("write windows count command");
        path
    }

    #[cfg(windows)]
    fn write_failing_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(
            &path,
            "@echo off\r\n<nul set /p =stdout-message\r\n1>&2 <nul set /p =stderr-message\r\nexit /b 7\r\n",
        )
        .expect("write windows failing command");
        path
    }

    #[cfg(windows)]
    fn write_large_stdout_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(
            &path,
            "@echo off\r\npowershell -NoLogo -NoProfile -Command \"$s = 'x' * (8MB + 1); [Console]::Out.Write($s)\"\r\n",
        )
        .expect("write windows loud command");
        path
    }

    #[cfg(windows)]
    fn write_very_large_stdout_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(
            &path,
            "@echo off\r\npowershell -NoLogo -NoProfile -Command \"$s = 'x' * 32MB; [Console]::Out.Write($s)\"\r\n",
        )
        .expect("write windows very loud command");
        path
    }

    #[cfg(windows)]
    fn write_exact_limit_stdout_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(
            &path,
            "@echo off\r\npowershell -NoLogo -NoProfile -Command \"$s = 'x' * 8MB; [Console]::Out.Write($s)\"\r\n",
        )
        .expect("write windows exact-limit stdout command");
        path
    }

    #[cfg(windows)]
    fn write_large_stderr_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(
            &path,
            "@echo off\r\npowershell -NoLogo -NoProfile -Command \"$s = 'x' * (8MB + 1); [Console]::Error.Write($s)\"\r\n",
        )
        .expect("write windows loud stderr command");
        path
    }

    fn current_dir_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }
}
