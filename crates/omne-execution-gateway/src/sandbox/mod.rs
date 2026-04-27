use std::path::Path;
use std::process::Command;

use crate::audit::SandboxRuntimeObservation;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use crate::error::ExecError;
use crate::error::ExecResult;
use policy_meta::ExecutionIsolation;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Debug)]
pub(crate) struct SandboxMonitor {
    observation: Option<SandboxRuntimeObservation>,
}

impl SandboxMonitor {
    fn none() -> Self {
        Self { observation: None }
    }

    pub(crate) fn observe_after_spawn(self) -> Option<SandboxRuntimeObservation> {
        self.observation
    }

    #[cfg(all(test, unix))]
    pub(crate) fn with_observation(observation: Option<SandboxRuntimeObservation>) -> Self {
        Self { observation }
    }
}

pub(crate) fn detect_supported_isolation() -> ExecutionIsolation {
    platform_supported_isolation()
}

pub(crate) fn apply_sandbox(
    command: &mut Command,
    required_isolation: ExecutionIsolation,
    workspace_root: &Path,
) -> ExecResult<SandboxMonitor> {
    platform_apply_sandbox(command, required_isolation, workspace_root)
}

#[cfg(target_os = "linux")]
fn platform_supported_isolation() -> ExecutionIsolation {
    linux::detect_supported_isolation()
}

#[cfg(target_os = "macos")]
fn platform_supported_isolation() -> ExecutionIsolation {
    macos::detect_supported_isolation()
}

#[cfg(target_os = "windows")]
fn platform_supported_isolation() -> ExecutionIsolation {
    windows::detect_supported_isolation()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_supported_isolation() -> ExecutionIsolation {
    ExecutionIsolation::None
}

#[cfg(target_os = "linux")]
fn platform_apply_sandbox(
    command: &mut Command,
    required_isolation: ExecutionIsolation,
    workspace_root: &Path,
) -> ExecResult<SandboxMonitor> {
    linux::apply_sandbox(command, required_isolation, workspace_root)
}

#[cfg(target_os = "macos")]
fn platform_apply_sandbox(
    command: &mut Command,
    required_isolation: ExecutionIsolation,
    workspace_root: &Path,
) -> ExecResult<SandboxMonitor> {
    macos::apply_sandbox(command, required_isolation, workspace_root)
}

#[cfg(target_os = "windows")]
fn platform_apply_sandbox(
    command: &mut Command,
    required_isolation: ExecutionIsolation,
    workspace_root: &Path,
) -> ExecResult<SandboxMonitor> {
    windows::apply_sandbox(command, required_isolation, workspace_root)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn platform_apply_sandbox(
    _command: &mut Command,
    required_isolation: ExecutionIsolation,
    _workspace_root: &Path,
) -> ExecResult<SandboxMonitor> {
    match required_isolation {
        ExecutionIsolation::None => Ok(SandboxMonitor::none()),
        _ => Err(ExecError::Sandbox(
            "sandbox not supported on this platform".to_string(),
        )),
    }
}
