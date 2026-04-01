use std::path::Path;
use std::process::Command;

use crate::audit::SandboxRuntimeObservation;
use crate::error::{ExecError, ExecResult};
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

    #[cfg(test)]
    pub(crate) fn with_observation(observation: Option<SandboxRuntimeObservation>) -> Self {
        Self { observation }
    }
}

pub(crate) fn detect_supported_isolation() -> ExecutionIsolation {
    #[cfg(target_os = "linux")]
    {
        return linux::detect_supported_isolation();
    }

    #[cfg(target_os = "macos")]
    {
        return macos::detect_supported_isolation();
    }

    #[cfg(target_os = "windows")]
    {
        return windows::detect_supported_isolation();
    }

    #[allow(unreachable_code)]
    ExecutionIsolation::None
}

pub(crate) fn apply_sandbox(
    command: &mut Command,
    required_isolation: ExecutionIsolation,
    workspace_root: &Path,
) -> ExecResult<SandboxMonitor> {
    #[cfg(target_os = "linux")]
    {
        return linux::apply_sandbox(command, required_isolation, workspace_root);
    }

    #[cfg(target_os = "macos")]
    {
        return macos::apply_sandbox(command, required_isolation, workspace_root);
    }

    #[cfg(target_os = "windows")]
    {
        return windows::apply_sandbox(command, required_isolation, workspace_root);
    }

    #[allow(unreachable_code)]
    match required_isolation {
        ExecutionIsolation::None => Ok(SandboxMonitor::none()),
        _ => Err(ExecError::Sandbox(
            "sandbox not supported on this platform".to_string(),
        )),
    }
}
