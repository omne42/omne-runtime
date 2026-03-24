use std::path::Path;
use std::process::Command;

use crate::audit::SandboxRuntimeObservation;
use crate::error::{ExecError, ExecResult};
use crate::types::IsolationLevel;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Debug)]
pub struct SandboxMonitor {
    observation: Option<SandboxRuntimeObservation>,
    #[cfg(target_os = "linux")]
    linux_best_effort: Option<linux::LinuxSandboxMonitor>,
}

impl SandboxMonitor {
    fn none() -> Self {
        Self {
            observation: None,
            #[cfg(target_os = "linux")]
            linux_best_effort: None,
        }
    }

    fn ready(observation: SandboxRuntimeObservation) -> Self {
        Self {
            observation: Some(observation),
            #[cfg(target_os = "linux")]
            linux_best_effort: None,
        }
    }

    #[cfg(target_os = "linux")]
    fn from_linux_best_effort(monitor: linux::LinuxSandboxMonitor) -> Self {
        Self {
            observation: None,
            linux_best_effort: Some(monitor),
        }
    }

    pub fn observe_after_spawn(self) -> Option<SandboxRuntimeObservation> {
        #[cfg(target_os = "linux")]
        if let Some(monitor) = self.linux_best_effort {
            return Some(monitor.observe_after_spawn());
        }

        self.observation
    }
}

pub fn detect_supported_isolation() -> IsolationLevel {
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
    IsolationLevel::None
}

pub fn apply_sandbox(
    command: &mut Command,
    required_isolation: IsolationLevel,
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
        IsolationLevel::None => Ok(SandboxMonitor::none()),
        _ => Err(ExecError::Sandbox(
            "sandbox not supported on this platform".to_string(),
        )),
    }
}
