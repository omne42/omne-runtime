use std::path::Path;
use std::process::Command;

use crate::error::{ExecError, ExecResult};
use crate::sandbox::SandboxMonitor;
use crate::types::IsolationLevel;

pub fn detect_supported_isolation() -> IsolationLevel {
    IsolationLevel::BestEffort
}

pub fn apply_sandbox(
    command: &mut Command,
    required_isolation: IsolationLevel,
    workspace_root: &Path,
) -> ExecResult<SandboxMonitor> {
    match required_isolation {
        IsolationLevel::None | IsolationLevel::BestEffort => {
            command.env("AGENT_EXEC_GATEWAY_WORKSPACE_ROOT", workspace_root);
            Ok(SandboxMonitor::none())
        }
        IsolationLevel::Strict => Err(ExecError::Sandbox(
            "windows strict isolation is not available in native mode".to_string(),
        )),
    }
}
