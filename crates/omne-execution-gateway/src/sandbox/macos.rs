use std::path::Path;
use std::process::Command;

use crate::error::{ExecError, ExecResult};
use crate::sandbox::SandboxMonitor;
use policy_meta::ExecutionIsolation;

pub(crate) fn detect_supported_isolation() -> ExecutionIsolation {
    ExecutionIsolation::BestEffort
}

pub(crate) fn apply_sandbox(
    command: &mut Command,
    required_isolation: ExecutionIsolation,
    workspace_root: &Path,
) -> ExecResult<SandboxMonitor> {
    match required_isolation {
        ExecutionIsolation::None | ExecutionIsolation::BestEffort => {
            command.env("AGENT_EXEC_GATEWAY_WORKSPACE_ROOT", workspace_root);
            Ok(SandboxMonitor::none())
        }
        ExecutionIsolation::Strict => Err(ExecError::Sandbox(
            "macOS strict isolation is not available in native mode".to_string(),
        )),
    }
}
