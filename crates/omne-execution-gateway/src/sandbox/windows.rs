use std::path::Path;
use std::process::Command;

use crate::error::{ExecError, ExecResult};
use crate::sandbox::SandboxMonitor;
use policy_meta::ExecutionIsolation;

pub(crate) fn detect_supported_isolation() -> ExecutionIsolation {
    ExecutionIsolation::None
}

pub(crate) fn apply_sandbox(
    command: &mut Command,
    required_isolation: ExecutionIsolation,
    workspace_root: &Path,
) -> ExecResult<SandboxMonitor> {
    let _ = (command, workspace_root);
    match required_isolation {
        ExecutionIsolation::None => Ok(SandboxMonitor::none()),
        ExecutionIsolation::BestEffort | ExecutionIsolation::Strict => {
            Err(ExecError::IsolationNotSupported {
                requested: required_isolation,
                supported: ExecutionIsolation::None,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_only_none_isolation_as_supported() {
        assert_eq!(detect_supported_isolation(), ExecutionIsolation::None);
    }

    #[test]
    fn best_effort_and_strict_fail_closed() {
        let workspace = std::env::current_dir().expect("current_dir");
        let mut command = Command::new("cmd");
        command.args(["/C", "exit 0"]);

        let best_effort = apply_sandbox(
            &mut command,
            ExecutionIsolation::BestEffort,
            workspace.as_path(),
        )
        .expect_err("best_effort should fail closed on windows");
        assert!(matches!(
            best_effort,
            ExecError::IsolationNotSupported {
                requested: ExecutionIsolation::BestEffort,
                supported: ExecutionIsolation::None,
            }
        ));

        let strict = apply_sandbox(
            &mut command,
            ExecutionIsolation::Strict,
            workspace.as_path(),
        )
        .expect_err("strict should fail closed on windows");
        assert!(matches!(
            strict,
            ExecError::IsolationNotSupported {
                requested: ExecutionIsolation::Strict,
                supported: ExecutionIsolation::None,
            }
        ));
    }
}
