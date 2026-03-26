use std::path::Path;
use std::process::Command;
use std::time::Duration;

use landlock::{
    ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, RestrictionStatus,
    Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus,
};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;

use crate::audit::{SandboxRuntimeMechanism, SandboxRuntimeObservation, SandboxRuntimeOutcome};
use crate::error::ExecResult;
use crate::sandbox::SandboxMonitor;
use policy_meta::ExecutionIsolation;

const BEST_EFFORT_MONITOR_TIMEOUT: Duration = Duration::from_millis(250);

#[derive(Debug)]
pub(crate) struct LinuxSandboxMonitor {
    best_effort_stream: UnixStream,
}

impl LinuxSandboxMonitor {
    pub(crate) fn observe_after_spawn(mut self) -> SandboxRuntimeObservation {
        if let Err(err) = self
            .best_effort_stream
            .set_read_timeout(Some(BEST_EFFORT_MONITOR_TIMEOUT))
        {
            return landlock_runtime_observation(
                SandboxRuntimeOutcome::Error,
                Some(format!("set_read_timeout failed: {err}")),
            );
        }

        let mut buffer = [0_u8; 512];
        match self.best_effort_stream.read(&mut buffer) {
            Ok(0) => landlock_runtime_observation(
                SandboxRuntimeOutcome::Error,
                Some("missing best_effort landlock status".to_string()),
            ),
            Ok(n) => decode_best_effort_observation(&buffer[..n]),
            Err(err) => landlock_runtime_observation(
                SandboxRuntimeOutcome::Error,
                Some(format!("read best_effort landlock status failed: {err}")),
            ),
        }
    }
}

pub(crate) fn detect_supported_isolation() -> ExecutionIsolation {
    if landlock_strict_is_available() {
        ExecutionIsolation::Strict
    } else {
        ExecutionIsolation::BestEffort
    }
}

pub(crate) fn apply_sandbox(
    command: &mut Command,
    required_isolation: ExecutionIsolation,
    workspace_root: &Path,
) -> ExecResult<SandboxMonitor> {
    match required_isolation {
        ExecutionIsolation::None => {
            command.env("AGENT_EXEC_GATEWAY_WORKSPACE_ROOT", workspace_root);
            Ok(SandboxMonitor::none())
        }
        ExecutionIsolation::BestEffort => {
            let workspace_root = workspace_root.to_path_buf();
            let workspace_root_for_pre_exec = workspace_root.clone();
            let (parent_stream, mut child_stream) = UnixStream::pair()
                .map_err(|err| crate::error::ExecError::Sandbox(err.to_string()))?;
            // SAFETY:
            // - `Command::pre_exec` is the only std hook that lets us install Landlock in the
            //   child after `fork` but before `execve`; there is no safe API for this boundary.
            // - The closure captures only owned `PathBuf`/`UnixStream` values, so it does not
            //   dereference parent-stack references after the fork.
            // - Best-effort mode keeps this closure intentionally narrow: install Landlock, write a
            //   small status message to an already-open Unix socket, then return immediately.
            // - We do not let additional logic accumulate here; the whole point of this unsafe
            //   boundary is to keep post-fork work minimal and auditable.
            unsafe {
                command.pre_exec(move || {
                    let observation =
                        apply_landlock_best_effort_observation(&workspace_root_for_pre_exec);
                    let _ = write_best_effort_observation(&mut child_stream, &observation);
                    Ok(())
                });
            }
            command.env("AGENT_EXEC_GATEWAY_WORKSPACE_ROOT", workspace_root);
            Ok(SandboxMonitor::from_linux_best_effort(
                LinuxSandboxMonitor {
                    best_effort_stream: parent_stream,
                },
            ))
        }
        ExecutionIsolation::Strict => {
            let workspace_root = workspace_root.to_path_buf();
            let workspace_root_for_pre_exec = workspace_root.clone();
            // SAFETY:
            // - `pre_exec` is required because strict isolation must be installed in the child
            //   before `execve`, and std exposes that hook as unsafe.
            // - The closure captures only owned data and performs only the required sandbox setup,
            //   returning an `io::Error` immediately if Landlock cannot be fully enforced.
            // - We keep this closure small on purpose so the unsafe post-fork window contains only
            //   the isolation step that cannot happen anywhere else.
            unsafe {
                command.pre_exec(move || {
                    apply_landlock_strict(&workspace_root_for_pre_exec)?;
                    Ok(())
                });
            }
            command.env("AGENT_EXEC_GATEWAY_WORKSPACE_ROOT", workspace_root);
            Ok(SandboxMonitor::ready(landlock_runtime_observation(
                SandboxRuntimeOutcome::FullyEnforced,
                None,
            )))
        }
    }
}

fn landlock_strict_is_available() -> bool {
    let abi = ABI::V6;
    let ruleset = match Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(AccessFs::from_all(abi))
    {
        Ok(ruleset) => ruleset,
        Err(_) => return false,
    };
    ruleset.create().is_ok()
}

fn apply_landlock_strict(workspace_root: &Path) -> io::Result<()> {
    let status = apply_landlock(workspace_root, CompatLevel::HardRequirement)?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("landlock not fully enforced: {:?}", status.ruleset),
        ));
    }
    Ok(())
}

fn apply_landlock_best_effort_observation(workspace_root: &Path) -> SandboxRuntimeObservation {
    match apply_landlock(workspace_root, CompatLevel::BestEffort) {
        Ok(status) => landlock_status_observation(status),
        Err(err) => {
            landlock_runtime_observation(SandboxRuntimeOutcome::Error, Some(err.to_string()))
        }
    }
}

fn apply_landlock(
    workspace_root: &Path,
    compat_level: CompatLevel,
) -> io::Result<landlock::RestrictionStatus> {
    let abi = ABI::V6;
    let all_access = AccessFs::from_all(abi);
    let read_access = AccessFs::from_read(abi) | AccessFs::Execute;
    let runtime_device_rw_access = AccessFs::from_read(abi) | AccessFs::WriteFile;
    let runtime_device_ro_access = AccessFs::from_read(abi);
    let created = Ruleset::default()
        .set_compatibility(compat_level)
        .handle_access(all_access)
        .map_err(to_io_error)?
        .create()
        .map_err(to_io_error)?;

    created
        .add_rule(PathBeneath::new(
            PathFd::new("/").map_err(to_io_error)?,
            read_access,
        ))
        .map_err(to_io_error)?
        .add_rule(PathBeneath::new(
            PathFd::new(workspace_root).map_err(to_io_error)?,
            all_access,
        ))
        .map_err(to_io_error)?
        // Permit a minimal set of harmless device files that common Unix tools rely on.
        .add_rule(PathBeneath::new(
            PathFd::new("/dev/null").map_err(to_io_error)?,
            runtime_device_rw_access,
        ))
        .map_err(to_io_error)?
        .add_rule(PathBeneath::new(
            PathFd::new("/dev/zero").map_err(to_io_error)?,
            runtime_device_rw_access,
        ))
        .map_err(to_io_error)?
        .add_rule(PathBeneath::new(
            PathFd::new("/dev/random").map_err(to_io_error)?,
            runtime_device_ro_access,
        ))
        .map_err(to_io_error)?
        .add_rule(PathBeneath::new(
            PathFd::new("/dev/urandom").map_err(to_io_error)?,
            runtime_device_ro_access,
        ))
        .map_err(to_io_error)?
        .restrict_self()
        .map_err(to_io_error)
}

fn to_io_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, err.to_string())
}

fn landlock_status_observation(status: RestrictionStatus) -> SandboxRuntimeObservation {
    let outcome = match status.ruleset {
        RulesetStatus::FullyEnforced => SandboxRuntimeOutcome::FullyEnforced,
        RulesetStatus::PartiallyEnforced => SandboxRuntimeOutcome::PartiallyEnforced,
        RulesetStatus::NotEnforced => SandboxRuntimeOutcome::NotEnforced,
    };
    let detail = if outcome == SandboxRuntimeOutcome::FullyEnforced {
        None
    } else {
        Some(format!(
            "ruleset={:?}, no_new_privs={}, landlock={:?}",
            status.ruleset, status.no_new_privs, status.landlock
        ))
    };
    landlock_runtime_observation(outcome, detail)
}

fn landlock_runtime_observation(
    outcome: SandboxRuntimeOutcome,
    detail: Option<String>,
) -> SandboxRuntimeObservation {
    SandboxRuntimeObservation {
        mechanism: SandboxRuntimeMechanism::Landlock,
        outcome,
        detail,
    }
}

fn write_best_effort_observation(
    stream: &mut UnixStream,
    observation: &SandboxRuntimeObservation,
) -> io::Result<()> {
    let code = match observation.outcome {
        SandboxRuntimeOutcome::FullyEnforced => b'F',
        SandboxRuntimeOutcome::PartiallyEnforced => b'P',
        SandboxRuntimeOutcome::NotEnforced => b'N',
        SandboxRuntimeOutcome::Error => b'E',
    };
    stream.write_all(&[code])?;
    if let Some(detail) = &observation.detail {
        stream.write_all(detail.as_bytes())?;
    }
    stream.flush()?;
    Ok(())
}

fn decode_best_effort_observation(buffer: &[u8]) -> SandboxRuntimeObservation {
    let detail = (buffer.len() > 1).then(|| String::from_utf8_lossy(&buffer[1..]).into_owned());
    let outcome = match buffer.first().copied() {
        Some(b'F') => SandboxRuntimeOutcome::FullyEnforced,
        Some(b'P') => SandboxRuntimeOutcome::PartiallyEnforced,
        Some(b'N') => SandboxRuntimeOutcome::NotEnforced,
        Some(b'E') => SandboxRuntimeOutcome::Error,
        Some(other) => {
            return landlock_runtime_observation(
                SandboxRuntimeOutcome::Error,
                Some(format!("unknown best_effort landlock status code: {other}")),
            );
        }
        None => {
            return landlock_runtime_observation(
                SandboxRuntimeOutcome::Error,
                Some("empty best_effort landlock status payload".to_string()),
            );
        }
    };
    landlock_runtime_observation(outcome, detail)
}
