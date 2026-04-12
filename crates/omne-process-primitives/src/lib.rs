#![forbid(unsafe_code)]

//! Low-level process/runtime primitives shared by higher-level runtime code.
//!
//! This crate owns platform-specific building blocks for:
//! - probing whether host commands are present and spawnable
//! - executing host commands with captured output and optional sudo-style escalation
//! - configuring spawned commands so they can be cleaned up as a process tree
//! - capturing process-tree cleanup handles/identities from a spawned child
//! - best-effort process-tree termination on Unix and Windows
//!
//! Unix uses per-child process groups. Cleanup capture fails closed unless the spawned child is
//! the leader of its own dedicated process group, so callers cannot accidentally arm cleanup
//! against the parent's process group by skipping setup. Linux only proceeds to `killpg` after it
//! can revalidate the exact original leader `/proc` identity snapshot, and refuses orphan-group
//! cleanup once that identity is missing or no longer revalidates, so cleanup does not trust a
//! potentially reused PGID. Other Unix targets fail closed and skip `killpg` entirely because
//! this crate cannot revalidate leader lifetime with Linux-strength evidence there.
//!
//! Windows prefers Job Objects. When the current process cannot attach the child to a kill-on-close
//! job, cleanup falls back to best-effort tree cleanup rooted at the captured child PID:
//! `taskkill /T /F` while the leader is still alive, and a local root-plus-descendant kill sweep
//! if `taskkill` itself fails.

use std::io;
#[cfg(any(windows, test))]
use std::sync::{Mutex, MutexGuard};

mod command_path;
mod host_command;

pub use command_path::{
    resolve_command_path, resolve_command_path_or_standard_location,
    resolve_command_path_or_standard_location_os, resolve_command_path_os,
};
pub use host_command::{
    HostCommandCaptureOptions, HostCommandError, HostCommandExecution, HostCommandOutput,
    HostCommandRequest, HostCommandRunOptions, HostCommandSudoMode, HostRecipeError,
    HostRecipeRequest, command_available, command_available_for_request, command_available_os,
    command_exists, command_exists_for_request, command_exists_os, command_path_exists,
    default_recipe_sudo_mode_for_program, run_host_command, run_host_command_with_capture_options,
    run_host_command_with_options, run_host_recipe, run_host_recipe_with_capture_options,
    run_host_recipe_with_options,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupDisposition {
    TreeTerminationInitiated,
    DirectChildKillRequired,
}

pub fn configure_std_command_for_process_tree(command: &mut std::process::Command) {
    configure_std_command_for_process_group(command);
}

pub fn configure_command_for_process_tree(command: &mut tokio::process::Command) {
    configure_tokio_command_for_process_group(command);
    command.kill_on_drop(true);
}

pub struct ProcessTreeCleanup {
    #[cfg(windows)]
    windows_job: Option<win32job::Job>,
    #[cfg(windows)]
    windows_process_identity: Mutex<Option<WindowsProcessIdentity>>,
    #[cfg(unix)]
    unix_process_group: Option<UnixProcessGroupIdentity>,
}

impl ProcessTreeCleanup {
    #[cfg(windows)]
    pub fn new(child: &tokio::process::Child) -> io::Result<Self> {
        Ok(Self {
            windows_job: maybe_attach_windows_kill_job(child)?,
            windows_process_identity: Mutex::new(capture_windows_process_identity(child.id())),
        })
    }

    #[cfg(not(windows))]
    pub fn new(child: &tokio::process::Child) -> io::Result<Self> {
        Self::from_pid(child.id().ok_or_else(|| {
            io::Error::other("cannot capture process-tree identity for a child without a pid")
        })?)
    }

    pub fn from_std_child(child: &std::process::Child) -> io::Result<Self> {
        Self::from_pid(child.id())
    }

    #[cfg(windows)]
    pub fn from_pid(pid: u32) -> io::Result<Self> {
        Ok(Self {
            windows_job: None,
            windows_process_identity: Mutex::new(capture_windows_process_identity(Some(pid))),
        })
    }

    #[cfg(not(windows))]
    pub fn from_pid(pid: u32) -> io::Result<Self> {
        Ok(Self {
            #[cfg(unix)]
            unix_process_group: capture_unix_process_group_identity(pid)?,
        })
    }

    #[cfg(windows)]
    pub fn start_termination(&mut self) -> CleanupDisposition {
        if self.windows_job.take().is_some() {
            take_windows_process_identity(&self.windows_process_identity);
            CleanupDisposition::TreeTerminationInitiated
        } else {
            CleanupDisposition::DirectChildKillRequired
        }
    }

    #[cfg(not(windows))]
    pub fn start_termination(&mut self) -> CleanupDisposition {
        let _ = self;
        CleanupDisposition::DirectChildKillRequired
    }

    pub fn kill_tree(&self) {
        kill_process_tree(self);
    }
}

#[cfg(unix)]
fn configure_std_command_for_process_group(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_std_command_for_process_group(_command: &mut std::process::Command) {}

#[cfg(unix)]
fn configure_tokio_command_for_process_group(command: &mut tokio::process::Command) {
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_tokio_command_for_process_group(_command: &mut tokio::process::Command) {}

#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct UnixProcessGroupIdentity {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    leader_pid: rustix::process::Pid,
    process_group_id: rustix::process::Pid,
    #[cfg(target_os = "linux")]
    leader_identity: LinuxProcessIdentity,
}

#[cfg(all(unix, target_os = "linux"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LinuxProcessIdentity {
    parent_pid: i32,
    process_group_id: i32,
    session_id: i32,
    start_ticks: u64,
}

#[cfg(unix)]
fn capture_unix_process_group_identity(pid: u32) -> io::Result<Option<UnixProcessGroupIdentity>> {
    let leader_pid = child_process_pid(pid).ok_or_else(|| {
        io::Error::other("cannot capture process-tree identity for a child without a pid")
    })?;
    #[cfg(target_os = "linux")]
    {
        capture_linux_process_group_identity(leader_pid)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let process_group_id = match rustix::process::getpgid(Some(leader_pid)) {
            Ok(process_group_id) => process_group_id,
            Err(rustix::io::Errno::SRCH) => return Ok(None),
            Err(error) => return Err(io::Error::from(error)),
        };
        ensure_unix_process_group_is_dedicated(leader_pid, process_group_id)?;
        Ok(Some(UnixProcessGroupIdentity {
            leader_pid,
            process_group_id,
        }))
    }
}

#[cfg(target_os = "linux")]
fn capture_linux_process_group_identity(
    leader_pid: rustix::process::Pid,
) -> io::Result<Option<UnixProcessGroupIdentity>> {
    let leader_identity = match read_linux_process_identity(leader_pid) {
        Ok(identity) => identity,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "process-tree cleanup requires a live Linux process-group leader identity during capture",
            ));
        }
        Err(error) => return Err(error),
    };
    let leader_identity = ensure_linux_leader_is_current_child(leader_identity)?;
    build_linux_process_group_identity(leader_pid, leader_identity).map(Some)
}

#[cfg(target_os = "linux")]
fn ensure_linux_leader_is_current_child(
    identity: LinuxProcessIdentity,
) -> io::Result<LinuxProcessIdentity> {
    let current_pid = i32::try_from(std::process::id())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid current process id"))?;
    if identity.parent_pid == current_pid {
        return Ok(identity);
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "process-tree cleanup requires the captured Linux process-group leader to still be this process child during capture",
    ))
}

#[cfg(target_os = "linux")]
fn build_linux_process_group_identity(
    leader_pid: rustix::process::Pid,
    leader_identity: LinuxProcessIdentity,
) -> io::Result<UnixProcessGroupIdentity> {
    let process_group_id = rustix::process::Pid::from_raw(leader_identity.process_group_id)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid proc group id"))?;
    ensure_unix_process_group_is_dedicated(leader_pid, process_group_id)?;
    Ok(UnixProcessGroupIdentity {
        leader_pid,
        process_group_id,
        leader_identity,
    })
}

#[cfg(unix)]
fn child_process_pid(pid: u32) -> Option<rustix::process::Pid> {
    let raw_pid = i32::try_from(pid).ok()?;
    rustix::process::Pid::from_raw(raw_pid)
}

#[cfg(unix)]
fn ensure_unix_process_group_is_dedicated(
    leader_pid: rustix::process::Pid,
    process_group_id: rustix::process::Pid,
) -> io::Result<()> {
    if process_group_id == leader_pid {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "process-tree cleanup requires the child to lead a dedicated process group; call configure_command_for_process_tree before spawning",
    ))
}

#[cfg(unix)]
fn kill_process_tree(cleanup: &ProcessTreeCleanup) {
    use rustix::io::Errno;
    use rustix::process::{Signal, kill_process_group};

    let Some(identity) = cleanup.unix_process_group else {
        return;
    };
    if !should_kill_unix_process_group(identity) {
        return;
    }

    match kill_process_group(identity.process_group_id, Signal::KILL) {
        Ok(()) | Err(Errno::SRCH) => {}
        Err(_) => {}
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn should_kill_unix_process_group(identity: UnixProcessGroupIdentity) -> bool {
    let _ = identity;
    false
}

#[cfg(target_os = "linux")]
fn should_kill_unix_process_group(identity: UnixProcessGroupIdentity) -> bool {
    // Linux only arms `killpg` while the original leader still matches the exact `/proc`
    // identity captured at spawn time; once that identity disappears, cleanup fails closed.
    should_kill_linux_process_group(identity, read_linux_process_identity(identity.leader_pid))
}

#[cfg(target_os = "linux")]
fn should_kill_linux_process_group(
    identity: UnixProcessGroupIdentity,
    current: io::Result<LinuxProcessIdentity>,
) -> bool {
    match current {
        Ok(current) => current == identity.leader_identity,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => false,
    }
}

#[cfg(all(unix, target_os = "linux"))]
fn read_linux_process_identity(pid: rustix::process::Pid) -> io::Result<LinuxProcessIdentity> {
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_pid()))?;
    parse_linux_process_identity_stat(&stat)
}

#[cfg(all(unix, target_os = "linux"))]
fn parse_linux_process_identity_stat(stat: &str) -> io::Result<LinuxProcessIdentity> {
    let tail = stat
        .rsplit_once(") ")
        .map(|(_, tail)| tail)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid /proc stat"))?;
    let mut fields = tail.split_whitespace();
    let _state = fields
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc state"))?;
    let parent_pid = parse_proc_stat_i32(fields.next(), "missing proc parent pid")?;
    let process_group_id = parse_proc_stat_i32(fields.next(), "missing proc group id")?;
    let session_id = parse_proc_stat_i32(fields.next(), "missing proc session id")?;
    for _ in 0..15 {
        let _ = fields
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing proc stat field"))?;
    }
    let start_ticks = parse_proc_stat_u64(fields.next(), "missing proc start time")?;
    Ok(LinuxProcessIdentity {
        parent_pid,
        process_group_id,
        session_id,
        start_ticks,
    })
}

#[cfg(all(unix, target_os = "linux"))]
fn parse_proc_stat_i32(raw: Option<&str>, message: &'static str) -> io::Result<i32> {
    raw.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, message))?
        .parse::<i32>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(all(unix, target_os = "linux"))]
fn parse_proc_stat_u64(raw: Option<&str>, message: &'static str) -> io::Result<u64> {
    raw.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, message))?
        .parse::<u64>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

#[cfg(all(not(windows), not(unix)))]
fn kill_process_tree(_cleanup: &ProcessTreeCleanup) {}

#[cfg(any(windows, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WindowsProcessIdentity {
    pid: u32,
    start_time: u64,
}

#[cfg(windows)]
fn kill_process_tree(cleanup: &ProcessTreeCleanup) {
    kill_windows_process_tree(
        cleanup.windows_job.is_some(),
        &cleanup.windows_process_identity,
        windows_taskkill_tree,
        kill_windows_remaining_process_tree,
    );
}

#[cfg(any(windows, test))]
fn take_windows_process_identity(
    process_id: &Mutex<Option<WindowsProcessIdentity>>,
) -> Option<WindowsProcessIdentity> {
    lock_windows_process_identity(process_id).take()
}

#[cfg(any(windows, test))]
fn lock_windows_process_identity(
    process_id: &Mutex<Option<WindowsProcessIdentity>>,
) -> MutexGuard<'_, Option<WindowsProcessIdentity>> {
    process_id
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(any(windows, test))]
fn kill_windows_process_tree<F, G>(
    has_windows_job: bool,
    process_id: &Mutex<Option<WindowsProcessIdentity>>,
    taskkill_tree: F,
    fallback: G,
) where
    F: FnOnce(WindowsProcessIdentity) -> io::Result<()>,
    G: FnOnce(WindowsProcessIdentity) -> io::Result<()>,
{
    if has_windows_job {
        return;
    }

    let Some(identity) = *lock_windows_process_identity(process_id) else {
        return;
    };

    let termination_result = taskkill_tree(identity).or_else(|_| fallback(identity));
    if termination_result.is_ok() {
        take_windows_process_identity(process_id);
    }
}

#[cfg(windows)]
fn windows_taskkill_program() -> std::path::PathBuf {
    std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(|root| {
            std::path::PathBuf::from(root)
                .join("System32")
                .join("taskkill.exe")
        })
        .unwrap_or_else(|| std::path::PathBuf::from("taskkill"))
}

#[cfg(test)]
fn process_identity_matches(
    identity: WindowsProcessIdentity,
    processes: impl IntoIterator<Item = WindowsProcessIdentity>,
) -> bool {
    processes.into_iter().any(|candidate| candidate == identity)
}

#[cfg(windows)]
fn windows_taskkill_tree(identity: WindowsProcessIdentity) -> io::Result<()> {
    let snapshot = windows_process_snapshot();
    if !snapshot_contains_process_identity(&snapshot, identity) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "root process identity no longer matches before taskkill",
        ));
    }

    let status = std::process::Command::new(windows_taskkill_program())
        .args(["/T", "/F", "/PID", &identity.pid.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if status.success() {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "taskkill exited unsuccessfully for pid {}: {status}",
        identity.pid
    )))
}

#[cfg(windows)]
fn kill_windows_remaining_process_tree(identity: WindowsProcessIdentity) -> io::Result<()> {
    use sysinfo::Pid;

    let snapshot = windows_process_snapshot();
    if !snapshot_contains_process_identity(&snapshot, identity) {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "root process identity no longer matches before fallback cleanup",
        ));
    }
    let remaining_tree = collect_process_tree_pids(
        snapshot
            .processes()
            .iter()
            .map(|(pid, process)| (pid.as_u32(), process.parent().map(|parent| parent.as_u32()))),
        identity.pid,
    );

    let mut root_kill_failed = false;
    for pid in remaining_tree {
        if let Some(process) = snapshot.process(Pid::from_u32(pid)) {
            let killed = process.kill();
            if pid == identity.pid && !killed {
                root_kill_failed = true;
            }
        }
    }

    if root_kill_failed {
        return Err(io::Error::other(format!(
            "failed to terminate root process {} after taskkill failure",
            identity.pid
        )));
    }

    Ok(())
}

#[cfg(windows)]
fn windows_process_snapshot() -> sysinfo::System {
    use sysinfo::{ProcessRefreshKind, RefreshKind, System};

    System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
    )
}

#[cfg(windows)]
fn snapshot_contains_process_identity(
    snapshot: &sysinfo::System,
    identity: WindowsProcessIdentity,
) -> bool {
    use sysinfo::Pid;

    snapshot
        .process(Pid::from_u32(identity.pid))
        .is_some_and(|process| process.start_time() == identity.start_time)
}

#[cfg(windows)]
fn capture_windows_process_identity(pid: Option<u32>) -> Option<WindowsProcessIdentity> {
    use sysinfo::Pid;

    let pid = pid?;
    let snapshot = windows_process_snapshot();
    let process = snapshot.process(Pid::from_u32(pid))?;
    Some(WindowsProcessIdentity {
        pid,
        start_time: process.start_time(),
    })
}

#[cfg(any(windows, test))]
fn collect_descendant_pids(
    processes: impl IntoIterator<Item = (u32, Option<u32>)>,
    root_pid: u32,
) -> Vec<u32> {
    use std::collections::{BTreeMap, BTreeSet};

    let mut children_by_parent = BTreeMap::<u32, Vec<u32>>::new();
    for (pid, parent) in processes {
        if let Some(parent) = parent {
            children_by_parent.entry(parent).or_default().push(pid);
        }
    }

    let mut descendants = Vec::new();
    let mut stack = vec![(root_pid, false)];
    let mut visited = BTreeSet::new();

    while let Some((pid, expanded)) = stack.pop() {
        if expanded {
            if pid != root_pid {
                descendants.push(pid);
            }
            continue;
        }

        if !visited.insert(pid) {
            continue;
        }

        stack.push((pid, true));
        if let Some(children) = children_by_parent.get(&pid) {
            for &child in children.iter().rev() {
                stack.push((child, false));
            }
        }
    }

    descendants
}

#[cfg(any(windows, test))]
fn collect_process_tree_pids(
    processes: impl IntoIterator<Item = (u32, Option<u32>)>,
    root_pid: u32,
) -> Vec<u32> {
    let mut pids = collect_descendant_pids(processes, root_pid);
    pids.push(root_pid);
    pids
}

#[cfg(test)]
mod descendant_tests {
    use std::io;
    use std::sync::Mutex;

    use super::{
        WindowsProcessIdentity, collect_descendant_pids, collect_process_tree_pids,
        kill_windows_process_tree, process_identity_matches,
    };

    #[test]
    fn collect_descendant_pids_returns_postorder_descendants_only() {
        let processes = [
            (10, None),
            (11, Some(10)),
            (12, Some(10)),
            (13, Some(11)),
            (14, Some(13)),
            (20, None),
        ];

        assert_eq!(collect_descendant_pids(processes, 10), vec![14, 13, 11, 12]);
    }

    #[test]
    fn collect_descendant_pids_ignores_unrelated_cycles() {
        let processes = [(10, None), (11, Some(10)), (21, Some(22)), (22, Some(21))];

        assert_eq!(collect_descendant_pids(processes, 10), vec![11]);
    }

    #[test]
    fn collect_process_tree_pids_includes_root_after_descendants() {
        let processes = [(10, None), (11, Some(10)), (12, Some(10)), (13, Some(11))];

        assert_eq!(
            collect_process_tree_pids(processes, 10),
            vec![13, 11, 12, 10]
        );
    }

    #[test]
    fn process_identity_matches_requires_matching_pid_and_start_time() {
        let identity = WindowsProcessIdentity {
            pid: 42,
            start_time: 100,
        };

        assert!(process_identity_matches(
            identity,
            [WindowsProcessIdentity {
                pid: 42,
                start_time: 100
            }]
        ));
        assert!(!process_identity_matches(
            identity,
            [WindowsProcessIdentity {
                pid: 42,
                start_time: 101
            }]
        ));
        assert!(!process_identity_matches(
            identity,
            [WindowsProcessIdentity {
                pid: 43,
                start_time: 100
            }]
        ));
    }

    #[test]
    fn windows_fallback_runs_when_taskkill_returns_error() {
        let identity = WindowsProcessIdentity {
            pid: 42,
            start_time: 7,
        };
        let process_id = Mutex::new(Some(identity));
        let mut taskkill_attempts = Vec::new();
        let mut fallback_identities = Vec::new();

        kill_windows_process_tree(
            false,
            &process_id,
            |identity| {
                taskkill_attempts.push(identity);
                Err(io::Error::other("taskkill failed"))
            },
            |identity| {
                fallback_identities.push(identity);
                Ok(())
            },
        );

        assert_eq!(taskkill_attempts, vec![identity]);
        assert_eq!(fallback_identities, vec![identity]);
        assert_eq!(*process_id.lock().expect("lock pid"), None);
    }

    #[test]
    fn windows_fallback_skips_when_taskkill_succeeds() {
        let identity = WindowsProcessIdentity {
            pid: 42,
            start_time: 7,
        };
        let process_id = Mutex::new(Some(identity));
        let mut taskkill_attempts = Vec::new();
        let mut fallback_identities = Vec::new();

        kill_windows_process_tree(
            false,
            &process_id,
            |identity| {
                taskkill_attempts.push(identity);
                Ok(())
            },
            |identity| {
                fallback_identities.push(identity);
                Ok(())
            },
        );

        assert_eq!(taskkill_attempts, vec![identity]);
        assert!(fallback_identities.is_empty());
        assert_eq!(*process_id.lock().expect("lock pid"), None);
    }

    #[test]
    fn windows_fallback_keeps_pid_when_root_termination_still_fails() {
        let identity = WindowsProcessIdentity {
            pid: 42,
            start_time: 7,
        };
        let process_id = Mutex::new(Some(identity));
        let mut taskkill_attempts = Vec::new();
        let mut fallback_identities = Vec::new();

        kill_windows_process_tree(
            false,
            &process_id,
            |identity| {
                taskkill_attempts.push(identity);
                Err(io::Error::other("taskkill failed"))
            },
            |identity| {
                fallback_identities.push(identity);
                Err(io::Error::other("fallback failed"))
            },
        );

        assert_eq!(taskkill_attempts, vec![identity]);
        assert_eq!(fallback_identities, vec![identity]);
        assert_eq!(*process_id.lock().expect("lock pid"), Some(identity));
    }
}

#[cfg(windows)]
fn maybe_attach_windows_kill_job(
    child: &tokio::process::Child,
) -> io::Result<Option<win32job::Job>> {
    use win32job::{ExtendedLimitInfo, Job};

    let Some(process_handle) = child.raw_handle() else {
        return Ok(None);
    };
    if process_handle.is_null() {
        return Ok(None);
    }

    let job = Job::create().map_err(io::Error::from)?;
    let mut limits = ExtendedLimitInfo::new();
    limits.limit_kill_on_job_close();
    job.set_extended_limit_info(&limits)
        .map_err(io::Error::from)?;

    match job.assign_process(process_handle as isize) {
        Ok(()) => Ok(Some(job)),
        Err(error) => {
            let error = io::Error::from(error);
            match error.raw_os_error() {
                Some(WINDOWS_ERROR_ACCESS_DENIED) | Some(WINDOWS_ERROR_NOT_SUPPORTED) => Ok(None),
                _ => Err(error),
            }
        }
    }
}

#[cfg(windows)]
const WINDOWS_ERROR_ACCESS_DENIED: i32 = 5;

#[cfg(windows)]
const WINDOWS_ERROR_NOT_SUPPORTED: i32 = 50;

#[cfg(all(test, unix, target_os = "linux"))]
mod tests {
    use super::{
        CleanupDisposition, LinuxProcessIdentity, ProcessTreeCleanup, UnixProcessGroupIdentity,
        build_linux_process_group_identity, capture_linux_process_group_identity,
        configure_command_for_process_tree, configure_std_command_for_process_tree,
        ensure_linux_leader_is_current_child, ensure_unix_process_group_is_dedicated,
        parse_linux_process_identity_stat, should_kill_linux_process_group,
    };
    use rustix::process::{Pid, Signal, kill_process};
    use std::io;
    use std::path::Path;
    use std::process::Stdio;
    use std::time::Duration;

    fn fixture_identity(
        process_group_id: i32,
        session_id: i32,
        start_ticks: u64,
    ) -> LinuxProcessIdentity {
        LinuxProcessIdentity {
            parent_pid: 1,
            process_group_id,
            session_id,
            start_ticks,
        }
    }

    #[test]
    fn reused_leader_pid_fails_closed_even_if_surviving_group_members_remain() {
        let identity = UnixProcessGroupIdentity {
            leader_pid: Pid::from_raw(4242).expect("leader pid must be non-zero"),
            process_group_id: Pid::from_raw(31337).expect("process group id must be non-zero"),
            leader_identity: fixture_identity(31337, 7, 11),
        };

        assert!(!should_kill_linux_process_group(
            identity,
            Ok(fixture_identity(9999, 7, 22)),
        ));
    }

    #[test]
    fn reused_leader_pid_fails_closed_when_linux_process_group_is_gone() {
        let identity = UnixProcessGroupIdentity {
            leader_pid: Pid::from_raw(4242).expect("leader pid must be non-zero"),
            process_group_id: Pid::from_raw(31337).expect("process group id must be non-zero"),
            leader_identity: fixture_identity(31337, 7, 11),
        };

        assert!(!should_kill_linux_process_group(
            identity,
            Err(io::ErrorKind::NotFound.into()),
        ));
    }

    #[test]
    fn orphaned_group_fails_closed_when_leader_exited_before_capture_completed() {
        let identity = UnixProcessGroupIdentity {
            leader_pid: Pid::from_raw(4242).expect("leader pid must be non-zero"),
            process_group_id: Pid::from_raw(31337).expect("process group id must be non-zero"),
            leader_identity: fixture_identity(31337, 7, 11),
        };

        assert!(!should_kill_linux_process_group(
            identity,
            Err(io::ErrorKind::NotFound.into()),
        ));
    }

    #[test]
    fn reused_leader_pid_still_fails_closed_when_start_ticks_change() {
        let identity = UnixProcessGroupIdentity {
            leader_pid: Pid::from_raw(4242).expect("leader pid must be non-zero"),
            process_group_id: Pid::from_raw(31337).expect("process group id must be non-zero"),
            leader_identity: fixture_identity(31337, 7, 11),
        };

        assert!(!should_kill_linux_process_group(
            identity,
            Ok(fixture_identity(31337, 7, 22)),
        ));
    }

    #[test]
    fn leader_session_mismatch_fails_closed_even_when_group_and_ticks_match() {
        let identity = UnixProcessGroupIdentity {
            leader_pid: Pid::from_raw(4242).expect("leader pid must be non-zero"),
            process_group_id: Pid::from_raw(31337).expect("process group id must be non-zero"),
            leader_identity: fixture_identity(31337, 7, 11),
        };

        assert!(!should_kill_linux_process_group(
            identity,
            Ok(fixture_identity(31337, 99, 11)),
        ));
    }

    #[test]
    fn leader_exit_after_capture_fails_closed() {
        let identity = UnixProcessGroupIdentity {
            leader_pid: Pid::from_raw(4242).expect("leader pid must be non-zero"),
            process_group_id: Pid::from_raw(31337).expect("process group id must be non-zero"),
            leader_identity: fixture_identity(31337, 7, 11),
        };

        assert!(!should_kill_linux_process_group(
            identity,
            Err(io::ErrorKind::NotFound.into()),
        ));
    }

    #[test]
    fn dedicated_process_group_validation_rejects_shared_group() {
        let leader_pid = Pid::from_raw(4242).expect("leader pid must be non-zero");
        let shared_group = Pid::from_raw(77).expect("shared group id must be non-zero");

        let err = ensure_unix_process_group_is_dedicated(leader_pid, shared_group)
            .expect_err("shared process group must be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string()
                .contains("configure_command_for_process_tree"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn linux_capture_identity_uses_single_snapshot_for_group_and_leader_identity() {
        let leader_pid = Pid::from_raw(4242).expect("leader pid must be non-zero");
        let identity =
            build_linux_process_group_identity(leader_pid, fixture_identity(4242, 7, 11))
                .expect("dedicated process group snapshot should be accepted");

        assert_eq!(identity.leader_pid, leader_pid);
        assert_eq!(identity.process_group_id, leader_pid);
        assert_eq!(identity.leader_identity, fixture_identity(4242, 7, 11));
    }

    #[test]
    fn linux_capture_identity_rejects_invalid_zero_process_group_id() {
        let leader_pid = Pid::from_raw(4242).expect("leader pid must be non-zero");
        let err = build_linux_process_group_identity(leader_pid, fixture_identity(0, 7, 11))
            .expect_err("zero pgid must fail closed");

        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("invalid proc group id"));
    }

    #[test]
    fn linux_capture_fails_closed_when_leader_identity_is_already_gone() {
        let impossible_pid = Pid::from_raw(999_999).expect("pid must be non-zero");
        let err = capture_linux_process_group_identity(impossible_pid)
            .expect_err("missing leader identity must fail closed");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(
            err.to_string()
                .contains("live Linux process-group leader identity")
        );
    }

    #[test]
    fn linux_process_identity_parser_uses_one_snapshot_even_with_parens_in_comm() {
        let identity = parse_linux_process_identity_stat(
            "4242 (worker ) name) S 1 4242 7 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 11",
        )
        .expect("parse proc stat");

        assert_eq!(identity, fixture_identity(4242, 7, 11));
    }

    #[test]
    fn linux_capture_rejects_identity_when_leader_is_not_current_child() {
        let current_pid = i32::try_from(std::process::id()).expect("pid fits i32");
        let err = ensure_linux_leader_is_current_child(LinuxProcessIdentity {
            parent_pid: current_pid.saturating_add(1),
            process_group_id: 4242,
            session_id: 7,
            start_ticks: 11,
        })
        .expect_err("non-child identity must fail closed");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn linux_capture_accepts_identity_when_leader_is_current_child() {
        let current_pid = i32::try_from(std::process::id()).expect("pid fits i32");
        let identity = ensure_linux_leader_is_current_child(LinuxProcessIdentity {
            parent_pid: current_pid,
            process_group_id: 4242,
            session_id: 7,
            start_ticks: 11,
        })
        .expect("current child identity should be accepted");
        assert_eq!(identity.parent_pid, current_pid);
    }

    #[test]
    fn std_child_cleanup_capture_supports_same_dedicated_group_contract() -> io::Result<()> {
        let mut command = std::process::Command::new("sh");
        command
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_std_command_for_process_tree(&mut command);

        let mut child = command.spawn()?;
        let mut cleanup = ProcessTreeCleanup::from_std_child(&child)?;

        assert_eq!(
            cleanup.start_termination(),
            CleanupDisposition::DirectChildKillRequired
        );
        cleanup.kill_tree();

        let child_pid = Pid::from_raw(i32::try_from(child.id()).expect("pid fits i32"))
            .expect("child pid must be non-zero");
        let _ = kill_process(child_pid, Signal::KILL);
        let _ = child.wait();
        Ok(())
    }

    fn process_terminated_or_zombie(pid: u32) -> bool {
        let status_path = format!("/proc/{pid}/status");
        match std::fs::read_to_string(status_path) {
            Ok(status) => status
                .lines()
                .find(|line| line.starts_with("State:"))
                .map(|line| line.contains("\tZ") || line.contains(" zombie"))
                .unwrap_or(false),
            Err(err) => err.kind() == io::ErrorKind::NotFound,
        }
    }

    async fn wait_for_pid(path: &Path) -> Option<u32> {
        for _ in 0..100 {
            if let Ok(raw) = tokio::fs::read_to_string(path).await
                && let Ok(pid) = raw.trim().parse::<u32>()
            {
                return Some(pid);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        None
    }

    #[tokio::test]
    async fn cleanup_does_not_kill_process_group_without_strong_identity_revalidation()
    -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let pid_file = dir.path().join("background.pid");
        let script = format!("sleep 30 & echo $! > '{}'; wait", pid_file.display());

        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_command_for_process_tree(&mut command);

        let mut child = command.spawn()?;
        let mut cleanup = ProcessTreeCleanup::new(&child)?;
        let pid = wait_for_pid(&pid_file)
            .await
            .expect("background pid file should be written");

        assert_eq!(
            cleanup.start_termination(),
            CleanupDisposition::DirectChildKillRequired
        );
        cleanup.kill_tree();
        let _ = child.kill().await;
        let _ = child.wait().await;

        let mut gone = false;
        for _ in 0..300 {
            if process_terminated_or_zombie(pid) {
                gone = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(gone, "background process group should be terminated");
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_does_not_kill_child_process_group_after_leader_dies_before_kill_tree()
    -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let pid_file = dir.path().join("background.pid");
        let script = format!("sleep 30 & echo $! > '{}'; wait", pid_file.display());

        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_command_for_process_tree(&mut command);

        let mut child = command.spawn()?;
        let mut cleanup = ProcessTreeCleanup::new(&child)?;
        let pid = wait_for_pid(&pid_file)
            .await
            .expect("background pid file should be written");

        assert_eq!(
            cleanup.start_termination(),
            CleanupDisposition::DirectChildKillRequired
        );
        let _ = child.kill().await;
        let _ = child.wait().await;
        cleanup.kill_tree();

        let mut alive = true;
        for _ in 0..100 {
            if process_terminated_or_zombie(pid) {
                alive = false;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            alive,
            "cleanup must fail closed when the leader is already gone before kill_tree"
        );
        let _ = kill_process(
            Pid::from_raw(pid as i32).expect("background pid should fit i32"),
            Signal::KILL,
        );
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_created_after_leader_exit_still_fails_closed_once_the_leader_is_reaped()
    -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let shell_pid_file = dir.path().join("shell.pid");
        let bg_pid_file = dir.path().join("background.pid");
        let script = format!(
            "echo $$ > '{shell}'; sleep 30 & echo $! > '{background}'; exit 0",
            shell = shell_pid_file.display(),
            background = bg_pid_file.display()
        );

        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_command_for_process_tree(&mut command);

        let mut child = command.spawn()?;
        let shell_pid = wait_for_pid(&shell_pid_file)
            .await
            .expect("shell pid file should be written");
        let bg_pid = wait_for_pid(&bg_pid_file)
            .await
            .expect("background pid file should be written");

        let mut leader_exited = false;
        for _ in 0..300 {
            if process_terminated_or_zombie(shell_pid) {
                leader_exited = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            leader_exited,
            "shell leader should exit before cleanup capture"
        );

        let mut cleanup = ProcessTreeCleanup::new(&child)?;
        assert_eq!(
            cleanup.start_termination(),
            CleanupDisposition::DirectChildKillRequired
        );

        let _ = child.wait().await;
        cleanup.kill_tree();

        assert!(
            !process_terminated_or_zombie(bg_pid),
            "cleanup must still fail closed after the exited leader has been reaped"
        );

        let _ = kill_process(
            Pid::from_raw(bg_pid as i32).expect("background pid should fit i32"),
            Signal::KILL,
        );
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_rejects_child_without_dedicated_process_group() -> io::Result<()> {
        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg("sleep 30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = command.spawn()?;
        let err = ProcessTreeCleanup::new(&child)
            .err()
            .expect("non-isolated child must not arm process-tree cleanup");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let _ = child.kill().await;
        let _ = child.wait().await;
        Ok(())
    }
}

#[cfg(all(test, unix, not(target_os = "linux")))]
mod unix_tests {
    use super::{CleanupDisposition, ProcessTreeCleanup, configure_command_for_process_tree};
    use rustix::io::Errno;
    use rustix::process::{Pid, Signal, kill_process, test_kill_process_group};
    use std::io;
    use std::path::Path;
    use std::process::Stdio;
    use std::time::Duration;

    async fn wait_for_pid(path: &Path) -> Option<u32> {
        for _ in 0..100 {
            if let Ok(raw) = tokio::fs::read_to_string(path).await
                && let Ok(pid) = raw.trim().parse::<u32>()
            {
                return Some(pid);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        None
    }

    fn process_group_gone(process_group: Pid) -> bool {
        matches!(test_kill_process_group(process_group), Err(Errno::SRCH))
    }

    fn pid_to_process_group(pid: u32) -> Pid {
        Pid::from_raw(i32::try_from(pid).expect("pid should fit in i32"))
            .expect("process group id must be non-zero")
    }

    #[tokio::test]
    async fn cleanup_does_not_kill_process_group_without_strong_identity_revalidation()
    -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let pid_file = dir.path().join("background.pid");
        let script = format!("sleep 30 & echo $! > '{}'; wait", pid_file.display());

        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_command_for_process_tree(&mut command);

        let mut child = command.spawn()?;
        let mut cleanup = ProcessTreeCleanup::new(&child)?;
        let process_group = pid_to_process_group(child.id().expect("child pid should exist"));
        let bg_pid = wait_for_pid(&pid_file)
            .await
            .expect("background pid file should be written");
        let background_pid =
            Pid::from_raw(i32::try_from(bg_pid).expect("background pid should fit in i32"))
                .expect("background pid must be non-zero");

        assert_eq!(
            cleanup.start_termination(),
            CleanupDisposition::DirectChildKillRequired
        );
        cleanup.kill_tree();
        let _ = child.kill().await;
        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "child did not exit in time"))??;

        let mut still_present = false;
        for _ in 0..300 {
            if !process_group_gone(process_group) {
                still_present = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            still_present,
            "cleanup must fail closed instead of killing a non-Linux Unix process group without strong identity revalidation"
        );

        let _ = kill_process(background_pid, Signal::KILL);
        for _ in 0..300 {
            if process_group_gone(process_group) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "background process group did not exit after explicit cleanup",
        ))
    }

    #[tokio::test]
    async fn cleanup_does_not_kill_orphaned_process_group_after_leader_exit() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let shell_pid_file = dir.path().join("shell.pid");
        let bg_pid_file = dir.path().join("background.pid");
        let script = format!(
            "echo $$ > '{shell}'; sleep 30 & echo $! > '{background}'; exit 0",
            shell = shell_pid_file.display(),
            background = bg_pid_file.display()
        );

        let mut command = tokio::process::Command::new("sh");
        command
            .arg("-c")
            .arg(script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_command_for_process_tree(&mut command);

        let mut child = command.spawn()?;
        let mut cleanup = ProcessTreeCleanup::new(&child)?;
        let shell_pid = wait_for_pid(&shell_pid_file)
            .await
            .expect("shell pid file should be written");
        let process_group = pid_to_process_group(shell_pid);
        let bg_pid = wait_for_pid(&bg_pid_file)
            .await
            .expect("background pid file should be written");
        let background_pid =
            Pid::from_raw(i32::try_from(bg_pid).expect("background pid should fit in i32"))
                .expect("background pid must be non-zero");

        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "shell did not exit in time"))??;

        assert_eq!(
            cleanup.start_termination(),
            CleanupDisposition::DirectChildKillRequired
        );
        cleanup.kill_tree();

        let mut still_present = false;
        for _ in 0..300 {
            if !process_group_gone(process_group) {
                still_present = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        assert!(
            still_present,
            "cleanup must fail closed instead of killing an orphaned process group after the leader exits"
        );

        let _ = kill_process(background_pid, Signal::KILL);
        for _ in 0..300 {
            if process_group_gone(process_group) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "background process group did not exit after explicit cleanup",
        ))
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::{CleanupDisposition, ProcessTreeCleanup, configure_command_for_process_tree};
    use std::io;
    use std::process::Stdio;
    use std::time::Duration;

    #[tokio::test]
    async fn cleanup_terminates_direct_child_or_attached_job() -> io::Result<()> {
        let mut command = tokio::process::Command::new("cmd");
        command
            .arg("/C")
            .arg("ping -n 30 127.0.0.1 >NUL")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_command_for_process_tree(&mut command);

        let mut child = command.spawn()?;
        let mut cleanup = ProcessTreeCleanup::new(&child)?;
        let disposition = cleanup.start_termination();
        cleanup.kill_tree();
        if matches!(disposition, CleanupDisposition::DirectChildKillRequired) {
            let _ = child.kill().await;
        }

        tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "child did not exit in time"))??;
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_is_safe_after_child_exit() -> io::Result<()> {
        let mut command = tokio::process::Command::new("cmd");
        command
            .arg("/C")
            .arg("exit /B 0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_command_for_process_tree(&mut command);

        let mut child = command.spawn()?;
        let mut cleanup = ProcessTreeCleanup::new(&child)?;
        let _ = child.wait().await?;

        let _ = cleanup.start_termination();
        cleanup.kill_tree();
        Ok(())
    }

    #[tokio::test]
    async fn cleanup_allows_repeated_termination_requests() -> io::Result<()> {
        let mut command = tokio::process::Command::new("cmd");
        command
            .arg("/C")
            .arg("ping -n 30 127.0.0.1 >NUL")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_command_for_process_tree(&mut command);

        let mut child = command.spawn()?;
        let mut cleanup = ProcessTreeCleanup::new(&child)?;

        let _ = cleanup.start_termination();
        cleanup.kill_tree();
        cleanup.kill_tree();

        let _ = cleanup.start_termination();
        cleanup.kill_tree();

        let _ = child.kill().await;
        let _ = child.wait().await?;
        Ok(())
    }
}
