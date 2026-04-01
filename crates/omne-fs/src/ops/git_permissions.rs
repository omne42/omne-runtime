use std::path::Path;

use crate::error::{Error, Result};

use super::Context;

#[cfg(feature = "git-permissions")]
use omne_process_primitives::{
    HostCommandError, HostCommandRequest, HostCommandSudoMode,
    resolve_command_path_or_standard_location_os, run_host_command,
};
#[cfg(feature = "git-permissions")]
use std::ffi::{OsStr, OsString};
#[cfg(feature = "git-permissions")]
use std::path::PathBuf;

#[cfg(feature = "git-permissions")]
const GIT_BINARY_MISSING_HINT: &str =
    "git permission fallback requires `git` to be installed and available in PATH";

#[cfg(feature = "git-permissions")]
fn run_git_status(
    canonical_root: &Path,
    relative_path: &Path,
    op: &str,
    args: &[&str],
) -> Result<std::process::ExitStatus> {
    let args = git_args_with_path(canonical_root, args, relative_path);
    run_git_command(op, relative_path, &args).map(|output| output.status)
}

#[cfg(feature = "git-permissions")]
fn run_git_output_no_path(canonical_root: &Path, op: &str, args: &[&str]) -> Result<String> {
    let args = git_args_no_path(canonical_root, args);
    let output = run_git_command(op, canonical_root, &args)?;
    if !output.status.success() {
        return Err(Error::NotPermitted(format!(
            "{op} is disabled by policy: git check failed at {}",
            canonical_root.display()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(feature = "git-permissions")]
fn run_git_command(op: &str, path: &Path, args: &[OsString]) -> Result<std::process::Output> {
    let git_path = resolve_git_program_path(op)?;
    let request = HostCommandRequest {
        program: git_path.as_os_str(),
        args,
        env: &[],
        working_directory: None,
        sudo_mode: HostCommandSudoMode::Never,
    };
    run_host_command(&request)
        .map(|output| output.output)
        .map_err(|err| map_git_command_error(op, path, err))
}

#[cfg(feature = "git-permissions")]
fn resolve_git_program_path(op: &str) -> Result<PathBuf> {
    resolve_command_path_or_standard_location_os(OsStr::new("git")).ok_or_else(|| {
        Error::NotPermitted(format!(
            "{op} is disabled by policy: {GIT_BINARY_MISSING_HINT}"
        ))
    })
}

#[cfg(feature = "git-permissions")]
fn map_git_command_error(op: &str, path: &Path, err: HostCommandError) -> Error {
    match err {
        HostCommandError::CommandNotFound { .. } => Error::NotPermitted(format!(
            "{op} is disabled by policy: {GIT_BINARY_MISSING_HINT}"
        )),
        HostCommandError::SpawnFailed { source, .. }
        | HostCommandError::CaptureFailed { source, .. } => Error::IoPath {
            op: "spawn_git",
            path: path.to_path_buf(),
            source,
        },
    }
}

#[cfg(feature = "git-permissions")]
fn git_args_no_path(canonical_root: &Path, args: &[&str]) -> Vec<OsString> {
    let mut git_args = Vec::with_capacity(args.len() + 2);
    git_args.push(OsString::from("-C"));
    git_args.push(canonical_root.as_os_str().to_os_string());
    git_args.extend(args.iter().map(OsString::from));
    git_args
}

#[cfg(feature = "git-permissions")]
fn git_args_with_path(canonical_root: &Path, args: &[&str], relative_path: &Path) -> Vec<OsString> {
    let mut git_args = git_args_no_path(canonical_root, args);
    git_args.push(OsString::from("--"));
    git_args.push(relative_path.as_os_str().to_os_string());
    git_args
}

#[cfg(feature = "git-permissions")]
pub(super) fn ensure_revertible_write_allowed(
    ctx: &Context,
    root_id: &str,
    relative_path: &Path,
    op: &str,
    recursive: bool,
) -> Result<()> {
    if op == "delete" && recursive {
        return Err(Error::NotPermitted(
            "delete is disabled by policy: git permission fallback only supports recursive=false"
                .to_string(),
        ));
    }
    if relative_path.as_os_str().is_empty() || relative_path == Path::new(".") {
        return Err(Error::NotPermitted(format!(
            "{op} is disabled by policy: git permission fallback requires a file path"
        )));
    }

    let canonical_root = ctx.canonical_root(root_id)?;
    let inside_work_tree =
        run_git_output_no_path(canonical_root, op, &["rev-parse", "--is-inside-work-tree"])?;
    if inside_work_tree != "true" {
        return Err(Error::NotPermitted(format!(
            "{op} is disabled by policy: root {root_id} is not inside a git working tree"
        )));
    }

    let tracked = run_git_status(
        canonical_root,
        relative_path,
        op,
        &["ls-files", "--error-unmatch"],
    )?;
    if !tracked.success() {
        return Err(Error::NotPermitted(format!(
            "{op} is disabled by policy: {} is not tracked in git",
            relative_path.display()
        )));
    }

    let diff_status = run_git_status(
        canonical_root,
        relative_path,
        op,
        &["diff", "--quiet", "HEAD"],
    )?;
    match diff_status.code() {
        Some(0) => Ok(()),
        Some(1) => Err(Error::NotPermitted(format!(
            "{op} is disabled by policy: {} has uncommitted changes relative to HEAD",
            relative_path.display()
        ))),
        _ => Err(Error::NotPermitted(format!(
            "{op} is disabled by policy: failed to evaluate git diff status for {}",
            relative_path.display()
        ))),
    }
}

#[cfg(not(feature = "git-permissions"))]
pub(super) fn ensure_revertible_write_allowed(
    _ctx: &Context,
    _root_id: &str,
    _relative_path: &Path,
    op: &str,
    _recursive: bool,
) -> Result<()> {
    Err(Error::NotPermitted(format!("{op} is disabled by policy")))
}
