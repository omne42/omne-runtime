use std::path::Path;

use crate::error::{Error, Result};

use super::Context;

#[cfg(feature = "git-permissions")]
use std::process::Command;

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
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(canonical_root);
    cmd.args(args);
    cmd.arg("--");
    cmd.arg(relative_path);
    let status = match cmd.status() {
        Ok(status) => status,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::NotPermitted(format!(
                "{op} is disabled by policy: {GIT_BINARY_MISSING_HINT}"
            )));
        }
        Err(err) => {
            return Err(Error::IoPath {
                op: "spawn_git",
                path: relative_path.to_path_buf(),
                source: err,
            });
        }
    };
    Ok(status)
}

#[cfg(feature = "git-permissions")]
fn run_git_output_no_path(canonical_root: &Path, op: &str, args: &[&str]) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(canonical_root);
    cmd.args(args);
    let output = match cmd.output() {
        Ok(output) => output,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::NotPermitted(format!(
                "{op} is disabled by policy: {GIT_BINARY_MISSING_HINT}"
            )));
        }
        Err(err) => {
            return Err(Error::IoPath {
                op: "spawn_git",
                path: canonical_root.to_path_buf(),
                source: err,
            });
        }
    };
    if !output.status.success() {
        return Err(Error::NotPermitted(format!(
            "{op} is disabled by policy: git check failed at {}",
            canonical_root.display()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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
