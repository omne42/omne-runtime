#[cfg(feature = "git-permissions")]
use std::ffi::{OsStr, OsString};
use std::path::Path;
#[cfg(feature = "git-permissions")]
use std::path::PathBuf;

use crate::error::{Error, Result};

use super::Context;

#[cfg(feature = "git-permissions")]
use std::process::{Command, Output, Stdio};

#[cfg(feature = "git-permissions")]
const GIT_BINARY_MISSING_HINT: &str =
    "git permission fallback requires `git` to be installed at a trusted system path";

#[cfg(feature = "git-permissions")]
fn trusted_git_program() -> Option<PathBuf> {
    trusted_git_candidates()
        .into_iter()
        .find(|path| path.is_file())
}

#[cfg(feature = "git-permissions")]
fn trusted_git_candidates() -> Vec<PathBuf> {
    #[cfg(unix)]
    {
        vec![
            PathBuf::from("/usr/bin/git"),
            PathBuf::from("/bin/git"),
            PathBuf::from("/usr/local/bin/git"),
            PathBuf::from("/opt/homebrew/bin/git"),
            PathBuf::from("/opt/local/bin/git"),
        ]
    }

    #[cfg(windows)]
    {
        vec![
            PathBuf::from(r"C:\Program Files\Git\cmd\git.exe"),
            PathBuf::from(r"C:\Program Files\Git\bin\git.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Git\cmd\git.exe"),
            PathBuf::from(r"C:\Program Files (x86)\Git\bin\git.exe"),
        ]
    }
}

#[cfg(feature = "git-permissions")]
fn build_git_command(
    program: &Path,
    canonical_root: &Path,
    args: &[&str],
    relative_path: Option<&Path>,
) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear();
    cmd.envs(sanitized_git_environment(std::env::vars_os()));
    cmd.arg("-C").arg(canonical_root);
    cmd.args(args);
    if let Some(relative_path) = relative_path {
        cmd.arg("--");
        cmd.arg(relative_path);
    }
    cmd
}

#[cfg(feature = "git-permissions")]
fn sanitized_git_environment<I>(env: I) -> Vec<(OsString, OsString)>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    env.into_iter()
        .filter(|(name, _)| !is_git_env_name(name))
        .collect()
}

#[cfg(feature = "git-permissions")]
fn is_git_env_name(name: &OsStr) -> bool {
    #[cfg(windows)]
    {
        name.to_string_lossy()
            .to_ascii_uppercase()
            .starts_with("GIT_")
    }

    #[cfg(not(windows))]
    {
        name.as_encoded_bytes().starts_with(b"GIT_")
    }
}

#[cfg(feature = "git-permissions")]
fn run_git_status(
    canonical_root: &Path,
    relative_path: &Path,
    op: &str,
    args: &[&str],
) -> Result<std::process::ExitStatus> {
    let Some(program) = trusted_git_program() else {
        return Err(Error::NotPermitted(format!(
            "{op} is disabled by policy: {GIT_BINARY_MISSING_HINT}"
        )));
    };
    let mut cmd = build_git_command(&program, canonical_root, args, Some(relative_path));
    let status = match run_command_status_silently(&mut cmd) {
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
    let Some(program) = trusted_git_program() else {
        return Err(Error::NotPermitted(format!(
            "{op} is disabled by policy: {GIT_BINARY_MISSING_HINT}"
        )));
    };
    let mut cmd = build_git_command(&program, canonical_root, args, None);
    let output = match run_command_output(&mut cmd) {
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
fn run_command_status_silently(cmd: &mut Command) -> std::io::Result<std::process::ExitStatus> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

#[cfg(feature = "git-permissions")]
fn run_command_output(cmd: &mut Command) -> std::io::Result<Output> {
    cmd.stdin(Stdio::null()).output()
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
        &["diff", "--quiet", "--no-ext-diff", "HEAD"],
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

#[cfg(all(test, feature = "git-permissions"))]
mod tests {
    use super::{
        build_git_command, is_git_env_name, run_command_status_silently, sanitized_git_environment,
    };
    use std::ffi::{OsStr, OsString};
    use std::path::Path;

    #[test]
    fn sanitized_git_environment_drops_git_prefixed_variables() {
        let env = vec![
            (OsString::from("HOME"), OsString::from("/tmp/home")),
            (OsString::from("GIT_DIR"), OsString::from("/tmp/git")),
            (OsString::from("GIT_WORK_TREE"), OsString::from("/tmp/work")),
        ];

        let sanitized = sanitized_git_environment(env);
        assert_eq!(
            sanitized,
            vec![(OsString::from("HOME"), OsString::from("/tmp/home"))]
        );
    }

    #[test]
    fn build_git_command_uses_absolute_program_and_sanitized_env() {
        let command = build_git_command(
            Path::new("/usr/bin/git"),
            Path::new("/tmp/repo"),
            &["rev-parse", "--is-inside-work-tree"],
            None,
        );
        assert_eq!(command.get_program(), OsStr::new("/usr/bin/git"));
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![
                OsStr::new("-C"),
                OsStr::new("/tmp/repo"),
                OsStr::new("rev-parse"),
                OsStr::new("--is-inside-work-tree")
            ]
        );
    }

    #[cfg(unix)]
    #[test]
    fn silent_status_runner_does_not_block_on_large_stderr_output() {
        let mut command = std::process::Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("python3 - <<'PY'\nimport sys\nsys.stderr.write('x' * 131072)\nPY\n");

        let status = run_command_status_silently(&mut command).expect("run silenced status");
        assert!(status.success());
    }

    #[test]
    fn git_env_name_detection_matches_git_prefix() {
        assert!(is_git_env_name(OsStr::new("GIT_DIR")));
        assert!(!is_git_env_name(OsStr::new("HOME")));
    }
}
