use std::path::Path;

use crate::error::{Error, Result};

use super::Context;

#[cfg(feature = "git-permissions")]
use std::process::Command;

#[cfg(feature = "git-permissions")]
const GIT_BINARY_MISSING_HINT: &str =
    "git permission fallback requires `git` to be installed and available in PATH";

#[cfg(feature = "git-permissions")]
const SANITIZED_GIT_ENV_VARS: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES",
    "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_LITERAL_PATHSPECS",
    "GIT_GLOB_PATHSPECS",
    "GIT_NOGLOB_PATHSPECS",
    "GIT_ICASE_PATHSPECS",
];

#[cfg(feature = "git-permissions")]
fn git_command(canonical_root: &Path) -> Command {
    let mut cmd = Command::new("git");
    for key in SANITIZED_GIT_ENV_VARS {
        cmd.env_remove(key);
    }
    cmd.arg("-C").arg(canonical_root);
    cmd
}

#[cfg(feature = "git-permissions")]
fn run_git_status(
    canonical_root: &Path,
    relative_path: &Path,
    op: &str,
    args: &[&str],
) -> Result<std::process::ExitStatus> {
    let mut cmd = git_command(canonical_root);
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
    let mut cmd = git_command(canonical_root);
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

#[cfg(all(test, feature = "git-permissions"))]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    use policy_meta::WriteScope;

    use crate::policy::SandboxPolicy;

    const CHILD_MARKER_ENV: &str = "OMNE_FS_GIT_PERMISSIONS_TEST_CHILD";
    const TARGET_REPO_ENV: &str = "OMNE_FS_GIT_PERMISSIONS_TARGET_REPO";
    const ATTACKER_REPO_ENV: &str = "OMNE_FS_GIT_PERMISSIONS_ATTACKER_REPO";

    fn git_available() -> bool {
        Command::new("git")
            .arg("--version")
            .status()
            .is_ok_and(|status| status.success())
    }

    fn run_git(repo: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .status()
            .expect("run git");
        assert!(status.success(), "git {:?} failed with {status}", args);
    }

    fn init_git_repo(path: &Path) {
        run_git(path, &["init", "-q"]);
        run_git(path, &["config", "user.email", "tests@example.com"]);
        run_git(path, &["config", "user.name", "Tests"]);
    }

    fn commit_tracked_file(repo: &Path, relative_path: &str, contents: &str) {
        let path = repo.join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir parents");
        }
        fs::write(&path, contents).expect("write tracked file");
        run_git(repo, &["add", "--", relative_path]);
        run_git(repo, &["commit", "-qm", "init"]);
    }

    fn child_test_name() -> &'static str {
        "ops::git_permissions::tests::git_permission_fallback_ignores_ambient_repo_override_env"
    }

    fn run_child_with_polluted_git_env(target_repo: &Path, attacker_repo: &Path) {
        let status = Command::new(std::env::current_exe().expect("current exe"))
            .arg("--exact")
            .arg(child_test_name())
            .arg("--nocapture")
            .env(CHILD_MARKER_ENV, "1")
            .env(TARGET_REPO_ENV, target_repo)
            .env(ATTACKER_REPO_ENV, attacker_repo)
            .env("GIT_DIR", attacker_repo.join(".git"))
            .env("GIT_WORK_TREE", attacker_repo)
            .env("GIT_INDEX_FILE", attacker_repo.join(".git").join("index"))
            .status()
            .expect("spawn child test");
        assert!(status.success(), "child test failed with {status}");
    }

    #[test]
    fn git_permission_fallback_ignores_ambient_repo_override_env() {
        if !git_available() {
            return;
        }

        if std::env::var_os(CHILD_MARKER_ENV).is_some() {
            let target_repo =
                PathBuf::from(std::env::var_os(TARGET_REPO_ENV).expect("target repo env"));
            let policy =
                SandboxPolicy::single_root("workspace", &target_repo, WriteScope::WorkspaceWrite);
            let ctx = Context::new(policy).expect("ctx");
            ensure_revertible_write_allowed(
                &ctx,
                "workspace",
                Path::new("tracked.txt"),
                "write",
                false,
            )
            .expect("git permission fallback should ignore inherited repo override env");
            return;
        }

        let target_dir = tempfile::tempdir().expect("target tempdir");
        let attacker_dir = tempfile::tempdir().expect("attacker tempdir");

        init_git_repo(target_dir.path());
        commit_tracked_file(target_dir.path(), "tracked.txt", "tracked\n");

        init_git_repo(attacker_dir.path());
        commit_tracked_file(attacker_dir.path(), "other.txt", "other\n");

        let polluted_status = Command::new("git")
            .env("GIT_DIR", attacker_dir.path().join(".git"))
            .env("GIT_WORK_TREE", attacker_dir.path())
            .env("GIT_INDEX_FILE", attacker_dir.path().join(".git").join("index"))
            .arg("-C")
            .arg(target_dir.path())
            .args(["ls-files", "--error-unmatch", "--", "tracked.txt"])
            .status()
            .expect("polluted git ls-files");
        assert!(
            !polluted_status.success(),
            "ambient git env should redirect unsanitized git to the attacker repo"
        );

        run_child_with_polluted_git_env(target_dir.path(), attacker_dir.path());
    }

    #[test]
    fn git_command_removes_repo_shaping_env_vars() {
        let command = git_command(Path::new("/tmp"));
        let envs = command
            .get_envs()
            .map(|(key, value)| (key.to_os_string(), value.map(OsString::from)))
            .collect::<Vec<_>>();
        for key in SANITIZED_GIT_ENV_VARS {
            let expected = OsString::from(key);
            assert!(
                envs.iter().any(|(candidate, value)| {
                    candidate == &expected && value.is_none()
                }),
                "expected {key} to be removed from git command environment"
            );
        }
    }
}
