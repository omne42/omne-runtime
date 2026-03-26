use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use crate::command_path::{
    is_regular_command_path, is_spawnable_command_path, resolve_available_command_path,
    resolve_command_path_os,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCommandSudoMode {
    Never,
    IfNonRootSystemCommand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCommandExecution {
    Direct,
    Sudo,
}

#[derive(Debug, Clone, Copy)]
pub struct HostCommandRequest<'a> {
    pub program: &'a OsStr,
    pub args: &'a [String],
    pub env: &'a [(String, String)],
    pub working_directory: Option<&'a Path>,
    pub sudo_mode: HostCommandSudoMode,
}

#[derive(Debug)]
pub struct HostCommandOutput {
    pub execution: HostCommandExecution,
    pub output: Output,
}

#[derive(Debug, Clone, Copy)]
pub struct HostRecipeRequest<'a> {
    pub program: &'a OsStr,
    pub args: &'a [String],
    pub env: &'a [(String, String)],
    pub working_directory: Option<&'a Path>,
    pub sudo_mode: HostCommandSudoMode,
}

impl<'a> HostRecipeRequest<'a> {
    pub fn new(program: &'a OsStr, args: &'a [String]) -> Self {
        Self {
            program,
            args,
            env: &[],
            working_directory: None,
            sudo_mode: default_recipe_sudo_mode_for_program(program),
        }
    }

    pub fn with_env(mut self, env: &'a [(String, String)]) -> Self {
        self.env = env;
        self
    }

    pub fn with_working_directory(mut self, working_directory: &'a Path) -> Self {
        self.working_directory = Some(working_directory);
        self
    }

    pub fn with_sudo_mode(mut self, sudo_mode: HostCommandSudoMode) -> Self {
        self.sudo_mode = sudo_mode;
        self
    }
}

#[derive(Debug)]
pub enum HostCommandError {
    CommandNotFound {
        program: OsString,
    },
    SpawnFailed {
        program: OsString,
        execution: HostCommandExecution,
        source: io::Error,
    },
}

#[derive(Debug)]
pub enum HostRecipeError {
    Command(HostCommandError),
    NonZeroExit {
        program: OsString,
        execution: HostCommandExecution,
        output: Output,
    },
}

impl fmt::Display for HostCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommandNotFound { program } => {
                write!(f, "command not found: {}", program.to_string_lossy())
            }
            Self::SpawnFailed {
                program,
                execution,
                source,
            } => match execution {
                HostCommandExecution::Direct => {
                    write!(f, "run {} failed: {source}", program.to_string_lossy())
                }
                HostCommandExecution::Sudo => {
                    write!(
                        f,
                        "run sudo -n {} failed: {source}",
                        program.to_string_lossy()
                    )
                }
            },
        }
    }
}

impl std::error::Error for HostCommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CommandNotFound { .. } => None,
            Self::SpawnFailed { source, .. } => Some(source),
        }
    }
}

impl fmt::Display for HostRecipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command(source) => fmt::Display::fmt(source, f),
            Self::NonZeroExit {
                program,
                execution,
                output,
            } => match execution {
                HostCommandExecution::Direct => write!(
                    f,
                    "run {} failed: status={} stderr={} stdout={}",
                    program.to_string_lossy(),
                    output.status,
                    String::from_utf8_lossy(&output.stderr),
                    String::from_utf8_lossy(&output.stdout),
                ),
                HostCommandExecution::Sudo => write!(
                    f,
                    "run sudo -n {} failed: status={} stderr={} stdout={}",
                    program.to_string_lossy(),
                    output.status,
                    String::from_utf8_lossy(&output.stderr),
                    String::from_utf8_lossy(&output.stdout),
                ),
            },
        }
    }
}

impl std::error::Error for HostRecipeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Command(source) => Some(source),
            Self::NonZeroExit { .. } => None,
        }
    }
}

pub fn run_host_command(
    request: &HostCommandRequest<'_>,
) -> Result<HostCommandOutput, HostCommandError> {
    let execution = if should_try_sudo(request.program, request.sudo_mode) {
        HostCommandExecution::Sudo
    } else {
        HostCommandExecution::Direct
    };
    let output = run_command_output(request, execution)
        .map_err(|source| map_spawn_error(request.program, execution, source))?;
    Ok(HostCommandOutput { execution, output })
}

pub fn run_host_recipe(
    request: &HostRecipeRequest<'_>,
) -> Result<HostCommandOutput, HostRecipeError> {
    let output = run_host_command(&HostCommandRequest {
        program: request.program,
        args: request.args,
        env: request.env,
        working_directory: request.working_directory,
        sudo_mode: request.sudo_mode,
    })
    .map_err(HostRecipeError::Command)?;

    if output.output.status.success() {
        return Ok(output);
    }

    Err(HostRecipeError::NonZeroExit {
        program: request.program.to_os_string(),
        execution: output.execution,
        output: output.output,
    })
}

pub fn command_exists(command: &str) -> bool {
    command_exists_os(OsStr::new(command))
}

fn command_exists_os(command: &OsStr) -> bool {
    if is_explicit_command_path(command) {
        return is_spawnable_command_path(Path::new(command));
    }
    resolve_command_path_os(command).is_some()
}

pub fn command_path_exists(command: &Path) -> bool {
    is_spawnable_command_path(command)
}

pub fn command_available(command: &str) -> bool {
    let command = OsStr::new(command);
    if is_explicit_command_path(command) {
        return is_regular_command_path(Path::new(command));
    }
    resolve_available_command_path(command.to_string_lossy().as_ref()).is_some()
}

pub fn default_recipe_sudo_mode_for_program(program: &OsStr) -> HostCommandSudoMode {
    let Some(program) = program.to_str() else {
        return HostCommandSudoMode::Never;
    };
    match program {
        "brew" => HostCommandSudoMode::Never,
        "apt-get" | "dnf" | "yum" | "apk" | "pacman" | "zypper" => {
            HostCommandSudoMode::IfNonRootSystemCommand
        }
        _ => HostCommandSudoMode::Never,
    }
}

fn build_command(request: &HostCommandRequest<'_>, execution: HostCommandExecution) -> Command {
    let mut cmd = match execution {
        HostCommandExecution::Direct => Command::new(request.program),
        HostCommandExecution::Sudo => {
            let mut cmd = Command::new("sudo");
            cmd.arg("-n").arg(request.program);
            cmd
        }
    };
    for arg in request.args {
        cmd.arg(arg);
    }
    for (name, value) in request.env {
        cmd.env(name, value);
    }
    if let Some(working_directory) = request.working_directory {
        cmd.current_dir(working_directory);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn run_command_output(
    request: &HostCommandRequest<'_>,
    execution: HostCommandExecution,
) -> io::Result<Output> {
    #[cfg(unix)]
    {
        const EXECUTABLE_BUSY_RETRIES: usize = 3;
        const EXECUTABLE_BUSY_BACKOFF_MS: u64 = 10;

        for attempt in 0..=EXECUTABLE_BUSY_RETRIES {
            match build_command(request, execution).output() {
                Ok(output) => return Ok(output),
                Err(err)
                    if err.kind() == io::ErrorKind::ExecutableFileBusy
                        && attempt < EXECUTABLE_BUSY_RETRIES =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(
                        EXECUTABLE_BUSY_BACKOFF_MS,
                    ));
                }
                Err(err) => return Err(err),
            }
        }

        unreachable!("retry loop must return on success or final error");
    }

    #[cfg(not(unix))]
    {
        build_command(request, execution).output()
    }
}

fn should_try_sudo(program: &OsStr, sudo_mode: HostCommandSudoMode) -> bool {
    should_try_sudo_with_status(
        program,
        sudo_mode,
        unix_process_is_non_root(),
        command_exists("sudo"),
    )
}

fn should_try_sudo_with_status(
    program: &OsStr,
    sudo_mode: HostCommandSudoMode,
    process_is_non_root: bool,
    sudo_available: bool,
) -> bool {
    if sudo_mode != HostCommandSudoMode::IfNonRootSystemCommand {
        return false;
    }
    if !process_is_non_root || !sudo_available {
        return false;
    }
    !has_path_separator(program)
}

#[cfg(unix)]
fn unix_process_is_non_root() -> bool {
    !rustix::process::geteuid().is_root()
}

#[cfg(not(unix))]
fn unix_process_is_non_root() -> bool {
    false
}

fn has_path_separator(command: &OsStr) -> bool {
    command
        .to_string_lossy()
        .chars()
        .any(|ch| ch == '/' || ch == '\\')
}

fn is_explicit_command_path(command: &OsStr) -> bool {
    has_path_separator(command) || Path::new(command).is_absolute()
}

fn map_spawn_error(
    program: &OsStr,
    execution: HostCommandExecution,
    source: io::Error,
) -> HostCommandError {
    if source.kind() == io::ErrorKind::NotFound {
        HostCommandError::CommandNotFound {
            program: program.to_os_string(),
        }
    } else {
        HostCommandError::SpawnFailed {
            program: program.to_os_string(),
            execution,
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};

    #[cfg(unix)]
    use std::io;

    use super::{
        HostCommandError, HostCommandExecution, HostCommandOutput, HostCommandRequest,
        HostCommandSudoMode, HostRecipeError, HostRecipeRequest, command_available, command_exists,
        command_path_exists, default_recipe_sudo_mode_for_program, run_host_command,
        run_host_recipe, should_try_sudo_with_status,
    };

    #[cfg(unix)]
    fn run_host_command_with_retry(
        request: &HostCommandRequest<'_>,
    ) -> Result<HostCommandOutput, HostCommandError> {
        for attempt in 0..5 {
            match run_host_command(request) {
                Err(HostCommandError::SpawnFailed { source, .. })
                    if source.kind() == io::ErrorKind::ExecutableFileBusy && attempt < 4 =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                result => return result,
            }
        }
        unreachable!("retry loop always returns on the final attempt")
    }

    #[cfg(not(unix))]
    fn run_host_command_with_retry(
        request: &HostCommandRequest<'_>,
    ) -> Result<HostCommandOutput, HostCommandError> {
        run_host_command(request)
    }

    #[cfg(unix)]
    fn run_host_recipe_with_retry(
        request: &HostRecipeRequest<'_>,
    ) -> Result<HostCommandOutput, HostRecipeError> {
        for attempt in 0..5 {
            match run_host_recipe(request) {
                Err(HostRecipeError::Command(HostCommandError::SpawnFailed { source, .. }))
                    if source.kind() == io::ErrorKind::ExecutableFileBusy && attempt < 4 =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                result => return result,
            }
        }
        unreachable!("retry loop always returns on the final attempt")
    }

    #[cfg(not(unix))]
    fn run_host_recipe_with_retry(
        request: &HostRecipeRequest<'_>,
    ) -> Result<HostCommandOutput, HostRecipeError> {
        run_host_recipe(request)
    }

    #[test]
    fn command_probe_reports_missing_command_as_absent() {
        let command = "omne-process-primitives-missing-command";
        assert!(!command_exists(command));
        assert!(!command_available(command));
    }

    #[test]
    fn path_command_probe_accepts_executable_path() {
        let command_path = std::env::current_exe().expect("current exe");
        assert!(command_path_exists(&command_path));
    }

    #[test]
    fn run_host_command_captures_stdout_and_environment() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_test_command(temp.path(), "echoenv");
        let args = vec!["hello".to_string()];
        let env = vec![("OMNE_TEST_VALUE".to_string(), "world".to_string())];
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::IfNonRootSystemCommand,
        };

        let output = run_host_command_with_retry(&request).expect("run host command");
        assert_eq!(output.execution, HostCommandExecution::Direct);
        assert!(output.output.status.success());
        let stdout = String::from_utf8_lossy(&output.output.stdout);
        assert!(stdout.contains("arg=hello"));
        assert!(stdout.contains("env=world"));
    }

    #[test]
    fn sudo_mode_only_applies_to_non_root_bare_commands() {
        assert!(should_try_sudo_with_status(
            OsStr::new("apt-get"),
            HostCommandSudoMode::IfNonRootSystemCommand,
            true,
            true,
        ));
        assert!(!should_try_sudo_with_status(
            OsStr::new("/usr/bin/apt-get"),
            HostCommandSudoMode::IfNonRootSystemCommand,
            true,
            true,
        ));
        assert!(!should_try_sudo_with_status(
            OsStr::new("apt-get"),
            HostCommandSudoMode::Never,
            true,
            true,
        ));
        assert!(!should_try_sudo_with_status(
            OsStr::new("apt-get"),
            HostCommandSudoMode::IfNonRootSystemCommand,
            false,
            true,
        ));
    }

    #[test]
    fn default_recipe_sudo_mode_recognizes_common_package_managers() {
        assert_eq!(
            default_recipe_sudo_mode_for_program(OsStr::new("apt-get")),
            HostCommandSudoMode::IfNonRootSystemCommand
        );
        assert_eq!(
            default_recipe_sudo_mode_for_program(OsStr::new("dnf")),
            HostCommandSudoMode::IfNonRootSystemCommand
        );
        assert_eq!(
            default_recipe_sudo_mode_for_program(OsStr::new("brew")),
            HostCommandSudoMode::Never
        );
        assert_eq!(
            default_recipe_sudo_mode_for_program(OsStr::new("cargo")),
            HostCommandSudoMode::Never
        );
    }

    #[test]
    fn run_host_command_uses_working_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_pwd_command(temp.path(), "pwd");
        let working_directory = temp.path().join("cwd");
        std::fs::create_dir_all(&working_directory).expect("create working directory");
        let args = Vec::new();
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &[],
            working_directory: Some(&working_directory),
            sudo_mode: HostCommandSudoMode::Never,
        };

        let output = run_host_command_with_retry(&request).expect("run host command");
        assert!(output.output.status.success());
        let stdout = String::from_utf8_lossy(&output.output.stdout);
        assert!(stdout.contains(&working_directory.display().to_string()));
    }

    #[test]
    fn run_host_command_classifies_missing_program_as_not_found() {
        let args = Vec::new();
        let request = HostCommandRequest {
            program: OsStr::new("omne-process-primitives-missing-command"),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let error = run_host_command(&request).expect_err("missing command should fail");
        assert!(matches!(error, HostCommandError::CommandNotFound { .. }));
    }

    #[test]
    fn run_host_command_does_not_probe_by_executing_the_program_twice() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_count_command(temp.path(), "count");
        let count_file = temp.path().join("count.txt");
        let args = Vec::new();
        let env = vec![(
            "OMNE_COUNT_FILE".to_string(),
            count_file.to_string_lossy().into_owned(),
        )];
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &env,
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let output = run_host_command_with_retry(&request).expect("run host command");
        assert!(output.output.status.success());

        let recorded = std::fs::read_to_string(&count_file).expect("read count file");
        assert_eq!(recorded.lines().count(), 1);
    }

    #[test]
    fn run_host_command_resolves_relative_program_against_working_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let working_directory = temp.path().join("cwd");
        std::fs::create_dir_all(&working_directory).expect("create working directory");
        write_pwd_command(&working_directory, "pwd");
        let args = Vec::new();
        let request = HostCommandRequest {
            program: OsStr::new("./pwd"),
            args: &args,
            env: &[],
            working_directory: Some(&working_directory),
            sudo_mode: HostCommandSudoMode::Never,
        };

        let output = run_host_command_with_retry(&request).expect("run host command");
        assert!(output.output.status.success());
        let stdout = String::from_utf8_lossy(&output.output.stdout);
        assert!(stdout.contains(&working_directory.display().to_string()));
    }

    #[test]
    fn run_host_recipe_captures_success_output() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_test_command(temp.path(), "echoenv");
        let args = vec!["hello".to_string()];
        let env = vec![("OMNE_TEST_VALUE".to_string(), "world".to_string())];

        let output = run_host_recipe_with_retry(
            &HostRecipeRequest::new(command_path.as_os_str(), &args).with_env(&env),
        )
        .expect("run host recipe");
        assert_eq!(output.execution, HostCommandExecution::Direct);
        assert!(output.output.status.success());
        let stdout = String::from_utf8_lossy(&output.output.stdout);
        assert!(stdout.contains("arg=hello"));
        assert!(stdout.contains("env=world"));
    }

    #[test]
    fn run_host_recipe_returns_non_zero_exit_as_error() {
        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = write_failing_command(temp.path(), "failcmd");
        let args = Vec::new();

        let err =
            run_host_recipe_with_retry(&HostRecipeRequest::new(command_path.as_os_str(), &args))
                .expect_err("recipe should fail");
        match err {
            HostRecipeError::NonZeroExit {
                execution, output, ..
            } => {
                assert_eq!(execution, HostCommandExecution::Direct);
                assert_eq!(output.status.code(), Some(7));
                assert_eq!(String::from_utf8_lossy(&output.stdout), "stdout-message");
                assert_eq!(String::from_utf8_lossy(&output.stderr), "stderr-message");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn non_executable_paths_are_available_but_not_spawnable() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let command_path = temp.path().join("plain-script");
        std::fs::write(&command_path, "#!/bin/sh\nexit 0\n").expect("write plain script");
        let mut permissions = std::fs::metadata(&command_path)
            .expect("stat plain script")
            .permissions();
        permissions.set_mode(0o644);
        std::fs::set_permissions(&command_path, permissions).expect("chmod plain script");

        let command_path_string = command_path.to_string_lossy().into_owned();
        assert!(command_available(&command_path_string));
        assert!(!command_path_exists(&command_path));

        let args = Vec::new();
        let request = HostCommandRequest {
            program: command_path.as_os_str(),
            args: &args,
            env: &[],
            working_directory: None,
            sudo_mode: HostCommandSudoMode::Never,
        };

        let error = run_host_command(&request).expect_err("non-executable path should fail");
        match error {
            HostCommandError::CommandNotFound { .. } => {
                panic!("non-executable path must not be classified as not found");
            }
            HostCommandError::SpawnFailed { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::PermissionDenied);
            }
        }
    }

    #[cfg(unix)]
    fn write_test_command(dir: &Path, name: &str) -> PathBuf {
        write_unix_executable(
            dir,
            name,
            "#!/bin/sh\nprintf 'arg=%s\\n' \"$1\"\nprintf 'env=%s\\n' \"$OMNE_TEST_VALUE\"\n",
        )
    }

    #[cfg(unix)]
    fn write_pwd_command(dir: &Path, name: &str) -> PathBuf {
        write_unix_executable(dir, name, "#!/bin/sh\npwd\n")
    }

    #[cfg(unix)]
    fn write_count_command(dir: &Path, name: &str) -> PathBuf {
        write_unix_executable(
            dir,
            name,
            "#!/bin/sh\nprintf 'run\\n' >> \"$OMNE_COUNT_FILE\"\n",
        )
    }

    #[cfg(unix)]
    fn write_failing_command(dir: &Path, name: &str) -> PathBuf {
        write_unix_executable(
            dir,
            name,
            "#!/bin/sh\nprintf 'stdout-message'\nprintf 'stderr-message' >&2\nexit 7\n",
        )
    }

    #[cfg(unix)]
    fn write_unix_executable(dir: &Path, name: &str, content: &str) -> PathBuf {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(name);
        let temp_path = dir.join(format!("{name}.tmp"));
        let mut file = std::fs::File::create(&temp_path).expect("create unix command");
        file.write_all(content.as_bytes())
            .expect("write unix command");
        file.sync_all().expect("sync unix command");
        drop(file);
        let mut perms = std::fs::metadata(&temp_path)
            .expect("stat unix command")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&temp_path, perms).expect("chmod unix command");
        std::fs::rename(&temp_path, &path).expect("rename unix command");
        path
    }

    #[cfg(windows)]
    fn write_test_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(
            &path,
            "@echo off\r\necho arg=%1\r\necho env=%OMNE_TEST_VALUE%\r\n",
        )
        .expect("write windows command");
        path
    }

    #[cfg(windows)]
    fn write_pwd_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(&path, "@echo off\r\ncd\r\n").expect("write windows pwd command");
        path
    }

    #[cfg(windows)]
    fn write_count_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(&path, "@echo off\r\necho run>> \"%OMNE_COUNT_FILE%\"\r\n")
            .expect("write windows count command");
        path
    }

    #[cfg(windows)]
    fn write_failing_command(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(format!("{name}.cmd"));
        std::fs::write(
            &path,
            "@echo off\r\n<nul set /p =stdout-message\r\n1>&2 <nul set /p =stderr-message\r\nexit /b 7\r\n",
        )
        .expect("write windows failing command");
        path
    }
}
