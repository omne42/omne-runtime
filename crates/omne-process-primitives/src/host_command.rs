use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::Path;
use std::process::{Command, Output, Stdio};

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

pub fn run_host_command(
    request: &HostCommandRequest<'_>,
) -> Result<HostCommandOutput, HostCommandError> {
    if !command_exists_os(request.program) {
        return Err(HostCommandError::CommandNotFound {
            program: request.program.to_os_string(),
        });
    }

    let execution = if should_try_sudo(request.program, request.sudo_mode) {
        HostCommandExecution::Sudo
    } else {
        HostCommandExecution::Direct
    };
    let output = build_command(request, execution)
        .output()
        .map_err(|source| HostCommandError::SpawnFailed {
            program: request.program.to_os_string(),
            execution,
            source,
        })?;
    Ok(HostCommandOutput { execution, output })
}

pub fn command_exists(command: &str) -> bool {
    command_exists_os(OsStr::new(command))
}

fn command_exists_os(command: &OsStr) -> bool {
    let mut cmd = Command::new(command);
    cmd.arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd.status().is_ok()
}

pub fn command_path_exists(command: &Path) -> bool {
    command_exists_os(command.as_os_str())
}

pub fn command_available(command: &str) -> bool {
    let mut cmd = Command::new(command);
    cmd.arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match cmd.status() {
        Ok(_) => true,
        Err(err) => err.kind() != io::ErrorKind::NotFound,
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

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::path::{Path, PathBuf};

    use super::{
        HostCommandExecution, HostCommandRequest, HostCommandSudoMode, command_available,
        command_exists, command_path_exists, run_host_command, should_try_sudo_with_status,
    };

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

        let output = run_host_command(&request).expect("run host command");
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

        let output = run_host_command(&request).expect("run host command");
        assert!(output.output.status.success());
        let stdout = String::from_utf8_lossy(&output.output.stdout);
        assert!(stdout.contains(&working_directory.display().to_string()));
    }

    #[cfg(unix)]
    fn write_test_command(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(name);
        std::fs::write(
            &path,
            "#!/bin/sh\nprintf 'arg=%s\\n' \"$1\"\nprintf 'env=%s\\n' \"$OMNE_TEST_VALUE\"\n",
        )
        .expect("write unix command");
        let mut perms = std::fs::metadata(&path)
            .expect("stat unix command")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod unix command");
        path
    }

    #[cfg(unix)]
    fn write_pwd_command(dir: &Path, name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;

        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\npwd\n").expect("write unix pwd command");
        let mut perms = std::fs::metadata(&path)
            .expect("stat unix pwd command")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod unix pwd command");
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
}
