#![forbid(unsafe_code)]

//! Low-level host information primitives shared by higher-level tooling.
//!
//! This crate owns policy-free helpers for:
//! - recognizing the current host OS/architecture pair
//! - mapping supported host pairs to canonical target triples
//! - resolving an effective target triple from an optional override
//! - resolving the current user's home directory from standard environment variables
//! - inferring executable suffixes from target triples

use std::ffi::OsString;
use std::fmt;
#[cfg(target_os = "linux")]
use std::path::Path;
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostOperatingSystem {
    Linux,
    Macos,
    Windows,
}

impl HostOperatingSystem {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::Macos => "macos",
            Self::Windows => "windows",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostArchitecture {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLinuxLibc {
    Gnu,
    Musl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostPlatform {
    os: HostOperatingSystem,
    arch: HostArchitecture,
    linux_libc: Option<HostLinuxLibc>,
}

impl HostPlatform {
    pub const fn operating_system(self) -> HostOperatingSystem {
        self.os
    }

    pub const fn architecture(self) -> HostArchitecture {
        self.arch
    }

    pub const fn linux_libc(self) -> Option<HostLinuxLibc> {
        self.linux_libc
    }

    pub const fn target_triple(self) -> &'static str {
        match (self.os, self.arch, self.linux_libc) {
            (HostOperatingSystem::Macos, HostArchitecture::Aarch64, None) => "aarch64-apple-darwin",
            (HostOperatingSystem::Macos, HostArchitecture::X86_64, None) => "x86_64-apple-darwin",
            (HostOperatingSystem::Linux, HostArchitecture::Aarch64, Some(HostLinuxLibc::Gnu))
            | (HostOperatingSystem::Linux, HostArchitecture::Aarch64, None) => {
                "aarch64-unknown-linux-gnu"
            }
            (HostOperatingSystem::Linux, HostArchitecture::Aarch64, Some(HostLinuxLibc::Musl)) => {
                "aarch64-unknown-linux-musl"
            }
            (HostOperatingSystem::Linux, HostArchitecture::X86_64, Some(HostLinuxLibc::Gnu))
            | (HostOperatingSystem::Linux, HostArchitecture::X86_64, None) => {
                "x86_64-unknown-linux-gnu"
            }
            (HostOperatingSystem::Linux, HostArchitecture::X86_64, Some(HostLinuxLibc::Musl)) => {
                "x86_64-unknown-linux-musl"
            }
            (HostOperatingSystem::Windows, HostArchitecture::Aarch64, None) => {
                "aarch64-pc-windows-msvc"
            }
            (HostOperatingSystem::Windows, HostArchitecture::X86_64, None) => {
                "x86_64-pc-windows-msvc"
            }
            (HostOperatingSystem::Macos, _, Some(_))
            | (HostOperatingSystem::Windows, _, Some(_)) => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetTripleError {
    Empty,
    Unsupported(String),
}

impl fmt::Display for TargetTripleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "target triple must not be empty"),
            Self::Unsupported(target) => {
                write!(f, "unsupported target triple: {target}")
            }
        }
    }
}

impl std::error::Error for TargetTripleError {}

#[cfg(windows)]
const HOME_ENV_KEYS: &[&str] = &["HOME", "USERPROFILE"];
#[cfg(not(windows))]
const HOME_ENV_KEYS: &[&str] = &["HOME"];

pub fn detect_host_platform() -> Option<HostPlatform> {
    let linux_libc = detect_host_linux_libc();
    host_platform_from_parts(std::env::consts::OS, std::env::consts::ARCH, linux_libc)
}

pub fn detect_host_target_triple() -> Option<&'static str> {
    detect_host_platform().map(HostPlatform::target_triple)
}

pub fn resolve_target_triple(
    override_target: Option<&str>,
    host_target_triple: &str,
) -> Result<String, TargetTripleError> {
    if let Some(raw) = override_target {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return normalize_target_triple(trimmed).map(str::to_string);
        }
    }
    normalize_target_triple(host_target_triple).map(str::to_string)
}

pub fn executable_suffix_for_target(
    target_triple: &str,
) -> Result<&'static str, TargetTripleError> {
    let platform = host_platform_from_target_triple(target_triple)?;
    Ok(match platform.operating_system() {
        HostOperatingSystem::Windows => ".exe",
        HostOperatingSystem::Linux | HostOperatingSystem::Macos => "",
    })
}

pub fn resolve_home_dir() -> Option<PathBuf> {
    resolve_home_dir_with(&|key| std::env::var_os(key))
}

fn resolve_home_dir_with<F>(env_lookup: &F) -> Option<PathBuf>
where
    F: Fn(&str) -> Option<OsString>,
{
    for key in HOME_ENV_KEYS {
        if let Some(path) = absolute_env_path(env_lookup, key) {
            return Some(path);
        }
    }

    #[cfg(windows)]
    if let Some(path) = lookup_windows_home_drive_path(env_lookup) {
        return Some(path);
    }

    None
}

fn host_platform_from_parts(
    os: &str,
    arch: &str,
    linux_libc: Option<HostLinuxLibc>,
) -> Option<HostPlatform> {
    let os = match os {
        "linux" => HostOperatingSystem::Linux,
        "macos" => HostOperatingSystem::Macos,
        "windows" => HostOperatingSystem::Windows,
        _ => return None,
    };
    let arch = match arch {
        "x86_64" => HostArchitecture::X86_64,
        "aarch64" => HostArchitecture::Aarch64,
        _ => return None,
    };
    Some(HostPlatform {
        os,
        arch,
        linux_libc: match os {
            HostOperatingSystem::Linux => Some(linux_libc?),
            HostOperatingSystem::Macos | HostOperatingSystem::Windows => None,
        },
    })
}

fn host_platform_from_target_triple(
    target_triple: &str,
) -> Result<HostPlatform, TargetTripleError> {
    let normalized = normalize_target_triple(target_triple)?;
    match normalized {
        "aarch64-apple-darwin" => Ok(HostPlatform {
            os: HostOperatingSystem::Macos,
            arch: HostArchitecture::Aarch64,
            linux_libc: None,
        }),
        "x86_64-apple-darwin" => Ok(HostPlatform {
            os: HostOperatingSystem::Macos,
            arch: HostArchitecture::X86_64,
            linux_libc: None,
        }),
        "aarch64-unknown-linux-gnu" => Ok(HostPlatform {
            os: HostOperatingSystem::Linux,
            arch: HostArchitecture::Aarch64,
            linux_libc: Some(HostLinuxLibc::Gnu),
        }),
        "aarch64-unknown-linux-musl" => Ok(HostPlatform {
            os: HostOperatingSystem::Linux,
            arch: HostArchitecture::Aarch64,
            linux_libc: Some(HostLinuxLibc::Musl),
        }),
        "x86_64-unknown-linux-gnu" => Ok(HostPlatform {
            os: HostOperatingSystem::Linux,
            arch: HostArchitecture::X86_64,
            linux_libc: Some(HostLinuxLibc::Gnu),
        }),
        "x86_64-unknown-linux-musl" => Ok(HostPlatform {
            os: HostOperatingSystem::Linux,
            arch: HostArchitecture::X86_64,
            linux_libc: Some(HostLinuxLibc::Musl),
        }),
        "aarch64-pc-windows-msvc" => Ok(HostPlatform {
            os: HostOperatingSystem::Windows,
            arch: HostArchitecture::Aarch64,
            linux_libc: None,
        }),
        "x86_64-pc-windows-msvc" => Ok(HostPlatform {
            os: HostOperatingSystem::Windows,
            arch: HostArchitecture::X86_64,
            linux_libc: None,
        }),
        other => Err(TargetTripleError::Unsupported(other.to_string())),
    }
}

fn normalize_target_triple(raw: &str) -> Result<&str, TargetTripleError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(TargetTripleError::Empty);
    }
    host_platform_from_target_triple_text(trimmed)
}

fn host_platform_from_target_triple_text(target_triple: &str) -> Result<&str, TargetTripleError> {
    match target_triple {
        "aarch64-apple-darwin"
        | "x86_64-apple-darwin"
        | "aarch64-unknown-linux-gnu"
        | "aarch64-unknown-linux-musl"
        | "x86_64-unknown-linux-gnu"
        | "x86_64-unknown-linux-musl"
        | "aarch64-pc-windows-msvc"
        | "x86_64-pc-windows-msvc" => Ok(target_triple),
        other => Err(TargetTripleError::Unsupported(other.to_string())),
    }
}

#[cfg(target_os = "linux")]
fn detect_host_linux_libc() -> Option<HostLinuxLibc> {
    detect_host_linux_libc_with(&|path| path.is_file(), &|program, args| {
        Command::new(program)
            .args(args)
            .output()
            .ok()
            .map(|output| LinuxCommandOutput {
                status_success: output.status.success(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
    })
}

#[cfg(not(target_os = "linux"))]
fn detect_host_linux_libc() -> Option<HostLinuxLibc> {
    None
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct LinuxCommandOutput {
    status_success: bool,
    stdout: String,
    stderr: String,
}

#[cfg(target_os = "linux")]
fn detect_host_linux_libc_with<F, G>(path_exists: &F, run_command: &G) -> Option<HostLinuxLibc>
where
    F: Fn(&Path) -> bool,
    G: Fn(&Path, &[&str]) -> Option<LinuxCommandOutput>,
{
    if let Some(output) = run_first_available_linux_probe_command(
        path_exists,
        &["/usr/bin/getconf", "/bin/getconf"],
        &["GNU_LIBC_VERSION"],
        run_command,
    ) && output.status_success
        && output.stdout.contains("glibc")
    {
        return Some(HostLinuxLibc::Gnu);
    }

    let ldd_output = run_first_available_linux_probe_command(
        path_exists,
        &["/usr/bin/ldd", "/bin/ldd"],
        &["--version"],
        run_command,
    )?;
    let combined = format!("{}\n{}", ldd_output.stdout, ldd_output.stderr).to_ascii_lowercase();
    if combined.contains("musl") {
        return Some(HostLinuxLibc::Musl);
    }
    if ldd_output.status_success && (combined.contains("glibc") || combined.contains("gnu libc")) {
        return Some(HostLinuxLibc::Gnu);
    }

    None
}

#[cfg(target_os = "linux")]
fn run_first_available_linux_probe_command<F, G>(
    path_exists: &F,
    command_paths: &[&str],
    args: &[&str],
    run_command: &G,
) -> Option<LinuxCommandOutput>
where
    F: Fn(&Path) -> bool,
    G: Fn(&Path, &[&str]) -> Option<LinuxCommandOutput>,
{
    command_paths.iter().find_map(|candidate| {
        let path = Path::new(candidate);
        path_exists(path).then(|| run_command(path, args)).flatten()
    })
}

fn absolute_env_path<F>(env_lookup: &F, key: &str) -> Option<PathBuf>
where
    F: Fn(&str) -> Option<OsString>,
{
    let path = PathBuf::from(env_lookup(key).filter(|value| !value.is_empty())?);
    path.is_absolute().then_some(path)
}

#[cfg(windows)]
fn lookup_windows_home_drive_path<F>(env_lookup: &F) -> Option<PathBuf>
where
    F: Fn(&str) -> Option<OsString>,
{
    let home_drive = env_lookup("HOMEDRIVE").filter(|value| !value.is_empty())?;
    let home_path = env_lookup("HOMEPATH").filter(|value| !value.is_empty())?;
    let mut combined = PathBuf::from(home_drive);
    combined.push(PathBuf::from(home_path));
    combined.is_absolute().then_some(combined)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    #[cfg(target_os = "linux")]
    use std::path::Path;
    use std::path::PathBuf;

    use super::{
        HostArchitecture, HostLinuxLibc, HostOperatingSystem, TargetTripleError,
        detect_host_target_triple, executable_suffix_for_target, host_platform_from_parts,
        resolve_home_dir_with, resolve_target_triple,
    };

    #[test]
    fn host_platform_from_parts_maps_supported_pairs() {
        let linux = host_platform_from_parts("linux", "x86_64", Some(HostLinuxLibc::Gnu))
            .expect("linux platform");
        assert_eq!(linux.operating_system(), HostOperatingSystem::Linux);
        assert_eq!(linux.architecture(), HostArchitecture::X86_64);
        assert_eq!(linux.linux_libc(), Some(HostLinuxLibc::Gnu));
        assert_eq!(linux.target_triple(), "x86_64-unknown-linux-gnu");

        let macos = host_platform_from_parts("macos", "aarch64", None).expect("macos platform");
        assert_eq!(macos.operating_system(), HostOperatingSystem::Macos);
        assert_eq!(macos.architecture(), HostArchitecture::Aarch64);
        assert_eq!(macos.target_triple(), "aarch64-apple-darwin");

        let musl = host_platform_from_parts("linux", "aarch64", Some(HostLinuxLibc::Musl))
            .expect("musl platform");
        assert_eq!(musl.linux_libc(), Some(HostLinuxLibc::Musl));
        assert_eq!(musl.target_triple(), "aarch64-unknown-linux-musl");
    }

    #[test]
    fn host_platform_from_parts_rejects_unknown_pairs() {
        assert!(host_platform_from_parts("freebsd", "x86_64", None).is_none());
        assert!(host_platform_from_parts("linux", "riscv64", None).is_none());
        assert!(host_platform_from_parts("linux", "x86_64", None).is_none());
    }

    #[test]
    fn detect_host_target_triple_matches_current_host_when_supported() {
        if let Some(triple) = detect_host_target_triple() {
            assert!(!triple.is_empty());
        }
    }

    #[test]
    fn executable_suffix_matches_windows_and_unix_targets() {
        assert_eq!(
            executable_suffix_for_target("x86_64-pc-windows-msvc"),
            Ok(".exe")
        );
        assert_eq!(
            executable_suffix_for_target("x86_64-unknown-linux-gnu"),
            Ok("")
        );
        assert_eq!(
            executable_suffix_for_target("x86_64-unknown-linux-musl"),
            Ok("")
        );
    }

    #[test]
    fn resolve_target_triple_prefers_trimmed_override() {
        assert_eq!(
            resolve_target_triple(Some("  custom-target  "), "x86_64-unknown-linux-gnu"),
            Err(TargetTripleError::Unsupported("custom-target".to_string()))
        );
        assert_eq!(
            resolve_target_triple(Some("   "), "x86_64-unknown-linux-gnu"),
            Ok("x86_64-unknown-linux-gnu".to_string())
        );
    }

    #[test]
    fn resolve_target_triple_accepts_supported_override() {
        assert_eq!(
            resolve_target_triple(
                Some("  aarch64-pc-windows-msvc  "),
                "x86_64-unknown-linux-gnu",
            ),
            Ok("aarch64-pc-windows-msvc".to_string())
        );
    }

    #[test]
    fn resolve_target_triple_rejects_unknown_host_target() {
        assert_eq!(
            resolve_target_triple(None, "windows-gnu"),
            Err(TargetTripleError::Unsupported("windows-gnu".to_string()))
        );
    }

    #[test]
    fn executable_suffix_rejects_unknown_targets() {
        assert_eq!(
            executable_suffix_for_target("windows"),
            Err(TargetTripleError::Unsupported("windows".to_string()))
        );
    }

    #[test]
    fn resolve_home_dir_with_prefers_home() {
        let home = resolve_home_dir_with(&|key| match key {
            #[cfg(windows)]
            "HOME" => Some(OsString::from(r"C:\Users\test-home")),
            #[cfg(not(windows))]
            "HOME" => Some(OsString::from("/home/test")),
            #[cfg(windows)]
            "USERPROFILE" => Some(OsString::from(r"C:\Users\ignored")),
            #[cfg(not(windows))]
            "USERPROFILE" => Some(OsString::from("/Users/ignored")),
            _ => None,
        });
        #[cfg(windows)]
        assert_eq!(home, Some(PathBuf::from(r"C:\Users\test-home")));
        #[cfg(not(windows))]
        assert_eq!(home, Some(PathBuf::from("/home/test")));
    }

    #[cfg(not(windows))]
    #[test]
    fn resolve_home_dir_with_rejects_relative_home() {
        let home = resolve_home_dir_with(&|key| match key {
            "HOME" => Some(OsString::from("relative/home")),
            _ => None,
        });
        assert_eq!(home, None);
    }

    #[cfg(not(windows))]
    #[test]
    fn resolve_home_dir_with_ignores_userprofile_on_unix() {
        let home = resolve_home_dir_with(&|key| match key {
            "USERPROFILE" => Some(OsString::from("/Users/test")),
            _ => None,
        });
        assert_eq!(home, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_ignores_musl_filesystem_markers_without_runtime_evidence() {
        let libc = super::detect_host_linux_libc_with(
            &|path| path == std::path::Path::new("/etc/alpine-release"),
            &|_, _| None,
        );
        assert_eq!(libc, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_uses_getconf_for_glibc() {
        let libc = super::detect_host_linux_libc_with(
            &|path| path == Path::new("/usr/bin/getconf"),
            &|program, _| {
                if program == Path::new("/usr/bin/getconf") {
                    return Some(super::LinuxCommandOutput {
                        status_success: true,
                        stdout: "glibc 2.39\n".to_string(),
                        stderr: String::new(),
                    });
                }
                None
            },
        );
        assert_eq!(libc, Some(HostLinuxLibc::Gnu));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_does_not_probe_bare_getconf_or_ldd_names() {
        let libc = super::detect_host_linux_libc_with(
            &|path| {
                matches!(
                    path,
                    p if p == Path::new("/usr/bin/getconf") || p == Path::new("/usr/bin/ldd")
                )
            },
            &|program, _| {
                assert!(
                    program.is_absolute(),
                    "linux libc probe must use absolute command paths, got {}",
                    program.display()
                );
                None
            },
        );
        assert_eq!(libc, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_uses_bin_getconf_fallback_for_glibc() {
        let libc = super::detect_host_linux_libc_with(
            &|path| path == Path::new("/bin/getconf"),
            &|program, _| {
                if program == Path::new("/bin/getconf") {
                    return Some(super::LinuxCommandOutput {
                        status_success: true,
                        stdout: "glibc 2.39\n".to_string(),
                        stderr: String::new(),
                    });
                }
                None
            },
        );
        assert_eq!(libc, Some(HostLinuxLibc::Gnu));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_ignores_musl_toolchain_files_when_getconf_reports_glibc() {
        let libc = super::detect_host_linux_libc_with(
            &|path| {
                path == Path::new("/lib/ld-musl-x86_64.so.1")
                    || path == Path::new("/usr/bin/getconf")
            },
            &|program, _| {
                if program == Path::new("/usr/bin/getconf") {
                    return Some(super::LinuxCommandOutput {
                        status_success: true,
                        stdout: "glibc 2.39\n".to_string(),
                        stderr: String::new(),
                    });
                }
                None
            },
        );
        assert_eq!(libc, Some(HostLinuxLibc::Gnu));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_falls_back_to_ldd_version_output() {
        let libc = super::detect_host_linux_libc_with(
            &|path| path == Path::new("/usr/bin/ldd"),
            &|program, _| {
                if program == Path::new("/usr/bin/ldd") {
                    return Some(super::LinuxCommandOutput {
                        status_success: true,
                        stdout: "musl libc (x86_64)\n".to_string(),
                        stderr: String::new(),
                    });
                }
                None
            },
        );
        assert_eq!(libc, Some(HostLinuxLibc::Musl));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_uses_bin_ldd_fallback_for_musl() {
        let libc = super::detect_host_linux_libc_with(
            &|path| path == Path::new("/bin/ldd"),
            &|program, _| {
                if program == Path::new("/bin/ldd") {
                    return Some(super::LinuxCommandOutput {
                        status_success: true,
                        stdout: "musl libc (x86_64)\n".to_string(),
                        stderr: String::new(),
                    });
                }
                None
            },
        );
        assert_eq!(libc, Some(HostLinuxLibc::Musl));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_rejects_loader_markers_without_runtime_evidence() {
        let libc = super::detect_host_linux_libc_with(
            &|path| path == Path::new("/lib64/ld-linux-x86-64.so.2"),
            &|_, _| None,
        );
        assert_eq!(libc, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_rejects_unknown_linux_libc_when_runtime_checks_fail() {
        let libc = super::detect_host_linux_libc_with(&|_| false, &|_, _| None);
        assert_eq!(libc, None);
    }

    #[cfg(windows)]
    #[test]
    fn resolve_home_dir_with_uses_userprofile_on_windows() {
        let home = resolve_home_dir_with(&|key| match key {
            "USERPROFILE" => Some(OsString::from(r"C:\Users\test")),
            _ => None,
        });
        assert_eq!(home, Some(PathBuf::from(r"C:\Users\test")));
    }

    #[cfg(windows)]
    #[test]
    fn resolve_home_dir_with_skips_relative_home_before_userprofile() {
        let home = resolve_home_dir_with(&|key| match key {
            "HOME" => Some(OsString::from(r"Users\relative")),
            "USERPROFILE" => Some(OsString::from(r"C:\Users\test")),
            _ => None,
        });
        assert_eq!(home, Some(PathBuf::from(r"C:\Users\test")));
    }

    #[cfg(windows)]
    #[test]
    fn resolve_home_dir_with_uses_home_drive_and_path_on_windows() {
        let home = resolve_home_dir_with(&|key| match key {
            "HOMEDRIVE" => Some(OsString::from(r"C:")),
            "HOMEPATH" => Some(OsString::from(r"\Users\test")),
            _ => None,
        });
        assert_eq!(home, Some(PathBuf::from(r"C:\Users\test")));
    }
}
