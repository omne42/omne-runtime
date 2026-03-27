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
use std::path::PathBuf;

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
pub struct HostPlatform {
    os: HostOperatingSystem,
    arch: HostArchitecture,
}

impl HostPlatform {
    pub const fn operating_system(self) -> HostOperatingSystem {
        self.os
    }

    pub const fn architecture(self) -> HostArchitecture {
        self.arch
    }

    pub const fn target_triple(self) -> &'static str {
        match (self.os, self.arch) {
            (HostOperatingSystem::Macos, HostArchitecture::Aarch64) => "aarch64-apple-darwin",
            (HostOperatingSystem::Macos, HostArchitecture::X86_64) => "x86_64-apple-darwin",
            (HostOperatingSystem::Linux, HostArchitecture::Aarch64) => "aarch64-unknown-linux-gnu",
            (HostOperatingSystem::Linux, HostArchitecture::X86_64) => "x86_64-unknown-linux-gnu",
            (HostOperatingSystem::Windows, HostArchitecture::Aarch64) => "aarch64-pc-windows-msvc",
            (HostOperatingSystem::Windows, HostArchitecture::X86_64) => "x86_64-pc-windows-msvc",
        }
    }
}

#[cfg(windows)]
const HOME_ENV_KEYS: &[&str] = &["HOME", "USERPROFILE"];
#[cfg(not(windows))]
const HOME_ENV_KEYS: &[&str] = &["HOME"];

pub fn detect_host_platform() -> Option<HostPlatform> {
    host_platform_from_parts(std::env::consts::OS, std::env::consts::ARCH)
}

pub fn detect_host_target_triple() -> Option<&'static str> {
    detect_host_platform().map(HostPlatform::target_triple)
}

pub fn resolve_target_triple(override_target: Option<&str>, host_target_triple: &str) -> String {
    if let Some(raw) = override_target {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    host_target_triple.to_string()
}

pub fn executable_suffix_for_target(target_triple: &str) -> &'static str {
    if target_triple.contains("windows") {
        ".exe"
    } else {
        ""
    }
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

fn host_platform_from_parts(os: &str, arch: &str) -> Option<HostPlatform> {
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
    Some(HostPlatform { os, arch })
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
    use std::path::PathBuf;

    use super::{
        HostArchitecture, HostOperatingSystem, detect_host_target_triple,
        executable_suffix_for_target, host_platform_from_parts, resolve_home_dir_with,
        resolve_target_triple,
    };

    #[test]
    fn host_platform_from_parts_maps_supported_pairs() {
        let linux = host_platform_from_parts("linux", "x86_64").expect("linux platform");
        assert_eq!(linux.operating_system(), HostOperatingSystem::Linux);
        assert_eq!(linux.architecture(), HostArchitecture::X86_64);
        assert_eq!(linux.target_triple(), "x86_64-unknown-linux-gnu");

        let macos = host_platform_from_parts("macos", "aarch64").expect("macos platform");
        assert_eq!(macos.operating_system(), HostOperatingSystem::Macos);
        assert_eq!(macos.architecture(), HostArchitecture::Aarch64);
        assert_eq!(macos.target_triple(), "aarch64-apple-darwin");
    }

    #[test]
    fn host_platform_from_parts_rejects_unknown_pairs() {
        assert!(host_platform_from_parts("freebsd", "x86_64").is_none());
        assert!(host_platform_from_parts("linux", "riscv64").is_none());
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
            ".exe"
        );
        assert_eq!(executable_suffix_for_target("x86_64-unknown-linux-gnu"), "");
    }

    #[test]
    fn resolve_target_triple_prefers_trimmed_override() {
        assert_eq!(
            resolve_target_triple(Some("  custom-target  "), "x86_64-unknown-linux-gnu"),
            "custom-target"
        );
        assert_eq!(
            resolve_target_triple(Some("   "), "x86_64-unknown-linux-gnu"),
            "x86_64-unknown-linux-gnu"
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
