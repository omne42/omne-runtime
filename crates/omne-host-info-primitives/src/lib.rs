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
pub enum HostLinuxLibc {
    Gnu,
    Musl,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxLibcDetection {
    Detected(HostLinuxLibc),
    Unavailable,
    Ambiguous,
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
            (HostOperatingSystem::Linux, HostArchitecture::Aarch64, Some(HostLinuxLibc::Gnu)) => {
                "aarch64-unknown-linux-gnu"
            }
            (HostOperatingSystem::Linux, HostArchitecture::Aarch64, Some(HostLinuxLibc::Musl)) => {
                "aarch64-unknown-linux-musl"
            }
            (HostOperatingSystem::Linux, HostArchitecture::X86_64, Some(HostLinuxLibc::Gnu)) => {
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
            (HostOperatingSystem::Linux, _, None) => panic!("linux host platforms require libc"),
            (HostOperatingSystem::Macos, _, Some(_))
            | (HostOperatingSystem::Windows, _, Some(_)) => unreachable!(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SupportedTargetTriple {
    Aarch64AppleDarwin,
    X8664AppleDarwin,
    Aarch64UnknownLinuxGnu,
    Aarch64UnknownLinuxMusl,
    X8664UnknownLinuxGnu,
    X8664UnknownLinuxMusl,
    Aarch64PcWindowsMsvc,
    X8664PcWindowsMsvc,
}

impl SupportedTargetTriple {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Aarch64AppleDarwin => "aarch64-apple-darwin",
            Self::X8664AppleDarwin => "x86_64-apple-darwin",
            Self::Aarch64UnknownLinuxGnu => "aarch64-unknown-linux-gnu",
            Self::Aarch64UnknownLinuxMusl => "aarch64-unknown-linux-musl",
            Self::X8664UnknownLinuxGnu => "x86_64-unknown-linux-gnu",
            Self::X8664UnknownLinuxMusl => "x86_64-unknown-linux-musl",
            Self::Aarch64PcWindowsMsvc => "aarch64-pc-windows-msvc",
            Self::X8664PcWindowsMsvc => "x86_64-pc-windows-msvc",
        }
    }

    const fn executable_suffix(self) -> &'static str {
        match self {
            Self::Aarch64PcWindowsMsvc | Self::X8664PcWindowsMsvc => ".exe",
            Self::Aarch64AppleDarwin
            | Self::X8664AppleDarwin
            | Self::Aarch64UnknownLinuxGnu
            | Self::Aarch64UnknownLinuxMusl
            | Self::X8664UnknownLinuxGnu
            | Self::X8664UnknownLinuxMusl => "",
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
            Self::Unsupported(target) => write!(f, "unsupported target triple: {target}"),
        }
    }
}

impl std::error::Error for TargetTripleError {}

fn parse_supported_target_triple(raw: &str) -> Result<SupportedTargetTriple, TargetTripleError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(TargetTripleError::Empty);
    }

    match trimmed {
        "aarch64-apple-darwin" => Ok(SupportedTargetTriple::Aarch64AppleDarwin),
        "x86_64-apple-darwin" => Ok(SupportedTargetTriple::X8664AppleDarwin),
        "aarch64-unknown-linux-gnu" => Ok(SupportedTargetTriple::Aarch64UnknownLinuxGnu),
        "aarch64-unknown-linux-musl" => Ok(SupportedTargetTriple::Aarch64UnknownLinuxMusl),
        "x86_64-unknown-linux-gnu" => Ok(SupportedTargetTriple::X8664UnknownLinuxGnu),
        "x86_64-unknown-linux-musl" => Ok(SupportedTargetTriple::X8664UnknownLinuxMusl),
        "aarch64-pc-windows-msvc" => Ok(SupportedTargetTriple::Aarch64PcWindowsMsvc),
        "x86_64-pc-windows-msvc" => Ok(SupportedTargetTriple::X8664PcWindowsMsvc),
        _ => Err(TargetTripleError::Unsupported(trimmed.to_string())),
    }
}

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

pub fn try_resolve_target_triple(
    override_target: Option<&str>,
    host_target_triple: &str,
) -> Result<String, TargetTripleError> {
    if let Some(raw) = override_target {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return parse_supported_target_triple(trimmed)
                .map(|target| target.as_str().to_string());
        }
    }
    parse_supported_target_triple(host_target_triple).map(|target| target.as_str().to_string())
}

pub fn resolve_target_triple(override_target: Option<&str>, host_target_triple: &str) -> String {
    try_resolve_target_triple(override_target, host_target_triple).unwrap_or_else(|_| {
        parse_supported_target_triple(host_target_triple)
            .map(|target| target.as_str())
            .unwrap_or("")
            .to_string()
    })
}

pub fn try_executable_suffix_for_target(
    target_triple: &str,
) -> Result<&'static str, TargetTripleError> {
    parse_supported_target_triple(target_triple).map(SupportedTargetTriple::executable_suffix)
}

pub fn executable_suffix_for_target(target_triple: &str) -> &'static str {
    try_executable_suffix_for_target(target_triple).unwrap_or("")
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
    let linux_libc = match os {
        HostOperatingSystem::Linux => Some(linux_libc?),
        HostOperatingSystem::Macos | HostOperatingSystem::Windows => None,
    };
    Some(HostPlatform {
        os,
        arch,
        linux_libc,
    })
}

#[cfg(target_os = "linux")]
fn detect_host_linux_libc() -> Option<HostLinuxLibc> {
    detect_host_linux_libc_with_probes(
        &|| std::fs::read_to_string("/proc/self/maps").ok(),
        &|path| path.is_file(),
    )
}

#[cfg(not(target_os = "linux"))]
fn detect_host_linux_libc() -> Option<HostLinuxLibc> {
    None
}

#[cfg(target_os = "linux")]
fn detect_host_linux_libc_with_probes<ProcMapsReader, F>(
    proc_maps_reader: &ProcMapsReader,
    path_exists: &F,
) -> Option<HostLinuxLibc>
where
    ProcMapsReader: Fn() -> Option<String>,
    F: Fn(&std::path::Path) -> bool,
{
    match proc_maps_reader()
        .as_deref()
        .map(detect_host_linux_libc_from_proc_maps)
        .unwrap_or(LinuxLibcDetection::Unavailable)
    {
        LinuxLibcDetection::Detected(libc) => Some(libc),
        LinuxLibcDetection::Ambiguous => None,
        LinuxLibcDetection::Unavailable => {
            detect_host_linux_libc_from_filesystem_markers(path_exists).into_option()
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_host_linux_libc_from_proc_maps(proc_maps: &str) -> LinuxLibcDetection {
    let normalized = proc_maps.to_ascii_lowercase();
    let musl_marker_present = normalized.contains("ld-musl-") || normalized.contains("libc.musl-");
    let gnu_marker_present = normalized.contains("ld-linux-") || normalized.contains("libc.so.6");

    classify_linux_libc_markers(musl_marker_present, gnu_marker_present)
}

#[cfg(target_os = "linux")]
fn detect_host_linux_libc_from_filesystem_markers<F>(path_exists: &F) -> LinuxLibcDetection
where
    F: Fn(&std::path::Path) -> bool,
{
    let musl_loader_paths = [
        "/lib/ld-musl-x86_64.so.1",
        "/lib/ld-musl-aarch64.so.1",
        "/lib64/ld-musl-x86_64.so.1",
        "/lib64/ld-musl-aarch64.so.1",
    ];
    let musl_marker_present = musl_loader_paths
        .iter()
        .any(|path| path_exists(std::path::Path::new(path)));
    let alpine_marker_present = path_exists(std::path::Path::new("/etc/alpine-release"));

    let gnu_loader_paths = [
        "/lib64/ld-linux-x86-64.so.2",
        "/lib/ld-linux-aarch64.so.1",
        "/lib/ld-linux-x86-64.so.2",
        "/lib64/ld-linux-aarch64.so.1",
    ];
    let gnu_marker_present = gnu_loader_paths
        .iter()
        .any(|path| path_exists(std::path::Path::new(path)));

    if alpine_marker_present {
        return LinuxLibcDetection::Detected(HostLinuxLibc::Musl);
    }

    classify_linux_libc_markers(musl_marker_present, gnu_marker_present)
}

#[cfg(target_os = "linux")]
fn classify_linux_libc_markers(
    musl_marker_present: bool,
    gnu_marker_present: bool,
) -> LinuxLibcDetection {
    match (musl_marker_present, gnu_marker_present) {
        (true, false) => LinuxLibcDetection::Detected(HostLinuxLibc::Musl),
        (false, true) => LinuxLibcDetection::Detected(HostLinuxLibc::Gnu),
        (false, false) => LinuxLibcDetection::Unavailable,
        (true, true) => LinuxLibcDetection::Ambiguous,
    }
}

#[cfg(target_os = "linux")]
impl LinuxLibcDetection {
    const fn into_option(self) -> Option<HostLinuxLibc> {
        match self {
            Self::Detected(libc) => Some(libc),
            Self::Unavailable | Self::Ambiguous => None,
        }
    }
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
        HostArchitecture, HostLinuxLibc, HostOperatingSystem, TargetTripleError,
        detect_host_target_triple, executable_suffix_for_target, host_platform_from_parts,
        resolve_home_dir_with, resolve_target_triple, try_executable_suffix_for_target,
        try_resolve_target_triple,
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
    fn host_platform_from_parts_fails_closed_for_linux_without_libc() {
        assert!(host_platform_from_parts("linux", "aarch64", None).is_none());
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
            ".exe"
        );
        assert_eq!(executable_suffix_for_target("x86_64-unknown-linux-gnu"), "");
        assert_eq!(
            executable_suffix_for_target("x86_64-unknown-linux-musl"),
            ""
        );
    }

    #[test]
    fn resolve_target_triple_prefers_supported_trimmed_override() {
        assert_eq!(
            try_resolve_target_triple(
                Some("  aarch64-pc-windows-msvc  "),
                "x86_64-unknown-linux-gnu",
            ),
            Ok("aarch64-pc-windows-msvc".to_string())
        );
    }

    #[test]
    fn resolve_target_triple_uses_host_for_blank_override() {
        assert_eq!(
            resolve_target_triple(Some("   "), "x86_64-unknown-linux-gnu"),
            "x86_64-unknown-linux-gnu".to_string()
        );
    }

    #[test]
    fn resolve_target_triple_rejects_blank_host_target() {
        assert_eq!(
            try_resolve_target_triple(None, "   "),
            Err(TargetTripleError::Empty)
        );
    }

    #[test]
    fn resolve_target_triple_rejects_unknown_override() {
        assert_eq!(
            try_resolve_target_triple(Some("  custom-target  "), "x86_64-unknown-linux-gnu"),
            Err(TargetTripleError::Unsupported("custom-target".to_string()))
        );
    }

    #[test]
    fn executable_suffix_rejects_unknown_targets() {
        assert_eq!(
            try_executable_suffix_for_target("windows"),
            Err(TargetTripleError::Unsupported("windows".to_string()))
        );
        assert_eq!(
            try_executable_suffix_for_target("x86_64-unknown-linux-windows-gnu"),
            Err(TargetTripleError::Unsupported(
                "x86_64-unknown-linux-windows-gnu".to_string()
            ))
        );
    }

    #[test]
    fn resolve_target_triple_legacy_wrapper_falls_back_when_override_is_unsupported() {
        assert_eq!(
            resolve_target_triple(Some("custom-target"), "x86_64-unknown-linux-gnu"),
            "x86_64-unknown-linux-gnu".to_string()
        );
    }

    #[test]
    fn executable_suffix_legacy_wrapper_fails_closed_for_unknown_targets() {
        assert_eq!(executable_suffix_for_target("windows"), "");
        assert_eq!(
            executable_suffix_for_target("x86_64-unknown-linux-windows-gnu"),
            ""
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
    fn detect_host_linux_libc_prefers_musl_filesystem_markers() {
        let libc = super::detect_host_linux_libc_with_probes(&|| None, &|path| {
            path == std::path::Path::new("/etc/alpine-release")
        });
        assert_eq!(libc, Some(HostLinuxLibc::Musl));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_uses_glibc_loader_markers() {
        let libc = super::detect_host_linux_libc_with_probes(&|| None, &|path| {
            path == std::path::Path::new("/lib64/ld-linux-x86-64.so.2")
        });
        assert_eq!(libc, Some(HostLinuxLibc::Gnu));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_returns_none_without_known_markers() {
        let libc = super::detect_host_linux_libc_with_probes(&|| None, &|_| false);
        assert_eq!(libc, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_fails_closed_when_loader_markers_conflict() {
        let libc = super::detect_host_linux_libc_with_probes(&|| None, &|path| {
            matches!(
                path,
                path if path == std::path::Path::new("/lib64/ld-musl-x86_64.so.1")
                    || path == std::path::Path::new("/lib64/ld-linux-x86-64.so.2")
            )
        });
        assert_eq!(libc, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_keeps_alpine_marker_authoritative_when_glibc_loader_exists() {
        let libc = super::detect_host_linux_libc_with_probes(&|| None, &|path| {
            matches!(
                path,
                path if path == std::path::Path::new("/etc/alpine-release")
                    || path == std::path::Path::new("/lib64/ld-linux-x86-64.so.2")
            )
        });
        assert_eq!(libc, Some(HostLinuxLibc::Musl));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_reads_glibc_from_current_process_maps() {
        let proc_maps = "/lib64/ld-linux-x86-64.so.2\n/usr/lib64/libc.so.6\n";
        assert_eq!(
            super::detect_host_linux_libc_from_proc_maps(proc_maps),
            super::LinuxLibcDetection::Detected(HostLinuxLibc::Gnu)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_reads_musl_from_current_process_maps() {
        let proc_maps = "/lib/ld-musl-x86_64.so.1\n/lib/libc.musl-x86_64.so.1\n";
        assert_eq!(
            super::detect_host_linux_libc_from_proc_maps(proc_maps),
            super::LinuxLibcDetection::Detected(HostLinuxLibc::Musl)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_fails_closed_for_ambiguous_process_maps() {
        let proc_maps = "/lib64/ld-linux-x86-64.so.2\n/lib/ld-musl-x86_64.so.1\n";
        assert_eq!(
            super::detect_host_linux_libc_from_proc_maps(proc_maps),
            super::LinuxLibcDetection::Ambiguous
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_does_not_fallback_after_ambiguous_process_maps() {
        let libc = super::detect_host_linux_libc_with_probes(
            &|| Some("/lib64/ld-linux-x86-64.so.2\n/lib/ld-musl-x86_64.so.1\n".to_string()),
            &|path| path == std::path::Path::new("/etc/alpine-release"),
        );
        assert_eq!(libc, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_falls_back_only_when_process_maps_are_unavailable() {
        let libc = super::detect_host_linux_libc_with_probes(&|| None, &|path| {
            path == std::path::Path::new("/lib64/ld-linux-x86-64.so.2")
        });
        assert_eq!(libc, Some(HostLinuxLibc::Gnu));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_keeps_process_maps_authoritative_when_musl_files_exist() {
        let libc = super::detect_host_linux_libc_with_probes(
            &|| Some("/lib64/ld-linux-x86-64.so.2\n/usr/lib64/libc.so.6\n".to_string()),
            &|path| path == std::path::Path::new("/lib64/ld-musl-x86_64.so.1"),
        );
        assert_eq!(libc, Some(HostLinuxLibc::Gnu));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detect_host_linux_libc_only_checks_known_filesystem_markers() {
        let seen = std::cell::RefCell::new(Vec::new());
        let libc = super::detect_host_linux_libc_with_probes(&|| None, &|path| {
            seen.borrow_mut().push(path.to_path_buf());
            false
        });
        assert_eq!(libc, None);
        assert_eq!(
            seen.into_inner(),
            vec![
                std::path::PathBuf::from("/lib/ld-musl-x86_64.so.1"),
                std::path::PathBuf::from("/lib/ld-musl-aarch64.so.1"),
                std::path::PathBuf::from("/lib64/ld-musl-x86_64.so.1"),
                std::path::PathBuf::from("/lib64/ld-musl-aarch64.so.1"),
                std::path::PathBuf::from("/etc/alpine-release"),
                std::path::PathBuf::from("/lib64/ld-linux-x86-64.so.2"),
                std::path::PathBuf::from("/lib/ld-linux-aarch64.so.1"),
                std::path::PathBuf::from("/lib/ld-linux-x86-64.so.2"),
                std::path::PathBuf::from("/lib64/ld-linux-aarch64.so.1"),
            ]
        );
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
