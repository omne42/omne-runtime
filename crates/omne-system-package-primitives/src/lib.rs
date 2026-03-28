#![forbid(unsafe_code)]

//! Low-level system package primitives shared by higher-level tooling.
//!
//! This crate owns policy-free helpers for:
//! - recognizing supported system package managers
//! - building install command recipes from a package-manager + package pair
//! - declaring default package-manager fallback order per OS

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPackageInstallRecipe {
    pub program: &'static str,
    pub args: Vec<String>,
}

impl SystemPackageInstallRecipe {
    fn new(program: &'static str, leading_args: &[&str], package: &SystemPackageName) -> Self {
        let mut args = Vec::with_capacity(leading_args.len() + 2);
        args.extend(leading_args.iter().map(|arg| (*arg).to_string()));
        args.push("--".to_string());
        args.push(package.as_str().to_string());
        Self { program, args }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPackageName(String);

impl SystemPackageName {
    pub fn parse(raw: &str) -> Result<Self, InvalidSystemPackageName> {
        if raw.is_empty() {
            return Err(InvalidSystemPackageName::Empty);
        }
        if raw.starts_with('-') {
            return Err(InvalidSystemPackageName::LeadingDash);
        }
        if let Some(invalid) = raw.chars().find(|&ch| !is_allowed_package_char(ch)) {
            return Err(InvalidSystemPackageName::InvalidCharacter { character: invalid });
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SystemPackageName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl FromStr for SystemPackageName {
    type Err = InvalidSystemPackageName;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidSystemPackageName {
    Empty,
    LeadingDash,
    InvalidCharacter { character: char },
}

impl fmt::Display for InvalidSystemPackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "system package name must not be empty"),
            Self::LeadingDash => {
                write!(f, "system package name must not start with '-'")
            }
            Self::InvalidCharacter { character } => write!(
                f,
                "system package name contains unsupported character {:?}",
                character
            ),
        }
    }
}

impl std::error::Error for InvalidSystemPackageName {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemPackageManager {
    AptGet,
    Dnf,
    Yum,
    Apk,
    Pacman,
    Zypper,
    Brew,
}

impl SystemPackageManager {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "apt-get" => Some(Self::AptGet),
            "dnf" => Some(Self::Dnf),
            "yum" => Some(Self::Yum),
            "apk" => Some(Self::Apk),
            "pacman" => Some(Self::Pacman),
            "zypper" => Some(Self::Zypper),
            "brew" => Some(Self::Brew),
            _ => None,
        }
    }

    pub fn install_recipe(self, package: &SystemPackageName) -> SystemPackageInstallRecipe {
        match self {
            Self::AptGet => SystemPackageInstallRecipe::new("apt-get", &["install", "-y"], package),
            Self::Dnf => SystemPackageInstallRecipe::new("dnf", &["install", "-y"], package),
            Self::Yum => SystemPackageInstallRecipe::new("yum", &["install", "-y"], package),
            Self::Apk => SystemPackageInstallRecipe::new("apk", &["add", "--no-cache"], package),
            Self::Pacman => SystemPackageInstallRecipe::new(
                "pacman",
                &["-S", "--needed", "--noconfirm"],
                package,
            ),
            Self::Zypper => SystemPackageInstallRecipe::new(
                "zypper",
                &["--non-interactive", "install"],
                package,
            ),
            Self::Brew => SystemPackageInstallRecipe::new("brew", &["install"], package),
        }
    }
}

const LINUX_DEFAULT_SYSTEM_PACKAGE_MANAGERS: &[SystemPackageManager] = &[
    SystemPackageManager::AptGet,
    SystemPackageManager::Dnf,
    SystemPackageManager::Yum,
    SystemPackageManager::Apk,
    SystemPackageManager::Pacman,
    SystemPackageManager::Zypper,
];

const MACOS_DEFAULT_SYSTEM_PACKAGE_MANAGERS: &[SystemPackageManager] =
    &[SystemPackageManager::Brew];

fn default_system_package_managers_for_os(os: &str) -> &'static [SystemPackageManager] {
    match os {
        "linux" => LINUX_DEFAULT_SYSTEM_PACKAGE_MANAGERS,
        "macos" => MACOS_DEFAULT_SYSTEM_PACKAGE_MANAGERS,
        _ => &[],
    }
}

pub fn default_system_package_install_recipes_for_os(
    os: &str,
    package: &SystemPackageName,
) -> Vec<SystemPackageInstallRecipe> {
    default_system_package_managers_for_os(os)
        .iter()
        .copied()
        .map(|manager| manager.install_recipe(package))
        .collect()
}

fn is_allowed_package_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '+' | '_' | '-' | ':' | '@' | '/' | '=')
}

#[cfg(test)]
mod tests {
    use super::{
        InvalidSystemPackageName, SystemPackageInstallRecipe, SystemPackageManager,
        SystemPackageName, default_system_package_install_recipes_for_os,
        default_system_package_managers_for_os,
    };

    #[test]
    fn parse_rejects_unknown_manager() {
        assert_eq!(SystemPackageManager::parse("unknown"), None);
    }

    #[test]
    fn parse_accepts_only_canonical_manager_names() {
        assert_eq!(SystemPackageManager::parse("apt"), None);
        assert_eq!(
            SystemPackageManager::parse("apt-get"),
            Some(SystemPackageManager::AptGet)
        );
    }

    #[test]
    fn install_recipe_builds_expected_apt_command() {
        let package = SystemPackageName::parse("git").expect("valid package");
        assert_eq!(
            SystemPackageManager::AptGet.install_recipe(&package),
            SystemPackageInstallRecipe {
                program: "apt-get",
                args: vec![
                    "install".to_string(),
                    "-y".to_string(),
                    "--".to_string(),
                    "git".to_string(),
                ],
            }
        );
    }

    #[test]
    fn pacman_recipe_avoids_sync_only_install() {
        let package = SystemPackageName::parse("git").expect("valid package");
        assert_eq!(
            SystemPackageManager::Pacman.install_recipe(&package),
            SystemPackageInstallRecipe {
                program: "pacman",
                args: vec![
                    "-S".to_string(),
                    "--needed".to_string(),
                    "--noconfirm".to_string(),
                    "--".to_string(),
                    "git".to_string(),
                ],
            }
        );
    }

    #[test]
    fn linux_defaults_include_apt() {
        let managers = default_system_package_managers_for_os("linux");
        assert!(managers.contains(&SystemPackageManager::AptGet));
    }

    #[test]
    fn recipes_cover_linux_and_macos() {
        let package = SystemPackageName::parse("git").expect("valid package");
        assert!(
            default_system_package_install_recipes_for_os("linux", &package)
                .iter()
                .any(|recipe| recipe.program == "apt-get")
        );
        assert_eq!(
            default_system_package_install_recipes_for_os("macos", &package)[0].program,
            "brew"
        );
    }

    #[test]
    fn package_name_accepts_common_versioned_package_specs() {
        let package = SystemPackageName::parse("python3:any=3.12").expect("valid package");
        assert_eq!(package.as_str(), "python3:any=3.12");
    }

    #[test]
    fn package_name_rejects_empty_names() {
        assert_eq!(
            SystemPackageName::parse(""),
            Err(InvalidSystemPackageName::Empty)
        );
    }

    #[test]
    fn package_name_rejects_leading_dash() {
        assert_eq!(
            SystemPackageName::parse("--root=/tmp"),
            Err(InvalidSystemPackageName::LeadingDash)
        );
    }

    #[test]
    fn package_name_rejects_whitespace() {
        assert_eq!(
            SystemPackageName::parse("git curl"),
            Err(InvalidSystemPackageName::InvalidCharacter { character: ' ' })
        );
    }
}
