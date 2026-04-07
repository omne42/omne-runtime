#![forbid(unsafe_code)]

//! Low-level system package primitives shared by higher-level tooling.
//!
//! This crate owns policy-free helpers for:
//! - recognizing supported system package managers
//! - building install command recipes from a package-manager + package pair
//! - declaring default package-manager fallback order per OS

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPackageName(String);

impl SystemPackageName {
    pub fn new(raw: &str) -> Result<Self, SystemPackageNameError> {
        if raw.is_empty() {
            return Err(SystemPackageNameError::Empty);
        }
        if raw.trim() != raw {
            return Err(SystemPackageNameError::SurroundingWhitespace);
        }
        if raw.chars().any(char::is_whitespace) {
            return Err(SystemPackageNameError::ContainsWhitespace);
        }
        if raw.chars().any(char::is_control) {
            return Err(SystemPackageNameError::ContainsControlCharacter);
        }
        if raw.contains(['/', '\\']) {
            return Err(SystemPackageNameError::ContainsPathSeparator);
        }
        if matches!(raw, "." | "..") {
            return Err(SystemPackageNameError::RelativePathReference);
        }
        if raw.starts_with('-') {
            return Err(SystemPackageNameError::LooksLikeOption);
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

impl TryFrom<&str> for SystemPackageName {
    type Error = SystemPackageNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemPackageNameError {
    Empty,
    SurroundingWhitespace,
    ContainsWhitespace,
    ContainsControlCharacter,
    ContainsPathSeparator,
    RelativePathReference,
    LooksLikeOption,
}

impl fmt::Display for SystemPackageNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "package name must not be empty"),
            Self::SurroundingWhitespace => {
                write!(
                    f,
                    "package name must not have leading or trailing whitespace"
                )
            }
            Self::ContainsWhitespace => {
                write!(f, "package name must not contain whitespace")
            }
            Self::ContainsControlCharacter => {
                write!(f, "package name must not contain control characters")
            }
            Self::ContainsPathSeparator => {
                write!(f, "package name must not contain path separators")
            }
            Self::RelativePathReference => {
                write!(f, "package name must not be `.` or `..`")
            }
            Self::LooksLikeOption => {
                write!(f, "package name must not look like a command-line option")
            }
        }
    }
}

impl std::error::Error for SystemPackageNameError {}

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

    pub fn try_install_recipe(
        self,
        package: &str,
    ) -> Result<SystemPackageInstallRecipe, SystemPackageNameError> {
        let package = SystemPackageName::new(package)?;
        Ok(self.install_recipe(&package))
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

pub fn try_default_system_package_install_recipes_for_os(
    os: &str,
    package: &str,
) -> Result<Vec<SystemPackageInstallRecipe>, SystemPackageNameError> {
    let package = SystemPackageName::new(package)?;
    Ok(default_system_package_install_recipes_for_os(os, &package))
}

#[cfg(test)]
mod tests {
    use super::{
        SystemPackageInstallRecipe, SystemPackageManager, SystemPackageName,
        SystemPackageNameError, default_system_package_install_recipes_for_os,
        default_system_package_managers_for_os, try_default_system_package_install_recipes_for_os,
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
        let package = SystemPackageName::new("git").expect("valid package name");
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
        let package = SystemPackageName::new("git").expect("valid package name");
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
        let package = SystemPackageName::new("git").expect("valid package name");
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
    fn try_install_recipe_rejects_invalid_package_names() {
        let cases = [
            ("", SystemPackageNameError::Empty),
            (" git", SystemPackageNameError::SurroundingWhitespace),
            ("git tool", SystemPackageNameError::ContainsWhitespace),
            ("git\ntool", SystemPackageNameError::ContainsWhitespace),
            (
                "git\u{0000}",
                SystemPackageNameError::ContainsControlCharacter,
            ),
            ("../git", SystemPackageNameError::ContainsPathSeparator),
            ("/tmp/git", SystemPackageNameError::ContainsPathSeparator),
            ("..", SystemPackageNameError::RelativePathReference),
            ("-y", SystemPackageNameError::LooksLikeOption),
        ];

        for (raw, expected) in cases {
            let err = SystemPackageManager::AptGet
                .try_install_recipe(raw)
                .expect_err("package name should be rejected");
            assert_eq!(err, expected, "unexpected validation for `{raw}`");
        }
    }

    #[test]
    fn package_name_accepts_common_package_tokens() {
        for raw in [
            "git",
            "python3-dev",
            "libstdc++",
            "foo.bar",
            "pkg_name",
            "nodejs@20",
        ] {
            let package = SystemPackageName::new(raw).expect("package should be accepted");
            assert_eq!(package.as_str(), raw);
        }
    }

    #[test]
    fn try_default_recipes_reject_invalid_package_names() {
        let err = try_default_system_package_install_recipes_for_os("linux", "./git")
            .expect_err("invalid package should be rejected");
        assert_eq!(err, SystemPackageNameError::ContainsPathSeparator);
    }
}
