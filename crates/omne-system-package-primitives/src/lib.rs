#![forbid(unsafe_code)]

//! Low-level host system package primitives shared by higher-level tooling.
//!
//! This crate owns policy-free helpers for:
//! - recognizing supported host system package managers
//! - normalizing package-manager aliases such as `apt` -> `apt-get`
//! - building install command recipes from a package-manager + package pair
//! - declaring default package-manager fallback order per host OS

use omne_host_info_primitives::detect_host_platform;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPackageInstallRecipe {
    pub program: &'static str,
    pub args: Vec<String>,
}

impl SystemPackageInstallRecipe {
    pub fn new(program: &'static str, leading_args: &[&str], package: &str) -> Self {
        let mut args = Vec::with_capacity(leading_args.len() + 1);
        args.extend(leading_args.iter().map(|arg| (*arg).to_string()));
        args.push(package.to_string());
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
            "apt" | "apt-get" => Some(Self::AptGet),
            "dnf" => Some(Self::Dnf),
            "yum" => Some(Self::Yum),
            "apk" => Some(Self::Apk),
            "pacman" => Some(Self::Pacman),
            "zypper" => Some(Self::Zypper),
            "brew" => Some(Self::Brew),
            _ => None,
        }
    }

    pub fn install_recipe(self, package: &str) -> SystemPackageInstallRecipe {
        match self {
            Self::AptGet => SystemPackageInstallRecipe::new("apt-get", &["install", "-y"], package),
            Self::Dnf => SystemPackageInstallRecipe::new("dnf", &["install", "-y"], package),
            Self::Yum => SystemPackageInstallRecipe::new("yum", &["install", "-y"], package),
            Self::Apk => SystemPackageInstallRecipe::new("apk", &["add", "--no-cache"], package),
            Self::Pacman => {
                SystemPackageInstallRecipe::new("pacman", &["-Sy", "--noconfirm"], package)
            }
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

pub fn default_system_package_managers_for_os(os: &str) -> &'static [SystemPackageManager] {
    match os {
        "linux" => LINUX_DEFAULT_SYSTEM_PACKAGE_MANAGERS,
        "macos" => MACOS_DEFAULT_SYSTEM_PACKAGE_MANAGERS,
        _ => &[],
    }
}

pub fn default_system_package_install_recipes_for_os(
    os: &str,
    package: &str,
) -> Vec<SystemPackageInstallRecipe> {
    default_system_package_managers_for_os(os)
        .iter()
        .copied()
        .map(|manager| manager.install_recipe(package))
        .collect()
}

pub fn default_system_package_install_recipes_for_current_host(
    package: &str,
) -> Vec<SystemPackageInstallRecipe> {
    let Some(platform) = detect_host_platform() else {
        return Vec::new();
    };
    default_system_package_install_recipes_for_os(platform.operating_system().as_str(), package)
}

#[cfg(test)]
mod tests {
    use super::{
        SystemPackageInstallRecipe, SystemPackageManager,
        default_system_package_install_recipes_for_current_host,
        default_system_package_install_recipes_for_os, default_system_package_managers_for_os,
    };

    #[test]
    fn parse_rejects_unknown_manager() {
        assert_eq!(SystemPackageManager::parse("unknown"), None);
    }

    #[test]
    fn parse_normalizes_apt_aliases() {
        assert_eq!(
            SystemPackageManager::parse("apt"),
            Some(SystemPackageManager::AptGet)
        );
        assert_eq!(
            SystemPackageManager::parse("apt-get"),
            Some(SystemPackageManager::AptGet)
        );
    }

    #[test]
    fn install_recipe_builds_expected_apt_command() {
        assert_eq!(
            SystemPackageManager::AptGet.install_recipe("git"),
            SystemPackageInstallRecipe {
                program: "apt-get",
                args: vec!["install".to_string(), "-y".to_string(), "git".to_string()],
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
        assert!(
            default_system_package_install_recipes_for_os("linux", "git")
                .iter()
                .any(|recipe| recipe.program == "apt-get")
        );
        assert_eq!(
            default_system_package_install_recipes_for_os("macos", "git")[0].program,
            "brew"
        );
    }

    #[test]
    fn current_host_recipes_are_safe_to_compute() {
        let _ = default_system_package_install_recipes_for_current_host("git");
    }
}
