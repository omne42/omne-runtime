#![forbid(unsafe_code)]

//! Low-level system package primitives shared by higher-level tooling.
//!
//! This crate owns policy-free helpers for:
//! - recognizing supported system package managers
//! - building install command recipes from a package-manager + package pair
//! - declaring default package-manager fallback order per OS

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemPackageInstallRecipe {
    pub program: &'static str,
    pub args: Vec<String>,
}

impl SystemPackageInstallRecipe {
    fn new(program: &'static str, leading_args: &[&str], package: &str) -> Self {
        let mut args = Vec::with_capacity(leading_args.len() + 2);
        args.extend(leading_args.iter().map(|arg| (*arg).to_string()));
        args.push("--".to_string());
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

    pub fn install_recipe(self, package: &str) -> SystemPackageInstallRecipe {
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
    package: &str,
) -> Vec<SystemPackageInstallRecipe> {
    default_system_package_managers_for_os(os)
        .iter()
        .copied()
        .map(|manager| manager.install_recipe(package))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        SystemPackageInstallRecipe, SystemPackageManager,
        default_system_package_install_recipes_for_os, default_system_package_managers_for_os,
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
        assert_eq!(
            SystemPackageManager::AptGet.install_recipe("git"),
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
        assert_eq!(
            SystemPackageManager::Pacman.install_recipe("git"),
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
}
