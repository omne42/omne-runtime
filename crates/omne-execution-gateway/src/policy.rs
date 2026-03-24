use std::path::Path;
use std::path::PathBuf;
use std::{fs, io};

use serde::{Deserialize, Serialize};

use crate::types::IsolationLevel;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayPolicy {
    pub allow_isolation_none: bool,
    pub enforce_fs_tool_for_mutation: bool,
    pub fs_tool_program_allowlist: Vec<String>,
    pub default_isolation: IsolationLevel,
    pub audit_log_path: Option<PathBuf>,
}

impl Default for GatewayPolicy {
    fn default() -> Self {
        Self {
            allow_isolation_none: false,
            enforce_fs_tool_for_mutation: true,
            fs_tool_program_allowlist: vec!["omne-fs".to_string(), "omne-fs-cli".to_string()],
            default_isolation: IsolationLevel::BestEffort,
            audit_log_path: None,
        }
    }
}

impl GatewayPolicy {
    pub fn is_fs_tool_program(&self, program: &str) -> bool {
        let program_basename = Path::new(program)
            .file_name()
            .and_then(|name| name.to_str());
        self.fs_tool_program_allowlist
            .iter()
            .any(|item| item == program || program_basename.is_some_and(|name| item == name))
    }

    pub fn load_json(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let policy = serde_json::from_str::<Self>(&content)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_denies_none_and_enforces_fs_tool_for_mutation() {
        let policy = GatewayPolicy::default();
        assert!(!policy.allow_isolation_none);
        assert!(policy.enforce_fs_tool_for_mutation);
        assert!(policy.is_fs_tool_program("omne-fs"));
    }

    #[test]
    fn allowlist_matches_program_basename_for_explicit_paths() {
        let policy = GatewayPolicy::default();
        assert!(policy.is_fs_tool_program("/usr/local/bin/omne-fs"));
    }

    #[cfg(windows)]
    #[test]
    fn allowlist_matches_windows_program_basename_for_explicit_paths() {
        let policy = GatewayPolicy::default();
        assert!(policy.is_fs_tool_program("C:\\tools\\omne-fs-cli"));
    }
}
