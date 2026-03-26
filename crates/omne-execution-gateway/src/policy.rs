use std::path::Path;
use std::path::PathBuf;
use std::{fs, io};

use serde::{Deserialize, Serialize};

use policy_meta::ExecutionIsolation;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayPolicy {
    pub allow_isolation_none: bool,
    pub enforce_allowlisted_program_for_mutation: bool,
    pub mutating_program_allowlist: Vec<String>,
    pub default_isolation: ExecutionIsolation,
    pub audit_log_path: Option<PathBuf>,
}

impl Default for GatewayPolicy {
    fn default() -> Self {
        Self {
            allow_isolation_none: false,
            enforce_allowlisted_program_for_mutation: true,
            mutating_program_allowlist: vec!["omne-fs".to_string(), "omne-fs-cli".to_string()],
            default_isolation: ExecutionIsolation::BestEffort,
            audit_log_path: None,
        }
    }
}

impl GatewayPolicy {
    pub fn is_mutating_program_allowlisted(&self, program: &str) -> bool {
        let program_basename = Path::new(program)
            .file_name()
            .and_then(|name| name.to_str());
        self.mutating_program_allowlist.iter().any(|item| {
            program_name_matches(item, program)
                || program_basename.is_some_and(|name| program_name_matches(item, name))
        })
    }

    pub fn load_json(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let policy = serde_json::from_str::<Self>(&content)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        Ok(policy)
    }
}

#[cfg(windows)]
fn program_name_matches(expected: &str, actual: &str) -> bool {
    if expected.eq_ignore_ascii_case(actual) {
        return true;
    }

    executable_stem(expected)
        .zip(executable_stem(actual))
        .is_some_and(|(expected_stem, actual_stem)| expected_stem.eq_ignore_ascii_case(actual_stem))
        || executable_stem(actual)
            .is_some_and(|actual_stem| expected.eq_ignore_ascii_case(actual_stem))
        || executable_stem(expected)
            .is_some_and(|expected_stem| expected_stem.eq_ignore_ascii_case(actual))
}

#[cfg(not(windows))]
fn program_name_matches(expected: &str, actual: &str) -> bool {
    expected == actual
}

#[cfg(windows)]
fn executable_stem(name: &str) -> Option<&str> {
    name.get(..name.len().checked_sub(4)?)
        .filter(|stem| name[stem.len()..].eq_ignore_ascii_case(".exe"))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_policy_denies_none_and_enforces_mutation_allowlist() {
        let policy = GatewayPolicy::default();
        assert!(!policy.allow_isolation_none);
        assert!(policy.enforce_allowlisted_program_for_mutation);
        assert!(policy.is_mutating_program_allowlisted("omne-fs"));
    }

    #[test]
    fn allowlist_matches_program_basename_for_explicit_paths() {
        let policy = GatewayPolicy::default();
        assert!(policy.is_mutating_program_allowlisted("/usr/local/bin/omne-fs"));
    }

    #[cfg(windows)]
    #[test]
    fn allowlist_matches_windows_program_basename_for_explicit_paths() {
        let policy = GatewayPolicy::default();
        assert!(policy.is_mutating_program_allowlisted("C:\\tools\\omne-fs-cli"));
    }

    #[cfg(windows)]
    #[test]
    fn allowlist_matches_windows_program_basename_with_exe_suffix() {
        let policy = GatewayPolicy::default();
        assert!(policy.is_mutating_program_allowlisted("C:\\tools\\OMNE-FS.EXE"));
    }

    #[test]
    fn load_json_rejects_unknown_fields() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("policy.json");
        fs::write(
            &path,
            r#"{
                "allow_isolation_none": false,
                "enforce_allowlisted_program_for_mutation": true,
                "mutating_program_allowlist": ["omne-fs"],
                "default_isolation": "best_effort",
                "unexpected_field": true
            }"#,
        )
        .expect("write policy");

        let err = GatewayPolicy::load_json(&path).expect_err("unknown fields should be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("unknown field"),
            "unexpected error: {err}"
        );
    }
}
