use std::io;
use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::path_guard;
use policy_meta::ExecutionIsolation;

const MAX_POLICY_JSON_BYTES: usize = 1024 * 1024;

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
            mutating_program_allowlist: Vec::new(),
            default_isolation: ExecutionIsolation::BestEffort,
            audit_log_path: None,
        }
    }
}

impl GatewayPolicy {
    pub fn is_mutating_program_allowlisted(&self, program: &str) -> bool {
        self.is_mutating_program_allowlisted_path(Path::new(program))
    }

    pub fn is_mutating_program_allowlisted_path(&self, program: &Path) -> bool {
        if !is_explicit_program_path(program) {
            return false;
        }
        self.mutating_program_allowlist
            .iter()
            .any(|item| is_explicit_program_path(item) && program_path_matches(item, program))
    }

    pub fn load_json(path: impl AsRef<std::path::Path>) -> io::Result<Self> {
        let content = path_guard::read_utf8_regular_file_nofollow(
            path.as_ref(),
            MAX_POLICY_JSON_BYTES,
            "policy file",
        )?;
        let policy = serde_json::from_str::<Self>(&content)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        Ok(policy)
    }
}

fn is_explicit_program_path(program: impl AsRef<Path>) -> bool {
    let program = program.as_ref();
    program.is_absolute()
        || program
            .to_string_lossy()
            .chars()
            .any(|ch| ch == '/' || ch == '\\')
}

#[cfg(windows)]
fn program_path_matches(expected: &str, actual: &Path) -> bool {
    if same_file::is_same_file(expected, actual).unwrap_or(false) {
        return true;
    }

    if normalize_windows_path_text(expected)
        == normalize_windows_path_text(actual.to_string_lossy().as_ref())
    {
        return true;
    }

    let expected_path = Path::new(expected);
    match (expected_path.parent(), actual.parent()) {
        (Some(expected_parent), Some(actual_parent))
            if normalize_windows_path_text(&expected_parent.to_string_lossy())
                == normalize_windows_path_text(&actual_parent.to_string_lossy()) =>
        {
            expected_path
                .file_name()
                .and_then(|name| name.to_str())
                .zip(actual.file_name().and_then(|name| name.to_str()))
                .is_some_and(|(expected_name, actual_name)| {
                    program_name_matches(expected_name, actual_name)
                })
        }
        _ => false,
    }
}

#[cfg(not(windows))]
fn program_path_matches(expected: &str, actual: &Path) -> bool {
    same_file::is_same_file(expected, actual).unwrap_or(false) || Path::new(expected) == actual
}

#[cfg(windows)]
fn normalize_windows_path_text(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
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

#[cfg(windows)]
fn executable_stem(name: &str) -> Option<&str> {
    name.get(..name.len().checked_sub(4)?)
        .filter(|stem| name[stem.len()..].eq_ignore_ascii_case(".exe"))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::ffi::OsString;
    use std::fs::{self, File};
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    #[cfg(unix)]
    use std::os::unix::net::UnixListener;

    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_policy_denies_none_and_enforces_mutation_allowlist() {
        let policy = GatewayPolicy::default();
        assert!(!policy.allow_isolation_none);
        assert!(policy.enforce_allowlisted_program_for_mutation);
        assert!(policy.mutating_program_allowlist.is_empty());
    }

    #[test]
    fn bare_program_allowlist_does_not_authorize_bare_program_requests() {
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec!["omne-fs".to_string()],
            ..GatewayPolicy::default()
        };
        assert!(!policy.is_mutating_program_allowlisted("omne-fs"));
    }

    #[test]
    fn bare_program_allowlist_does_not_match_explicit_path_by_basename() {
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec!["omne-fs".to_string()],
            ..GatewayPolicy::default()
        };
        assert!(!policy.is_mutating_program_allowlisted("/usr/local/bin/omne-fs"));
    }

    #[test]
    fn explicit_path_allowlist_requires_exact_path_match() {
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec!["/usr/local/bin/omne-fs".to_string()],
            ..GatewayPolicy::default()
        };

        assert!(policy.is_mutating_program_allowlisted("/usr/local/bin/omne-fs"));
        assert!(!policy.is_mutating_program_allowlisted("/tmp/omne-fs"));
    }

    #[cfg(unix)]
    #[test]
    fn explicit_path_allowlist_matches_same_binary_identity_via_symlink_alias() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("omne-fs");
        let alias = dir.path().join("omne-fs-link");
        fs::write(&target, b"#!/bin/sh\nexit 0\n").expect("write tool");
        symlink(&target, &alias).expect("create symlink alias");

        let policy = GatewayPolicy {
            mutating_program_allowlist: vec![target.display().to_string()],
            ..GatewayPolicy::default()
        };

        assert!(policy.is_mutating_program_allowlisted(&alias.display().to_string()));
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_explicit_path_is_not_allowlisted_via_lossy_text() {
        let dir = tempdir().expect("tempdir");
        let program = dir.path().join(OsString::from_vec(vec![0x66, 0x6f, 0x80]));

        let policy = GatewayPolicy {
            mutating_program_allowlist: vec![dir.path().join("fo�").display().to_string()],
            ..GatewayPolicy::default()
        };

        assert!(!policy.is_mutating_program_allowlisted_path(&program));
    }

    #[cfg(windows)]
    #[test]
    fn bare_program_allowlist_does_not_match_windows_explicit_path_by_basename() {
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec!["omne-fs-cli".to_string()],
            ..GatewayPolicy::default()
        };
        assert!(!policy.is_mutating_program_allowlisted("C:\\tools\\omne-fs-cli"));
    }

    #[cfg(windows)]
    #[test]
    fn explicit_path_allowlist_matches_windows_path_case_and_exe_variants_only_for_same_path() {
        let policy = GatewayPolicy {
            mutating_program_allowlist: vec!["C:\\tools\\omne-fs".to_string()],
            ..GatewayPolicy::default()
        };

        assert!(policy.is_mutating_program_allowlisted("C:/TOOLS/OMNE-FS.EXE"));
        assert!(!policy.is_mutating_program_allowlisted("C:\\tmp\\OMNE-FS.EXE"));
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
                "mutating_program_allowlist": ["C:/tools/omne-fs"],
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

    #[test]
    fn load_json_rejects_directory_input() {
        let dir = tempdir().expect("tempdir");
        let err = GatewayPolicy::load_json(dir.path()).expect_err("directory should be rejected");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn load_json_rejects_oversized_input() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("policy.json");
        let oversized_len = u64::try_from(MAX_POLICY_JSON_BYTES)
            .expect("policy size bound fits u64")
            .saturating_add(1);
        let file = File::create(&path).expect("create oversized policy placeholder");
        file.set_len(oversized_len)
            .expect("extend oversized policy placeholder");

        let err = GatewayPolicy::load_json(&path).expect_err("oversized policy should fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("exceeds size limit"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn load_json_rejects_symlink_input() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("policy.json");
        let link = dir.path().join("policy-link.json");
        fs::write(
            &target,
            r#"{
                "allow_isolation_none": false,
                "enforce_allowlisted_program_for_mutation": true,
                "mutating_program_allowlist": [],
                "default_isolation": "best_effort"
            }"#,
        )
        .expect("write policy");
        symlink(&target, &link).expect("create symlink");

        let err = GatewayPolicy::load_json(&link).expect_err("symlink should be rejected");
        assert_ne!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn load_json_rejects_ancestor_symlink_input() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().expect("tempdir");
        let real_dir = dir.path().join("real");
        let alias_dir = dir.path().join("alias");
        std::fs::create_dir(&real_dir).expect("create real dir");
        let policy_path = real_dir.join("policy.json");
        std::fs::write(
            &policy_path,
            r#"{
                "allow_isolation_none": true,
                "enforce_allowlisted_program_for_mutation": false,
                "mutating_program_allowlist": [],
                "default_isolation": "none"
            }"#,
        )
        .expect("write policy");
        symlink(&real_dir, &alias_dir).expect("symlink ancestor");

        let err = GatewayPolicy::load_json(&alias_dir.join("policy.json"))
            .expect_err("ancestor symlink should be rejected");
        assert_ne!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[cfg(unix)]
    #[test]
    fn load_json_rejects_special_file_input() {
        let dir = tempdir().expect("tempdir");
        let socket_path = dir.path().join("policy.sock");
        let _listener = UnixListener::bind(&socket_path).expect("bind unix socket");

        let err = GatewayPolicy::load_json(&socket_path).expect_err("socket should be rejected");
        assert_ne!(err.kind(), io::ErrorKind::InvalidData);
    }
}
