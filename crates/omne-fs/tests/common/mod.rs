use omne_fs::policy::{Permissions, SandboxPolicy};
use policy_meta::WriteScope;

fn permissive_permissions() -> Permissions {
    Permissions {
        read: true,
        glob: true,
        grep: true,
        list_dir: true,
        stat: true,
        edit: true,
        patch: true,
        delete: true,
        mkdir: true,
        write: true,
        move_path: true,
        copy_file: true,
    }
}

/// Build a single-root test policy with a caller-provided root id.
pub fn test_policy_with_root_id(
    root_id: &str,
    root: &std::path::Path,
    mode: WriteScope,
) -> SandboxPolicy {
    let mut policy = SandboxPolicy::single_root(root_id, root.to_path_buf(), mode);
    policy.permissions = permissive_permissions();
    policy.secrets.deny_globs = Vec::new();
    policy.secrets.redact_regexes = vec!["API_KEY=[A-Za-z0-9_]+".to_string()];
    policy.secrets.replacement = "***REDACTED***".to_string();
    policy
}

/// Build a default single-root test policy using root id "root".
pub fn test_policy(root: &std::path::Path, mode: WriteScope) -> SandboxPolicy {
    test_policy_with_root_id("root", root, mode)
}

/// Build a policy with all operation permissions enabled.
/// This only changes `permissions`; `secrets`, `paths`, `limits`, and `traversal`
/// remain at their default values from `test_policy`.
pub fn all_permissions_test_policy(root: &std::path::Path, mode: WriteScope) -> SandboxPolicy {
    test_policy(root, mode)
}

#[cfg(test)]
mod tests {
    use super::{all_permissions_test_policy, test_policy};
    use policy_meta::WriteScope;
    use std::path::Path;

    #[test]
    fn all_permissions_policy_only_changes_permissions() {
        let root = Path::new("test-root");
        let base = test_policy(root, WriteScope::ReadOnly);
        let policy = all_permissions_test_policy(root, WriteScope::ReadOnly);

        assert_eq!(policy.secrets.deny_globs, base.secrets.deny_globs);
        assert_eq!(policy.secrets.redact_regexes, base.secrets.redact_regexes);
        assert_eq!(policy.secrets.replacement, base.secrets.replacement);
        assert_eq!(policy.paths.allow_absolute, base.paths.allow_absolute);
        assert_eq!(policy.traversal.skip_globs, base.traversal.skip_globs);
        assert_eq!(policy.traversal.stable_sort, base.traversal.stable_sort);
        assert_eq!(policy.limits.max_read_bytes, base.limits.max_read_bytes);
        assert_eq!(policy.limits.max_patch_bytes, base.limits.max_patch_bytes);
        assert_eq!(policy.limits.max_write_bytes, base.limits.max_write_bytes);
        assert_eq!(policy.limits.max_results, base.limits.max_results);
        assert_eq!(policy.limits.max_walk_entries, base.limits.max_walk_entries);
        assert_eq!(policy.limits.max_walk_files, base.limits.max_walk_files);
        assert_eq!(policy.limits.max_walk_ms, base.limits.max_walk_ms);
        assert_eq!(policy.limits.max_line_bytes, base.limits.max_line_bytes);
    }
}
