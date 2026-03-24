#[cfg(feature = "policy-io")]
#[cfg(unix)]
#[path = "common/unix_helpers.rs"]
mod unix_helpers;

#[cfg(feature = "policy-io")]
mod policy_io {
    #[cfg(unix)]
    const SYMLINK_FRAGMENT: &str = "symlink";

    use omne_fs::ops::Context;
    use omne_fs::policy::{Permissions, Root, RootMode, SandboxPolicy};
    use serde::Serialize;

    #[derive(Serialize)]
    struct TomlRoot {
        id: String,
        path: String,
        mode: String,
    }

    #[derive(Serialize)]
    struct TomlPermissions {
        read: bool,
    }

    #[derive(Serialize)]
    struct TomlPolicyDoc {
        roots: Vec<TomlRoot>,
        permissions: TomlPermissions,
    }

    fn write_readonly_toml_policy(policy_path: &std::path::Path, root_path: &std::path::Path) {
        let doc = TomlPolicyDoc {
            roots: vec![TomlRoot {
                id: "workspace".to_string(),
                path: root_path.display().to_string(),
                mode: "read_only".to_string(),
            }],
            permissions: TomlPermissions { read: true },
        };
        let encoded = toml::to_string(&doc).expect("serialize toml");
        std::fs::write(policy_path, encoded).expect("write toml");
    }

    #[cfg(unix)]
    fn assert_invalid_path(err: omne_fs::Error) {
        match err {
            omne_fs::Error::InvalidPath(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(unix)]
    fn assert_invalid_path_contains(err: omne_fs::Error, fragment: &str) {
        match err {
            omne_fs::Error::InvalidPath(msg) => {
                assert!(msg.contains(fragment), "unexpected message: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn assert_invalid_policy(err: omne_fs::Error) {
        match err {
            omne_fs::Error::InvalidPolicy(_) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn assert_invalid_policy_contains(err: omne_fs::Error, fragment: &str) {
        match err {
            omne_fs::Error::InvalidPolicy(msg) => {
                assert!(msg.contains(fragment), "unexpected message: {msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn load_policy_toml_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");

        let toml_path = dir.path().join("policy.toml");

        write_readonly_toml_policy(&toml_path, &root_path);

        let toml_policy = omne_fs::policy_io::load_policy(&toml_path).expect("load toml");
        assert_eq!(toml_policy.roots.len(), 1);
        assert_eq!(toml_policy.roots[0].id, "workspace");
        assert_eq!(toml_policy.roots[0].path, root_path);
        assert_eq!(toml_policy.roots[0].mode, RootMode::ReadOnly);
        assert!(toml_policy.permissions.read);
        assert!(!toml_policy.paths.allow_absolute);
    }

    #[test]
    fn load_policy_json_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");
        let json_path = dir.path().join("policy.json");

        std::fs::write(
            &json_path,
            serde_json::to_string(&SandboxPolicy {
                roots: vec![Root {
                    id: "workspace".to_string(),
                    path: root_path.clone(),
                    mode: RootMode::ReadOnly,
                }],
                permissions: Permissions {
                    read: true,
                    ..Default::default()
                },
                limits: Default::default(),
                secrets: Default::default(),
                traversal: Default::default(),
                paths: Default::default(),
                metadata: Default::default(),
            })
            .expect("serialize json"),
        )
        .expect("write json");

        let json_policy = omne_fs::policy_io::load_policy(&json_path).expect("load json");
        assert_eq!(json_policy.roots.len(), 1);
        assert_eq!(json_policy.roots[0].id, "workspace");
        assert_eq!(json_policy.roots[0].path, root_path);
        assert_eq!(json_policy.roots[0].mode, RootMode::ReadOnly);
        assert!(json_policy.permissions.read);
        assert!(!json_policy.paths.allow_absolute);
    }

    #[test]
    fn load_policy_without_extension_defaults_to_toml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");
        let path = dir.path().join("policy");

        write_readonly_toml_policy(&path, &root_path);

        let policy = omne_fs::policy_io::load_policy(&path).expect("load toml");
        assert_eq!(policy.roots.len(), 1);
        assert_eq!(policy.roots[0].id, "workspace");
        assert_eq!(policy.roots[0].path, root_path);
        assert_eq!(policy.roots[0].mode, RootMode::ReadOnly);
        assert!(policy.permissions.read);
    }

    #[test]
    fn load_policy_hidden_dot_json_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");
        let json_path = dir.path().join(".json");

        std::fs::write(
            &json_path,
            serde_json::to_string(&SandboxPolicy {
                roots: vec![Root {
                    id: "workspace".to_string(),
                    path: root_path.clone(),
                    mode: RootMode::ReadOnly,
                }],
                permissions: Permissions {
                    read: true,
                    ..Default::default()
                },
                limits: Default::default(),
                secrets: Default::default(),
                traversal: Default::default(),
                paths: Default::default(),
                metadata: Default::default(),
            })
            .expect("serialize json"),
        )
        .expect("write json");

        let json_policy = omne_fs::policy_io::load_policy(&json_path).expect("load json");
        assert_eq!(json_policy.roots.len(), 1);
        assert_eq!(json_policy.roots[0].id, "workspace");
        assert_eq!(json_policy.roots[0].path, root_path);
        assert_eq!(json_policy.roots[0].mode, RootMode::ReadOnly);
        assert!(json_policy.permissions.read);
        assert!(!json_policy.paths.allow_absolute);
    }

    #[test]
    fn load_policy_hidden_dot_toml_ok() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");
        let toml_path = dir.path().join(".toml");

        write_readonly_toml_policy(&toml_path, &root_path);

        let toml_policy = omne_fs::policy_io::load_policy(&toml_path).expect("load toml");
        assert_eq!(toml_policy.roots.len(), 1);
        assert_eq!(toml_policy.roots[0].id, "workspace");
        assert_eq!(toml_policy.roots[0].path, root_path);
        assert_eq!(toml_policy.roots[0].mode, RootMode::ReadOnly);
        assert!(toml_policy.permissions.read);
        assert!(!toml_policy.paths.allow_absolute);
    }

    #[test]
    fn load_policy_accepts_case_insensitive_extensions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");

        let toml_path = dir.path().join("policy.TOML");
        write_readonly_toml_policy(&toml_path, &root_path);

        let toml_policy = omne_fs::policy_io::load_policy(&toml_path).expect("load toml");
        assert_eq!(toml_policy.roots.len(), 1);
        assert_eq!(toml_policy.roots[0].id, "workspace");
        assert_eq!(toml_policy.roots[0].path, root_path);
        assert_eq!(toml_policy.roots[0].mode, RootMode::ReadOnly);
        assert!(toml_policy.permissions.read);

        let json_path = dir.path().join("policy.JSON");
        std::fs::write(
            &json_path,
            serde_json::to_string(&SandboxPolicy {
                roots: vec![Root {
                    id: "workspace".to_string(),
                    path: root_path.clone(),
                    mode: RootMode::ReadOnly,
                }],
                permissions: Permissions {
                    read: true,
                    ..Default::default()
                },
                limits: Default::default(),
                secrets: Default::default(),
                traversal: Default::default(),
                paths: Default::default(),
                metadata: Default::default(),
            })
            .expect("serialize json"),
        )
        .expect("write json");

        let json_policy = omne_fs::policy_io::load_policy(&json_path).expect("load json");
        assert_eq!(json_policy.roots.len(), 1);
        assert_eq!(json_policy.roots[0].id, "workspace");
        assert_eq!(json_policy.roots[0].path, root_path);
        assert_eq!(json_policy.roots[0].mode, RootMode::ReadOnly);
        assert!(json_policy.permissions.read);
    }

    #[test]
    fn context_from_policy_path_uses_loaded_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");
        let toml_path = dir.path().join("policy.toml");
        write_readonly_toml_policy(&toml_path, &root_path);

        let ctx = Context::from_policy_path(&toml_path).expect("ctx");
        assert!(ctx.policy().permissions.read);
    }

    #[test]
    fn load_policy_rejects_large_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, "x".repeat(100)).expect("write");

        let err = omne_fs::policy_io::load_policy_limited(&path, 10).expect_err("reject");
        match err {
            omne_fs::Error::FileTooLarge {
                path: actual_path,
                size_bytes,
                max_bytes,
            } => {
                assert_eq!(actual_path, path);
                assert_eq!(max_bytes, 10);
                assert!(size_bytes >= 100, "unexpected size_bytes: {size_bytes}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn load_policy_rejects_zero_max_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");
        let path = dir.path().join("policy.toml");
        write_readonly_toml_policy(&path, &root_path);

        let err = omne_fs::policy_io::load_policy_limited(&path, 0).expect_err("reject");
        assert_invalid_policy_contains(err, "max policy bytes must be > 0");
    }

    #[test]
    fn load_policy_rejects_max_bytes_over_hard_limit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");
        let path = dir.path().join("policy.toml");
        write_readonly_toml_policy(&path, &root_path);

        let err = omne_fs::policy_io::load_policy_limited(&path, u64::MAX).expect_err("reject");
        assert_invalid_policy_contains(err, "hard limit");
    }

    #[test]
    fn load_policy_rejects_unsupported_extension() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");
        let path = dir.path().join("policy.yaml");
        write_readonly_toml_policy(&path, &root_path);

        let err = omne_fs::policy_io::load_policy(&path).expect_err("reject");
        assert_invalid_policy(err);
    }

    #[test]
    #[cfg(unix)]
    fn load_policy_rejects_fifo_special_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.toml");
        crate::unix_helpers::create_fifo(&path);

        let err = omne_fs::policy_io::load_policy_limited(&path, 8).expect_err("reject");
        assert_invalid_path(err);
    }

    #[test]
    #[cfg(unix)]
    fn load_policy_rejects_symlink_paths() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");

        let real_policy = dir.path().join("real.toml");
        write_readonly_toml_policy(&real_policy, &root_path);

        let link_policy = dir.path().join("policy.toml");
        symlink(&real_policy, &link_policy).expect("symlink");

        let err = omne_fs::policy_io::load_policy(&link_policy).expect_err("reject");
        assert_invalid_path_contains(err, SYMLINK_FRAGMENT);
    }

    #[test]
    fn load_policy_validates_structure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");

        let policy_path = dir.path().join("invalid.toml");
        std::fs::write(
            &policy_path,
            format!(
                r#"
[[roots]]
id = "dup"
path = '{}'
write_scope = "read_only"

[[roots]]
id = "dup"
path = '{}'
write_scope = "read_only"
"#,
                root_path.display(),
                root_path.display()
            ),
        )
        .expect("write");

        let err = omne_fs::policy_io::load_policy(&policy_path).expect_err("reject");
        assert_invalid_policy(err);
    }

    #[test]
    fn parse_policy_validates_by_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        let other_root_path = dir.path().join("other");
        std::fs::create_dir_all(&root_path).expect("mkdir");
        std::fs::create_dir_all(&other_root_path).expect("mkdir");

        let raw = serde_json::json!({
            "roots": [
                {"id": "dup", "path": root_path, "mode": "read_only"},
                {"id": "dup", "path": other_root_path, "mode": "read_only"}
            ],
            "permissions": {"read": true}
        })
        .to_string();

        let err = omne_fs::policy_io::parse_policy(&raw, omne_fs::policy_io::PolicyFormat::Json)
            .expect_err("should validate");
        assert_invalid_policy(err);
    }

    #[test]
    fn parse_policy_unvalidated_preserves_raw_parse_behavior() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_path = dir.path().join("root");
        std::fs::create_dir_all(&root_path).expect("mkdir");

        let raw = serde_json::json!({
            "roots": [
                {"id": "dup", "path": root_path, "mode": "read_only"},
                {"id": "dup", "path": dir.path().join("other"), "mode": "read_only"}
            ],
            "permissions": {"read": true}
        })
        .to_string();

        let parsed = omne_fs::policy_io::parse_policy_unvalidated(
            &raw,
            omne_fs::policy_io::PolicyFormat::Json,
        )
        .expect("raw parse");
        assert_eq!(parsed.roots.len(), 2);
        assert_eq!(parsed.roots[0].id, "dup");
        assert_eq!(parsed.roots[1].id, "dup");
        assert_eq!(parsed.roots[0].path, root_path);
        assert_eq!(parsed.roots[1].path, dir.path().join("other"));
        assert_eq!(parsed.roots[0].mode, RootMode::ReadOnly);
        assert_eq!(parsed.roots[1].mode, RootMode::ReadOnly);
    }
}
