use std::path::Path;

use crate::{Error, Result, SandboxPolicy};

const DEFAULT_MAX_POLICY_BYTES: u64 = 4 * 1024 * 1024;
const HARD_MAX_POLICY_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_INITIAL_POLICY_CAPACITY: usize = 8 * 1024;
const MAX_INITIAL_POLICY_CAPACITY: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyFormat {
    Toml,
    Json,
}

fn open_policy_file(path: &Path) -> Result<std::fs::File> {
    let file = crate::platform_open::open_readonly_nofollow(path).map_err(|err| {
        if crate::platform_open::is_symlink_open_error(&err) {
            return Error::InvalidPath(format!(
                "path {} encountered a symlink or symlink resolution loop while opening policy path",
                path.display()
            ));
        }
        if err.kind() == std::io::ErrorKind::Unsupported {
            return Error::NotPermitted(
                "loading policy files on this platform requires an atomic no-follow open primitive"
                    .to_string(),
            );
        }
        Error::io_path("open", path, err)
    })?;
    #[cfg(windows)]
    {
        let meta = file
            .metadata()
            .map_err(|err| Error::io_path("metadata", path, err))?;
        if meta.file_type().is_symlink() {
            return Err(Error::InvalidPath(format!(
                "path {} final component is a symlink; refusing to load policy via symlink final component",
                path.display()
            )));
        }
    }
    Ok(file)
}

pub fn parse_policy(raw: &str, format: PolicyFormat) -> Result<SandboxPolicy> {
    let policy = parse_policy_unvalidated(raw, format)?;
    policy.validate()?;
    Ok(policy)
}

/// Parse a policy without enforcing [`SandboxPolicy::validate`] invariants.
///
/// The returned value may violate policy safety constraints. Prefer [`parse_policy`]
/// unless you explicitly need a partially validated intermediate value.
pub fn parse_policy_unvalidated(raw: &str, format: PolicyFormat) -> Result<SandboxPolicy> {
    match format {
        PolicyFormat::Json => serde_json::from_str(raw)
            .map_err(|err| Error::InvalidPolicy(format!("invalid json policy: {err}"))),
        PolicyFormat::Toml => toml::from_str(raw)
            .map_err(|err| Error::InvalidPolicy(format!("invalid toml policy: {err}"))),
    }
}

pub fn load_policy(path: impl AsRef<Path>) -> Result<SandboxPolicy> {
    load_policy_limited(path, DEFAULT_MAX_POLICY_BYTES)
}

fn detect_policy_format(path: &Path) -> Result<(PolicyFormat, bool)> {
    match path.extension() {
        None => match path.file_name().and_then(|name| name.to_str()) {
            Some(name) if name.eq_ignore_ascii_case(".json") => Ok((PolicyFormat::Json, false)),
            Some(name) if name.eq_ignore_ascii_case(".toml") => Ok((PolicyFormat::Toml, false)),
            _ => Ok((PolicyFormat::Toml, true)),
        },
        Some(ext) => match ext.to_str() {
            Some(ext) if ext.eq_ignore_ascii_case("json") => Ok((PolicyFormat::Json, false)),
            Some(ext) if ext.eq_ignore_ascii_case("toml") => Ok((PolicyFormat::Toml, false)),
            Some(other) => Err(Error::InvalidPolicy(format!(
                "unsupported policy format {other:?}; expected .toml or .json"
            ))),
            None => Err(Error::InvalidPolicy(
                "unsupported policy format with non-UTF-8 extension; expected .toml or .json"
                    .to_string(),
            )),
        },
    }
}

/// Load and validate a policy file from disk with a byte limit.
///
/// Format detection is by file extension:
/// - `.json` => JSON
/// - `.toml` or no extension => TOML
/// - hidden file names `.json` / `.toml` are also recognized explicitly
///
/// For no-extension paths, TOML is inferred by default. Use
/// [`load_policy_limited_with_format`] to disable format inference.
///
/// This rejects symlink targets for the final path component and non-regular files
/// (FIFOs, sockets, device nodes) to avoid blocking behavior and related DoS risks.
pub fn load_policy_limited(path: impl AsRef<Path>, max_bytes: u64) -> Result<SandboxPolicy> {
    let path = path.as_ref();
    let (format, inferred_default_toml) = detect_policy_format(path)?;
    load_policy_limited_inner(path, max_bytes, format, inferred_default_toml)
}

/// Load and validate a policy file from disk with a byte limit and explicit format.
///
/// This is equivalent to [`load_policy_limited`] except it bypasses extension-based
/// format inference.
pub fn load_policy_limited_with_format(
    path: impl AsRef<Path>,
    max_bytes: u64,
    format: PolicyFormat,
) -> Result<SandboxPolicy> {
    load_policy_limited_inner(path.as_ref(), max_bytes, format, false)
}

fn load_policy_limited_inner(
    path: &Path,
    max_bytes: u64,
    format: PolicyFormat,
    inferred_default_toml: bool,
) -> Result<SandboxPolicy> {
    if max_bytes == 0 {
        return Err(Error::InvalidPolicy(
            "max policy bytes must be > 0".to_string(),
        ));
    }
    if max_bytes > HARD_MAX_POLICY_BYTES {
        return Err(Error::InvalidPolicy(format!(
            "max policy bytes exceeds hard limit ({HARD_MAX_POLICY_BYTES} bytes)"
        )));
    }

    let mut file = open_policy_file(path)?;
    let meta = file
        .metadata()
        .map_err(|err| Error::io_path("metadata", path, err))?;
    if !meta.is_file() {
        return Err(Error::InvalidPath(format!(
            "path {} is not a regular file",
            path.display()
        )));
    }
    let meta_len = meta.len();
    if meta_len > max_bytes {
        return Err(Error::FileTooLarge {
            path: path.to_path_buf(),
            size_bytes: meta_len,
            max_bytes,
        });
    }

    let (bytes, truncated) = omne_fs_primitives::read_to_end_limited_with_capacity(
        &mut file,
        usize::try_from(max_bytes).unwrap_or(usize::MAX),
        initial_policy_capacity(meta_len, max_bytes),
    )
    .map_err(|err| Error::io_path("read", path, err))?;
    if truncated {
        let read_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        return Err(Error::FileTooLarge {
            path: path.to_path_buf(),
            size_bytes: read_size,
            max_bytes,
        });
    }

    let raw =
        std::str::from_utf8(&bytes).map_err(|err| Error::invalid_utf8(path.to_path_buf(), err))?;
    let parsed = parse_policy(raw, format);
    if inferred_default_toml {
        return parsed.map_err(|err| match err {
            Error::InvalidPolicy(msg) => Error::InvalidPolicy(format!(
                "{msg}; policy format was inferred as TOML because the path has no extension"
            )),
            other => other,
        });
    }
    parsed
}

fn initial_policy_capacity(meta_len: u64, max_bytes: u64) -> usize {
    usize::try_from(meta_len.min(max_bytes))
        .ok()
        .map_or(DEFAULT_INITIAL_POLICY_CAPACITY, |capacity| {
            capacity.min(MAX_INITIAL_POLICY_CAPACITY)
        })
}

#[cfg(test)]
mod tests {
    use super::{PolicyFormat, initial_policy_capacity, parse_policy};

    use policy_meta::{Decision, ExecutionIsolation, RiskProfile};

    #[test]
    fn initial_policy_capacity_keeps_small_values() {
        assert_eq!(initial_policy_capacity(1024, 4096), 1024);
        assert_eq!(initial_policy_capacity(0, 4096), 0);
    }

    #[test]
    fn initial_policy_capacity_caps_large_values() {
        assert_eq!(
            initial_policy_capacity(64 * 1024 * 1024, 64 * 1024 * 1024),
            256 * 1024
        );
    }

    #[test]
    fn parse_policy_accepts_nested_policy_meta_in_toml() {
        let root_path = std::env::temp_dir().display().to_string();
        let raw = format!(
            r#"
[[roots]]
id = "workspace"
path = "{root_path}"
write_scope = "read_only"

[permissions]
read = true

[metadata.policy_meta]
version = 1
risk_profile = "standard"
write_scope = "workspace_write"
execution_isolation = "best_effort"
decision = "prompt"
"#
        );

        let policy = parse_policy(&raw, PolicyFormat::Toml).expect("parse policy");
        let policy_meta = policy
            .metadata
            .policy_meta
            .as_ref()
            .expect("nested policy metadata");

        assert_eq!(
            policy.root("workspace").expect("root").mode.as_str(),
            "read_only"
        );
        assert_eq!(policy_meta.version.map(|version| version.as_u8()), Some(1));
        assert_eq!(policy_meta.risk_profile, Some(RiskProfile::Standard));
        assert_eq!(
            policy_meta.write_scope.map(|scope| scope.as_str()),
            Some("workspace_write")
        );
        assert_eq!(
            policy_meta.execution_isolation,
            Some(ExecutionIsolation::BestEffort)
        );
        assert_eq!(policy_meta.decision, Some(Decision::Prompt));
    }

    #[test]
    fn toml_serialization_preserves_nested_policy_meta_table() {
        let mut policy = crate::SandboxPolicy::single_root(
            "workspace",
            std::env::temp_dir(),
            crate::RootMode::ReadOnly,
        );
        policy.metadata.policy_meta = Some(policy_meta::PolicyMetaV1 {
            version: Some(policy_meta::SpecVersion::V1),
            risk_profile: Some(RiskProfile::Standard),
            write_scope: Some(crate::RootMode::WorkspaceWrite),
            execution_isolation: Some(ExecutionIsolation::BestEffort),
            decision: Some(Decision::Prompt),
        });

        let rendered = toml::to_string(&policy).expect("serialize policy");

        assert!(rendered.contains("[metadata.policy_meta]"));
        assert!(rendered.contains("version = 1"));
        assert!(rendered.contains("risk_profile = \"standard\""));
        assert!(rendered.contains("write_scope = \"workspace_write\""));
        assert!(rendered.contains("execution_isolation = \"best_effort\""));
        assert!(rendered.contains("decision = \"prompt\""));
    }
}
