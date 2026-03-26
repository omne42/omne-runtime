use std::path::{Component, Path, PathBuf};

use omne_fs::policy::SandboxPolicy;

pub(crate) const CLI_ERROR_CODE_INVALID_CLI_ARGS: &str = "invalid_cli_args";
const CLI_ERROR_CODE_JSON: &str = "json";

#[derive(Debug)]
pub(crate) enum CliError {
    Tool(omne_fs::Error),
    Json(serde_json::Error),
    ArgsValidation(String),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Tool(err) => write!(f, "{err}"),
            CliError::Json(err) => write!(f, "json error: {err}"),
            CliError::ArgsValidation(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CliError::Tool(err) => Some(err),
            CliError::Json(err) => Some(err),
            CliError::ArgsValidation(_) => None,
        }
    }
}

impl From<omne_fs::Error> for CliError {
    fn from(err: omne_fs::Error) -> Self {
        Self::Tool(err)
    }
}

impl From<serde_json::Error> for CliError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

impl CliError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            CliError::Tool(err) => err.code(),
            CliError::Json(_) => CLI_ERROR_CODE_JSON,
            CliError::ArgsValidation(_) => CLI_ERROR_CODE_INVALID_CLI_ARGS,
        }
    }
}

#[derive(Debug, Clone)]
struct RedactionRoot {
    path: PathBuf,
    normalized_depth: usize,
}

impl RedactionRoot {
    fn new(path: PathBuf) -> Self {
        let normalized_depth = normalized_component_depth(path.as_path());
        Self {
            path,
            normalized_depth,
        }
    }
}

fn normalized_component_depth(path: &Path) -> usize {
    if path.as_os_str().is_empty() {
        return 1;
    }

    let mut saw_non_curdir = false;
    let mut has_root = false;
    let mut has_prefix = false;
    let mut leading_parent_count = 0usize;
    let mut normal_count = 0usize;

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                saw_non_curdir = true;
                if normal_count > 0 {
                    normal_count -= 1;
                } else if !has_root {
                    leading_parent_count = leading_parent_count.saturating_add(1);
                }
            }
            Component::Normal(_) => {
                saw_non_curdir = true;
                normal_count = normal_count.saturating_add(1);
            }
            Component::RootDir => {
                saw_non_curdir = true;
                has_root = true;
            }
            Component::Prefix(_) => {
                saw_non_curdir = true;
                has_prefix = true;
            }
        }
    }

    if !saw_non_curdir {
        return 1;
    }
    if !has_root && !has_prefix && normal_count == 0 && leading_parent_count == 0 {
        return 1;
    }

    usize::from(has_prefix)
        .saturating_add(usize::from(has_root))
        .saturating_add(leading_parent_count)
        .saturating_add(normal_count)
}

#[derive(Debug, Clone)]
pub(crate) struct PathRedaction {
    roots: Vec<RedactionRoot>,
    canonical_roots: Vec<RedactionRoot>,
}

impl PathRedaction {
    pub(crate) fn from_policy(policy: &SandboxPolicy) -> Self {
        let mut roots = Vec::<RedactionRoot>::with_capacity(policy.roots.len());
        let mut canonical_roots = Vec::<RedactionRoot>::with_capacity(policy.roots.len());

        for root in &policy.roots {
            roots.push(RedactionRoot::new(root.path.clone()));
            if let Ok(canonical) = root.path.canonicalize()
                && !paths_equivalent_for_redaction(canonical.as_path(), root.path.as_path())
            {
                canonical_roots.push(RedactionRoot::new(canonical));
            }
        }

        Self {
            roots,
            canonical_roots,
        }
    }
}

fn paths_equivalent_for_redaction(a: &Path, b: &Path) -> bool {
    omne_fs::path_utils::starts_with_case_insensitive(a, b)
        && omne_fs::path_utils::starts_with_case_insensitive(b, a)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RedactionMode {
    Off,
    BestEffort,
    Strict,
}

impl RedactionMode {
    fn from_flags(redact_paths: bool, strict_redact_paths: bool) -> Self {
        if strict_redact_paths {
            Self::Strict
        } else if redact_paths {
            Self::BestEffort
        } else {
            Self::Off
        }
    }

    fn redact_paths(self) -> bool {
        !matches!(self, Self::Off)
    }
}

#[cfg(test)]
pub(crate) fn format_path_for_error(
    path: &Path,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
    strict_redact_paths: bool,
) -> String {
    let mode = RedactionMode::from_flags(redact_paths, strict_redact_paths);
    format_path_for_error_with_mode(path, redaction, mode)
}

fn format_path_for_error_with_mode(
    path: &Path,
    redaction: Option<&PathRedaction>,
    mode: RedactionMode,
) -> String {
    if !mode.redact_paths() {
        return path.display().to_string();
    }

    if matches!(mode, RedactionMode::Strict) {
        return "<redacted>".to_string();
    }

    if !path.is_absolute() {
        return best_effort_leaf(path);
    }

    if let Some(redaction) = redaction
        && let Some(best_root) = most_specific_matching_root(path, redaction)
        && let Some(relative) =
            omne_fs::path_utils::strip_prefix_case_insensitive(path, &best_root.path)
    {
        return if relative.as_os_str().is_empty() {
            ".".to_string()
        } else {
            relative.display().to_string()
        };
    }

    best_effort_leaf(path)
}

fn most_specific_matching_root<'a>(
    path: &Path,
    redaction: &'a PathRedaction,
) -> Option<&'a RedactionRoot> {
    let mut best_root = None::<&RedactionRoot>;
    let mut best_depth = 0usize;
    for root in redaction
        .roots
        .iter()
        .chain(redaction.canonical_roots.iter())
    {
        if omne_fs::path_utils::starts_with_case_insensitive(path, &root.path)
            && root.normalized_depth > best_depth
        {
            best_depth = root.normalized_depth;
            best_root = Some(root);
        }
    }
    best_root
}

fn best_effort_leaf(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "<redacted>".to_string())
}

pub(crate) fn tool_error_details(tool: &omne_fs::Error) -> serde_json::Value {
    tool_error_details_with(tool, None, false, false)
}

fn details_map(kind: &'static str) -> serde_json::Map<String, serde_json::Value> {
    let mut out = serde_json::Map::with_capacity(1);
    out.insert(
        "kind".to_string(),
        serde_json::Value::String(kind.to_string()),
    );
    out
}

pub(crate) fn tool_error_details_with(
    tool: &omne_fs::Error,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
    strict_redact_paths: bool,
) -> serde_json::Value {
    render_tool_error(tool, redaction, redact_paths, strict_redact_paths).details
}

pub(crate) fn tool_public_message(
    tool: &omne_fs::Error,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
    strict_redact_paths: bool,
) -> String {
    render_tool_error(tool, redaction, redact_paths, strict_redact_paths).public_message
}

pub(crate) fn render_tool_error(
    tool: &omne_fs::Error,
    redaction: Option<&PathRedaction>,
    redact_paths: bool,
    strict_redact_paths: bool,
) -> ToolErrorRender {
    let mode = RedactionMode::from_flags(redact_paths, strict_redact_paths);
    render_tool_error_with_mode(tool, redaction, mode)
}

#[derive(Debug)]
pub(crate) struct ToolErrorRender {
    pub(crate) details: serde_json::Value,
    pub(crate) public_message: String,
}

fn render_tool_error_with_mode(
    tool: &omne_fs::Error,
    redaction: Option<&PathRedaction>,
    mode: RedactionMode,
) -> ToolErrorRender {
    let redact_paths = mode.redact_paths();

    match tool {
        omne_fs::Error::Io(err) => {
            let mut out = details_map(omne_fs::Error::CODE_IO);
            out.insert(
                "io_kind".to_string(),
                serde_json::Value::String(format!("{:?}", err.kind())),
            );
            if let Some(raw_os_error) = err.raw_os_error() {
                out.insert("raw_os_error".to_string(), serde_json::json!(raw_os_error));
            }
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(err.to_string()),
                );
            }

            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "io error".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        omne_fs::Error::IoPath { op, path, source } => {
            let rendered_path = format_path_for_error_with_mode(path, redaction, mode);
            let public_message = if redact_paths {
                format!("io error during {op} ({rendered_path})")
            } else {
                tool.to_string()
            };
            let mut out = details_map(omne_fs::Error::CODE_IO_PATH);
            out.insert("op".to_string(), serde_json::Value::String(op.to_string()));
            out.insert("path".to_string(), serde_json::Value::String(rendered_path));
            out.insert(
                "io_kind".to_string(),
                serde_json::Value::String(format!("{:?}", source.kind())),
            );
            if let Some(raw_os_error) = source.raw_os_error() {
                out.insert("raw_os_error".to_string(), serde_json::json!(raw_os_error));
            }
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(source.to_string()),
                );
            }

            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message,
            }
        }
        omne_fs::Error::CommittedButUnsynced { op, path, source } => {
            let rendered_path = format_path_for_error_with_mode(path, redaction, mode);
            let public_message = if redact_paths {
                format!(
                    "filesystem update committed but parent sync failed during {op} ({rendered_path})"
                )
            } else {
                tool.to_string()
            };
            let mut out = details_map(omne_fs::Error::CODE_COMMITTED_UNSYNCED);
            out.insert("op".to_string(), serde_json::Value::String(op.to_string()));
            out.insert("path".to_string(), serde_json::Value::String(rendered_path));
            out.insert(
                "io_kind".to_string(),
                serde_json::Value::String(format!("{:?}", source.kind())),
            );
            if let Some(raw_os_error) = source.raw_os_error() {
                out.insert("raw_os_error".to_string(), serde_json::json!(raw_os_error));
            }
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(source.to_string()),
                );
            }

            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message,
            }
        }
        omne_fs::Error::InvalidPolicy(message) => {
            let mut out = details_map(omne_fs::Error::CODE_INVALID_POLICY);
            out.insert(
                "message".to_string(),
                serde_json::Value::String(if redact_paths {
                    "invalid policy".to_string()
                } else {
                    message.clone()
                }),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "invalid policy".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        omne_fs::Error::InvalidPath(message) => {
            let mut out = details_map(omne_fs::Error::CODE_INVALID_PATH);
            out.insert(
                "message".to_string(),
                serde_json::Value::String(if redact_paths {
                    "invalid path".to_string()
                } else {
                    message.clone()
                }),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "invalid path".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        omne_fs::Error::RootNotFound(root_id) => {
            let rendered_root_id = format_root_id_for_error(root_id, mode);
            let public_message = if redact_paths {
                format!("root not found: {rendered_root_id}")
            } else {
                tool.to_string()
            };
            let mut out = details_map(omne_fs::Error::CODE_ROOT_NOT_FOUND);
            out.insert(
                "root_id".to_string(),
                serde_json::Value::String(rendered_root_id),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message,
            }
        }
        omne_fs::Error::OutsideRoot { root_id, path } => {
            let rendered_root_id = format_root_id_for_error(root_id, mode);
            let public_message = if redact_paths {
                format!("path resolves outside root '{rendered_root_id}'")
            } else {
                tool.to_string()
            };
            let mut out = details_map(omne_fs::Error::CODE_OUTSIDE_ROOT);
            out.insert(
                "root_id".to_string(),
                serde_json::Value::String(rendered_root_id),
            );
            out.insert(
                "path".to_string(),
                serde_json::Value::String(format_path_for_error_with_mode(path, redaction, mode)),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message,
            }
        }
        omne_fs::Error::NotPermitted(message) => {
            let mut out = details_map(omne_fs::Error::CODE_NOT_PERMITTED);
            out.insert(
                "message".to_string(),
                serde_json::Value::String(if redact_paths {
                    "not permitted".to_string()
                } else {
                    message.clone()
                }),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "not permitted".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        omne_fs::Error::SecretPathDenied(path) => {
            let rendered_path = format_path_for_error_with_mode(path, redaction, mode);
            let public_message = if redact_paths {
                format!("path is denied by secret rules: {rendered_path}")
            } else {
                tool.to_string()
            };
            let mut out = details_map(omne_fs::Error::CODE_SECRET_PATH_DENIED);
            out.insert("path".to_string(), serde_json::Value::String(rendered_path));
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message,
            }
        }
        omne_fs::Error::FileTooLarge {
            path,
            size_bytes,
            max_bytes,
        } => {
            let rendered_path = format_path_for_error_with_mode(path, redaction, mode);
            let public_message = if redact_paths {
                format!(
                    "file is too large ({size_bytes} bytes; max {max_bytes} bytes): {rendered_path}"
                )
            } else {
                tool.to_string()
            };
            let mut out = details_map(omne_fs::Error::CODE_FILE_TOO_LARGE);
            out.insert("path".to_string(), serde_json::Value::String(rendered_path));
            out.insert("size_bytes".to_string(), serde_json::json!(size_bytes));
            out.insert("max_bytes".to_string(), serde_json::json!(max_bytes));
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message,
            }
        }
        omne_fs::Error::InvalidUtf8 { path, .. } => {
            let rendered_path = format_path_for_error_with_mode(path, redaction, mode);
            let public_message = if redact_paths {
                format!("invalid utf-8 in file: {rendered_path}")
            } else {
                tool.to_string()
            };
            let mut out = details_map(omne_fs::Error::CODE_INVALID_UTF8);
            out.insert("path".to_string(), serde_json::Value::String(rendered_path));
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message,
            }
        }
        omne_fs::Error::Patch(message) => {
            let mut out = details_map(omne_fs::Error::CODE_PATCH);
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(message.clone()),
                );
            }
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "failed to apply patch".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        omne_fs::Error::InvalidRegex { pattern, source } => {
            let mut out = details_map(omne_fs::Error::CODE_INVALID_REGEX);
            out.insert(
                "message".to_string(),
                serde_json::Value::String(if redact_paths {
                    "invalid regex".to_string()
                } else {
                    format!("invalid regex pattern {pattern:?}: {source}")
                }),
            );
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "invalid regex".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        omne_fs::Error::InputTooLarge {
            size_bytes,
            max_bytes,
        } => {
            let mut out = details_map(omne_fs::Error::CODE_INPUT_TOO_LARGE);
            out.insert("size_bytes".to_string(), serde_json::json!(size_bytes));
            out.insert("max_bytes".to_string(), serde_json::json!(max_bytes));
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: tool.to_string(),
            }
        }
        omne_fs::Error::WalkDirRoot { path, source } => {
            let mut out = details_map(omne_fs::Error::CODE_WALKDIR_ROOT);
            out.insert(
                "path".to_string(),
                serde_json::Value::String(format_path_for_error_with_mode(path, redaction, mode)),
            );
            out.insert(
                "io_kind".to_string(),
                serde_json::Value::String(format!("{:?}", source.kind())),
            );
            if let Some(raw_os_error) = source.raw_os_error() {
                out.insert("raw_os_error".to_string(), serde_json::json!(raw_os_error));
            }
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(source.to_string()),
                );
            }
            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    "walkdir error".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        omne_fs::Error::WalkDir(err) => {
            let details = if redact_paths {
                let mut out = details_map(omne_fs::Error::CODE_WALKDIR);
                if let Some(path) = err.path() {
                    out.insert(
                        "path".to_string(),
                        serde_json::Value::String(format_path_for_error_with_mode(
                            path, redaction, mode,
                        )),
                    );
                }
                if let Some(io_error) = err.io_error() {
                    out.insert(
                        "io_kind".to_string(),
                        serde_json::Value::String(format!("{:?}", io_error.kind())),
                    );
                    if let Some(raw_os_error) = io_error.raw_os_error() {
                        out.insert("raw_os_error".to_string(), serde_json::json!(raw_os_error));
                    }
                }
                serde_json::Value::Object(out)
            } else {
                let mut out = details_map(omne_fs::Error::CODE_WALKDIR);
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(err.to_string()),
                );
                serde_json::Value::Object(out)
            };

            ToolErrorRender {
                details,
                public_message: if redact_paths {
                    "walkdir error".to_string()
                } else {
                    tool.to_string()
                },
            }
        }
        _ => {
            let mut out = details_map(tool.code());
            if !redact_paths {
                out.insert(
                    "message".to_string(),
                    serde_json::Value::String(tool.to_string()),
                );
            }

            ToolErrorRender {
                details: serde_json::Value::Object(out),
                public_message: if redact_paths {
                    tool.code().to_string()
                } else {
                    tool.to_string()
                },
            }
        }
    }
}

fn format_root_id_for_error(root_id: &str, mode: RedactionMode) -> String {
    if matches!(mode, RedactionMode::Strict) {
        "<redacted>".to_string()
    } else {
        root_id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use omne_fs::policy::SandboxPolicy;

    use super::{
        PathRedaction, RedactionMode, RedactionRoot, format_path_for_error_with_mode,
        most_specific_matching_root, normalized_component_depth, render_tool_error,
        tool_error_details_with, tool_public_message,
    };
    use std::path::{Path, PathBuf};

    #[test]
    fn strict_flag_without_redact_paths_still_uses_strict_mode() {
        let mode = RedactionMode::from_flags(false, true);
        assert_eq!(mode, RedactionMode::Strict);
        assert!(mode.redact_paths());
    }

    #[test]
    fn strict_mode_never_returns_raw_path() {
        let path = Path::new("/tmp/secret.txt");
        let redaction = PathRedaction {
            roots: vec![RedactionRoot::new(PathBuf::from("/tmp"))],
            canonical_roots: Vec::new(),
        };
        let formatted =
            format_path_for_error_with_mode(path, Some(&redaction), RedactionMode::Strict);
        assert_eq!(formatted, "<redacted>");
    }

    #[test]
    fn normalized_component_depth_collapses_lexical_segments() {
        let dir = tempfile::tempdir().expect("tempdir");
        let noisy_absolute = dir.path().join("tenant").join("..");

        assert_eq!(normalized_component_depth(Path::new("")), 1);
        assert_eq!(normalized_component_depth(Path::new(".")), 1);
        assert_eq!(normalized_component_depth(Path::new("a/..")), 1);
        assert_eq!(normalized_component_depth(Path::new("../a/..")), 1);
        assert_eq!(
            normalized_component_depth(noisy_absolute.as_path()),
            normalized_component_depth(dir.path())
        );
    }

    #[test]
    fn details_kind_matches_code_for_explicit_mappings() {
        let cases = vec![
            omne_fs::Error::Io(std::io::Error::other("io")),
            omne_fs::Error::IoPath {
                op: "open",
                path: PathBuf::from("/tmp/file.txt"),
                source: std::io::Error::other("io path"),
            },
            omne_fs::Error::CommittedButUnsynced {
                op: "rename",
                path: PathBuf::from("/tmp/file.txt"),
                source: std::io::Error::other("sync"),
            },
            omne_fs::Error::InvalidPolicy("bad policy".to_string()),
            omne_fs::Error::InvalidPath("bad path".to_string()),
            omne_fs::Error::RootNotFound("root".to_string()),
            omne_fs::Error::OutsideRoot {
                root_id: "root".to_string(),
                path: PathBuf::from("/tmp/outside.txt"),
            },
            omne_fs::Error::NotPermitted("nope".to_string()),
            omne_fs::Error::SecretPathDenied(PathBuf::from("/tmp/secret.txt")),
            omne_fs::Error::FileTooLarge {
                path: PathBuf::from("/tmp/large.txt"),
                size_bytes: 2,
                max_bytes: 1,
            },
            omne_fs::Error::Patch("bad patch".to_string()),
            omne_fs::Error::InputTooLarge {
                size_bytes: 2,
                max_bytes: 1,
            },
        ];

        for error in cases {
            let details = tool_error_details_with(&error, None, true, false);
            let kind = details.get("kind").and_then(serde_json::Value::as_str);
            assert_eq!(kind, Some(error.code()));
        }
    }

    #[test]
    fn missing_canonical_root_keeps_best_effort_fallback() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        let missing_root = std::env::temp_dir().join(format!(
            "omne-fs-missing-root-{}-{unique}",
            std::process::id(),
        ));
        assert!(!missing_root.exists());

        let policy =
            SandboxPolicy::single_root("root", &missing_root, policy_meta::WriteScope::ReadOnly);
        let redaction = PathRedaction::from_policy(&policy);

        let absolute_under_root = missing_root.join("secret.txt");
        let formatted = format_path_for_error_with_mode(
            &absolute_under_root,
            Some(&redaction),
            RedactionMode::BestEffort,
        );
        assert_eq!(formatted, "secret.txt");
    }

    #[test]
    fn best_effort_redaction_prefers_most_specific_normalized_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let noisy_root = dir.path().join("tenant").join("..");
        let specific_root = dir.path().join("project");
        let absolute_path = specific_root.join("secret.txt");

        let redaction = PathRedaction {
            roots: vec![
                RedactionRoot::new(noisy_root),
                RedactionRoot::new(specific_root),
            ],
            canonical_roots: Vec::new(),
        };
        let formatted = format_path_for_error_with_mode(
            &absolute_path,
            Some(&redaction),
            RedactionMode::BestEffort,
        );
        assert_eq!(formatted, "secret.txt");
    }

    #[test]
    fn most_specific_matching_root_keeps_first_root_on_tie() {
        let path = PathBuf::from("/tmp/project/secret.txt");
        let redaction = PathRedaction {
            roots: vec![RedactionRoot::new(PathBuf::from("/tmp/project"))],
            canonical_roots: vec![RedactionRoot::new(PathBuf::from("/tmp/project"))],
        };

        let selected = most_specific_matching_root(path.as_path(), &redaction)
            .expect("must select matching root");
        assert_eq!(selected.path, PathBuf::from("/tmp/project"));
    }

    #[test]
    fn canonical_root_duplicate_is_skipped_when_equal_to_declared_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");
        let policy =
            SandboxPolicy::single_root("root", &canonical_dir, policy_meta::WriteScope::ReadOnly);

        let redaction = PathRedaction::from_policy(&policy);
        assert_eq!(redaction.roots.len(), 1);
        assert!(redaction.canonical_roots.is_empty());
    }

    #[test]
    fn canonical_root_duplicate_is_skipped_when_lexically_equivalent_to_declared_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");
        let declared_with_curdir = canonical_dir.join(".");
        let policy = SandboxPolicy::single_root(
            "root",
            &declared_with_curdir,
            policy_meta::WriteScope::ReadOnly,
        );

        let redaction = PathRedaction::from_policy(&policy);
        assert_eq!(redaction.roots.len(), 1);
        assert!(redaction.canonical_roots.is_empty());
    }

    #[test]
    fn strict_mode_redacts_root_id_in_details_and_message() {
        let error = omne_fs::Error::OutsideRoot {
            root_id: "tenant-a".to_string(),
            path: PathBuf::from("/tmp/outside.txt"),
        };
        let details = tool_error_details_with(&error, None, false, true);
        let root_id = details.get("root_id").and_then(serde_json::Value::as_str);
        assert_eq!(root_id, Some("<redacted>"));

        let message = tool_public_message(&error, None, false, true);
        assert_eq!(message, "path resolves outside root '<redacted>'");
    }

    #[test]
    fn single_render_entry_matches_wrapper_outputs() {
        let error = omne_fs::Error::InvalidPath("bad path".to_string());
        let rendered = render_tool_error(&error, None, true, false);
        let details = tool_error_details_with(&error, None, true, false);
        let message = tool_public_message(&error, None, true, false);
        assert_eq!(rendered.details, details);
        assert_eq!(rendered.public_message, message);
    }
}
