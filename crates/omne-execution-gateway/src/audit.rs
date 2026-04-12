use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

use policy_meta::PolicyMetaV1;
use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeSeq;

use policy_meta::ExecutionIsolation;

use crate::os_serialization::{ExactOsStr, ExactOsStringEncoding, ExactOsStringValue, LossyOsStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecDecision {
    Run,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxRuntimeMechanism {
    Landlock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxRuntimeOutcome {
    FullyEnforced,
    PartiallyEnforced,
    NotEnforced,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SandboxRuntimeObservation {
    pub mechanism: SandboxRuntimeMechanism,
    pub outcome: SandboxRuntimeOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecEvent {
    pub decision: ExecDecision,
    pub requested_isolation: ExecutionIsolation,
    pub requested_policy_meta: PolicyMetaV1,
    pub supported_isolation: ExecutionIsolation,
    pub program: OsString,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub declared_mutation: bool,
    pub reason: Option<String>,
    pub sandbox_runtime: Option<SandboxRuntimeObservation>,
}

pub fn requested_policy_meta(requested_isolation: ExecutionIsolation) -> PolicyMetaV1 {
    PolicyMetaV1::new()
        .with_version()
        .with_execution_isolation(requested_isolation)
}

impl Serialize for ExecEvent {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct ExecEventSerde<'a> {
            decision: ExecDecision,
            requested_isolation: ExecutionIsolation,
            requested_policy_meta: &'a PolicyMetaV1,
            supported_isolation: ExecutionIsolation,
            program: LossyOsStr<'a>,
            args: RedactedArgs<'a>,
            env: RedactedEnvPairs<'a>,
            program_exact: ExactOsStr<'a>,
            args_exact: RedactedArgsExact<'a>,
            env_exact: RedactedEnvPairsExact<'a>,
            cwd: &'a PathBuf,
            workspace_root: &'a PathBuf,
            declared_mutation: bool,
            reason: &'a Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            sandbox_runtime: &'a Option<SandboxRuntimeObservation>,
        }

        ExecEventSerde {
            decision: self.decision,
            requested_isolation: self.requested_isolation,
            requested_policy_meta: &self.requested_policy_meta,
            supported_isolation: self.supported_isolation,
            program: LossyOsStr(self.program.as_os_str()),
            args: RedactedArgs(&self.args),
            env: RedactedEnvPairs(&self.env),
            program_exact: ExactOsStr(self.program.as_os_str()),
            args_exact: RedactedArgsExact(&self.args),
            env_exact: RedactedEnvPairsExact(&self.env),
            cwd: &self.cwd,
            workspace_root: &self.workspace_root,
            declared_mutation: self.declared_mutation,
            reason: &self.reason,
            sandbox_runtime: &self.sandbox_runtime,
        }
        .serialize(serializer)
    }
}

const REDACTED: &str = "[REDACTED]";
const SENSITIVE_TERMS: &[&str] = &[
    "access_token",
    "api_key",
    "authorization",
    "credential",
    "credentials",
    "key",
    "passwd",
    "password",
    "secret",
    "token",
];

#[derive(Debug, Clone, Copy)]
struct RedactedArgs<'a>(&'a [OsString]);

impl Serialize for RedactedArgs<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for value in redact_args(self.0) {
            seq.serialize_element(&value.to_string_lossy())?;
        }
        seq.end()
    }
}

#[derive(Debug, Clone, Copy)]
struct RedactedArgsExact<'a>(&'a [OsString]);

impl Serialize for RedactedArgsExact<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let redacted = redact_args(self.0);
        let mut seq = serializer.serialize_seq(Some(redacted.len()))?;
        for value in &redacted {
            seq.serialize_element(&exact_os_string_value(value.as_os_str()))?;
        }
        seq.end()
    }
}

#[derive(Debug, Clone, Copy)]
struct RedactedEnvPairs<'a>(&'a [(OsString, OsString)]);

impl Serialize for RedactedEnvPairs<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for (name, value) in redact_env(self.0) {
            seq.serialize_element(&LossyEnvPairSerde {
                name: name.to_string_lossy().into_owned(),
                value: value.to_string_lossy().into_owned(),
            })?;
        }
        seq.end()
    }
}

#[derive(Debug, Clone, Copy)]
struct RedactedEnvPairsExact<'a>(&'a [(OsString, OsString)]);

impl Serialize for RedactedEnvPairsExact<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let redacted = redact_env(self.0);
        let mut seq = serializer.serialize_seq(Some(redacted.len()))?;
        for (name, value) in &redacted {
            seq.serialize_element(&ExactEnvPairSerde {
                name: exact_os_string_value(name.as_os_str()),
                value: exact_os_string_value(value.as_os_str()),
            })?;
        }
        seq.end()
    }
}

#[derive(Serialize)]
struct LossyEnvPairSerde {
    name: String,
    value: String,
}

#[derive(Serialize)]
struct ExactEnvPairSerde {
    name: ExactOsStringValue,
    value: ExactOsStringValue,
}

fn redact_args(args: &[OsString]) -> Vec<OsString> {
    let mut redacted = Vec::with_capacity(args.len());
    let mut redact_next = false;

    for arg in args {
        if redact_next {
            redacted.push(OsString::from(REDACTED));
            redact_next = false;
            continue;
        }

        let Some(text) = arg.to_str() else {
            redacted.push(arg.clone());
            continue;
        };

        if let Some(redacted_arg) = redact_arg_inline(text) {
            redacted.push(OsString::from(redacted_arg));
            continue;
        }

        if is_sensitive_flag(text) {
            redacted.push(arg.clone());
            redact_next = true;
            continue;
        }

        redacted.push(arg.clone());
    }

    redacted
}

fn redact_env(env: &[(OsString, OsString)]) -> Vec<(OsString, OsString)> {
    env.iter()
        .map(|(name, value)| {
            if name.to_str().map(is_sensitive_name).unwrap_or(false) {
                (name.clone(), OsString::from(REDACTED))
            } else {
                (name.clone(), value.clone())
            }
        })
        .collect()
}

fn redact_arg_inline(arg: &str) -> Option<String> {
    if let Some((flag, _)) = split_flag_assignment(arg)
        && is_sensitive_flag_name(flag)
    {
        return Some(format!("{flag}={REDACTED}"));
    }

    if let Some((name, _)) = split_env_assignment(arg)
        && is_sensitive_name(name)
    {
        return Some(format!("{name}={REDACTED}"));
    }

    None
}

fn is_sensitive_flag(arg: &str) -> bool {
    split_flag_name(arg)
        .map(is_sensitive_flag_name)
        .unwrap_or(false)
}

fn is_sensitive_flag_name(flag: &str) -> bool {
    let normalized = flag.trim_start_matches('-');
    is_sensitive_name(normalized)
}

fn split_flag_name(arg: &str) -> Option<&str> {
    if !arg.starts_with('-') || arg == "-" {
        return None;
    }

    Some(arg.split_once('=').map(|(name, _)| name).unwrap_or(arg))
}

fn split_flag_assignment(arg: &str) -> Option<(&str, &str)> {
    let (name, value) = arg.split_once('=')?;
    if !name.starts_with('-') || name == "-" {
        return None;
    }
    Some((name, value))
}

fn split_env_assignment(arg: &str) -> Option<(&str, &str)> {
    let (name, value) = arg.split_once('=')?;
    if name.is_empty() || name.starts_with('-') {
        return None;
    }
    Some((name, value))
}

fn is_sensitive_name(name: &str) -> bool {
    let normalized = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();

    normalized
        .split('_')
        .filter(|segment| !segment.is_empty())
        .any(|segment| SENSITIVE_TERMS.contains(&segment))
}

fn exact_os_string_value(value: &OsStr) -> ExactOsStringValue {
    if let Some(text) = value.to_str() {
        return ExactOsStringValue {
            encoding: ExactOsStringEncoding::Utf8,
            value: text.to_string(),
        };
    }

    non_utf8_exact_os_string_value(value)
}

#[cfg(unix)]
fn non_utf8_exact_os_string_value(value: &OsStr) -> ExactOsStringValue {
    use std::os::unix::ffi::OsStrExt;

    ExactOsStringValue {
        encoding: ExactOsStringEncoding::UnixBytesHex,
        value: encode_hex(value.as_bytes()),
    }
}

#[cfg(windows)]
fn non_utf8_exact_os_string_value(value: &OsStr) -> ExactOsStringValue {
    use std::os::windows::ffi::OsStrExt;

    let mut bytes = Vec::new();
    for unit in value.encode_wide() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    ExactOsStringValue {
        encoding: ExactOsStringEncoding::WindowsUtf16LeHex,
        value: encode_hex(&bytes),
    }
}

#[cfg(all(not(unix), not(windows)))]
fn non_utf8_exact_os_string_value(value: &OsStr) -> ExactOsStringValue {
    ExactOsStringValue {
        encoding: ExactOsStringEncoding::PlatformDebug,
        value: format!("{value:?}"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn requested_policy_meta_emits_canonical_fragment() {
        assert_eq!(
            serde_json::to_value(requested_policy_meta(ExecutionIsolation::BestEffort))
                .expect("serialize policy meta"),
            json!({
                "version": 1,
                "execution_isolation": "best_effort"
            })
        );
    }

    fn sample_event(args: Vec<&str>, env: Vec<(&str, &str)>) -> ExecEvent {
        ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: ExecutionIsolation::BestEffort,
            requested_policy_meta: requested_policy_meta(ExecutionIsolation::BestEffort),
            supported_isolation: ExecutionIsolation::BestEffort,
            program: OsString::from("runner"),
            args: args.into_iter().map(OsString::from).collect(),
            env: env
                .into_iter()
                .map(|(name, value)| (OsString::from(name), OsString::from(value)))
                .collect(),
            cwd: PathBuf::from("/tmp"),
            workspace_root: PathBuf::from("/workspace"),
            declared_mutation: false,
            reason: None,
            sandbox_runtime: None,
        }
    }

    #[test]
    fn exec_event_redacts_sensitive_flag_value_pairs() {
        let value = serde_json::to_value(sample_event(
            vec!["deploy", "--password", "super-secret"],
            vec![],
        ))
        .expect("serialize exec event");

        assert_eq!(value["args"], json!(["deploy", "--password", REDACTED]));
        assert_eq!(value["args_exact"][2]["value"], json!(REDACTED));
    }

    #[test]
    fn exec_event_redacts_sensitive_inline_arguments() {
        let value = serde_json::to_value(sample_event(
            vec!["deploy", "--token=abc123", "API_KEY=xyz"],
            vec![],
        ))
        .expect("serialize exec event");

        assert_eq!(
            value["args"],
            json!([
                "deploy",
                format!("--token={REDACTED}"),
                format!("API_KEY={REDACTED}")
            ])
        );
        assert_eq!(
            value["args_exact"][1]["value"],
            json!(format!("--token={REDACTED}"))
        );
        assert_eq!(
            value["args_exact"][2]["value"],
            json!(format!("API_KEY={REDACTED}"))
        );
    }

    #[test]
    fn exec_event_redacts_sensitive_environment_values() {
        let value = serde_json::to_value(sample_event(
            vec!["deploy"],
            vec![("API_TOKEN", "abc123"), ("SAFE_MODE", "1")],
        ))
        .expect("serialize exec event");

        assert_eq!(
            value["env"],
            json!([
                {"name": "API_TOKEN", "value": REDACTED},
                {"name": "SAFE_MODE", "value": "1"}
            ])
        );
        assert_eq!(value["env_exact"][0]["value"]["value"], json!(REDACTED));
        assert_eq!(value["env_exact"][1]["value"]["value"], json!("1"));
    }

    #[test]
    fn exec_event_keeps_non_sensitive_arguments_intact() {
        let value = serde_json::to_value(sample_event(
            vec!["--monkey", "banana", "MODE=debug"],
            vec![("MODE", "debug")],
        ))
        .expect("serialize exec event");

        assert_eq!(value["args"], json!(["--monkey", "banana", "MODE=debug"]));
        assert_eq!(
            value["env"],
            json!([
                {"name": "MODE", "value": "debug"}
            ])
        );
    }
}
