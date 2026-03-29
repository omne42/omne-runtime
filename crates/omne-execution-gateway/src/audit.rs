use std::ffi::OsString;
use std::path::PathBuf;

use crate::os_json::serialize_os_string;
use policy_meta::PolicyMetaV1;
use serde::Serialize;

use policy_meta::ExecutionIsolation;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecEvent {
    pub decision: ExecDecision,
    pub requested_isolation: ExecutionIsolation,
    pub requested_policy_meta: PolicyMetaV1,
    pub supported_isolation: ExecutionIsolation,
    #[serde(serialize_with = "serialize_os_string")]
    pub program: OsString,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub declared_mutation: bool,
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_runtime: Option<SandboxRuntimeObservation>,
}

pub fn requested_policy_meta(requested_isolation: ExecutionIsolation) -> PolicyMetaV1 {
    PolicyMetaV1::new()
        .with_version()
        .with_execution_isolation(requested_isolation)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;

    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;

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

    #[cfg(unix)]
    #[test]
    fn event_program_serializes_non_utf8_losslessly() {
        let event = ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: ExecutionIsolation::None,
            requested_policy_meta: requested_policy_meta(ExecutionIsolation::None),
            supported_isolation: ExecutionIsolation::None,
            program: OsString::from_vec(vec![0x66, 0x6f, 0x80]),
            cwd: PathBuf::from("/tmp"),
            workspace_root: PathBuf::from("/tmp"),
            declared_mutation: false,
            reason: None,
            sandbox_runtime: None,
        };

        let value = serde_json::to_value(&event).expect("serialize event");
        assert_eq!(
            value["program"],
            json!({
                "display": "fo\u{fffd}",
                "unix_bytes_hex": "666f80"
            })
        );
    }
}
