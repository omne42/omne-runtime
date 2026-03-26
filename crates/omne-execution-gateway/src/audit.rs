use std::ffi::OsString;
use std::path::PathBuf;

use policy_meta::PolicyMetaV1;
use serde::Serialize;
use serde::ser::Serializer;

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
    #[serde(serialize_with = "serialize_os_string_lossy")]
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

fn serialize_os_string_lossy<S>(value: &OsString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string_lossy())
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
}
