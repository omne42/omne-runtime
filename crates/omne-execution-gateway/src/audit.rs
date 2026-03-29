use std::ffi::OsString;
use std::path::PathBuf;

use policy_meta::PolicyMetaV1;
use serde::Serialize;
use serde::Serializer;

use policy_meta::ExecutionIsolation;

use crate::os_serialization::{ExactOsStr, ExactOsStrings, LossyOsStr, LossyOsStrings};

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
            args: LossyOsStrings<'a>,
            program_exact: ExactOsStr<'a>,
            args_exact: ExactOsStrings<'a>,
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
            args: LossyOsStrings(&self.args),
            program_exact: ExactOsStr(self.program.as_os_str()),
            args_exact: ExactOsStrings(&self.args),
            cwd: &self.cwd,
            workspace_root: &self.workspace_root,
            declared_mutation: self.declared_mutation,
            reason: &self.reason,
            sandbox_runtime: &self.sandbox_runtime,
        }
        .serialize(serializer)
    }
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
