use std::ffi::OsString;
use std::path::PathBuf;

use crate::audit::ExecEvent;
use crate::os_serialization::{
    ExactEnvPairs, ExactOsStr, ExactOsStrings, LossyEnvPairs, LossyOsStr, LossyOsStrings,
};
use policy_meta::{ExecutionIsolation, PolicyMetaV1};
use serde::{Serialize, Serializer};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestedIsolationSource {
    Request,
    PolicyDefault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecRequest {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub cwd: PathBuf,
    pub required_isolation: ExecutionIsolation,
    pub requested_isolation_source: RequestedIsolationSource,
    pub workspace_root: PathBuf,
    pub declared_mutation: bool,
    declared_mutation_explicitly: bool,
}

impl ExecRequest {
    pub fn new<I, S>(
        program: impl Into<OsString>,
        args: I,
        cwd: impl Into<PathBuf>,
        required_isolation: ExecutionIsolation,
        workspace_root: impl Into<PathBuf>,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            env: Vec::new(),
            cwd: cwd.into(),
            required_isolation,
            requested_isolation_source: RequestedIsolationSource::Request,
            workspace_root: workspace_root.into(),
            declared_mutation: false,
            declared_mutation_explicitly: false,
        }
    }

    pub fn with_policy_default_isolation<I, S>(
        program: impl Into<OsString>,
        args: I,
        cwd: impl Into<PathBuf>,
        policy_default_isolation: ExecutionIsolation,
        workspace_root: impl Into<PathBuf>,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
            env: Vec::new(),
            cwd: cwd.into(),
            required_isolation: policy_default_isolation,
            requested_isolation_source: RequestedIsolationSource::PolicyDefault,
            workspace_root: workspace_root.into(),
            declared_mutation: false,
            declared_mutation_explicitly: false,
        }
    }

    pub fn with_declared_mutation(mut self, declared_mutation: bool) -> Self {
        self.declared_mutation = declared_mutation;
        self.declared_mutation_explicitly = true;
        self
    }

    pub fn with_env<I, K, V>(mut self, env: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        self.env = env
            .into_iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect();
        self
    }

    pub(crate) fn declared_mutation_is_explicit(&self) -> bool {
        self.declared_mutation_explicitly
    }

    fn input_required_isolation(&self) -> Option<ExecutionIsolation> {
        match self.requested_isolation_source {
            RequestedIsolationSource::Request => Some(self.required_isolation),
            RequestedIsolationSource::PolicyDefault => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestResolution {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub declared_mutation: bool,
    pub input_required_isolation: Option<ExecutionIsolation>,
    pub requested_isolation: ExecutionIsolation,
    pub requested_isolation_source: RequestedIsolationSource,
    pub requested_policy_meta: PolicyMetaV1,
    pub policy_default_isolation: ExecutionIsolation,
}

impl RequestResolution {
    #[cfg(test)]
    pub(crate) fn from_request(
        request: &ExecRequest,
        policy_default_isolation: ExecutionIsolation,
    ) -> Self {
        Self::from_effective_fields(
            request,
            request.program.clone(),
            request.cwd.clone(),
            request.workspace_root.clone(),
            policy_default_isolation,
        )
    }

    pub(crate) fn from_event(
        request: &ExecRequest,
        event: &ExecEvent,
        policy_default_isolation: ExecutionIsolation,
    ) -> Self {
        Self::from_effective_fields(
            request,
            event.program.clone(),
            event.cwd.clone(),
            event.workspace_root.clone(),
            policy_default_isolation,
        )
    }

    fn from_effective_fields(
        request: &ExecRequest,
        program: OsString,
        cwd: PathBuf,
        workspace_root: PathBuf,
        policy_default_isolation: ExecutionIsolation,
    ) -> Self {
        Self {
            program,
            args: request.args.clone(),
            env: request.env.clone(),
            cwd,
            workspace_root,
            declared_mutation: request.declared_mutation,
            input_required_isolation: request.input_required_isolation(),
            requested_isolation: request.required_isolation,
            requested_isolation_source: request.requested_isolation_source,
            requested_policy_meta: PolicyMetaV1::new()
                .with_version()
                .with_execution_isolation(request.required_isolation),
            policy_default_isolation,
        }
    }
}

impl Serialize for RequestResolution {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct RequestResolutionSerde<'a> {
            program: LossyOsStr<'a>,
            args: LossyOsStrings<'a>,
            env: LossyEnvPairs<'a>,
            program_exact: ExactOsStr<'a>,
            args_exact: ExactOsStrings<'a>,
            env_exact: ExactEnvPairs<'a>,
            cwd: &'a PathBuf,
            workspace_root: &'a PathBuf,
            declared_mutation: bool,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            input_required_isolation: Option<ExecutionIsolation>,
            requested_isolation: ExecutionIsolation,
            requested_isolation_source: RequestedIsolationSource,
            requested_policy_meta: &'a PolicyMetaV1,
            policy_default_isolation: ExecutionIsolation,
        }

        RequestResolutionSerde {
            program: LossyOsStr(self.program.as_os_str()),
            args: LossyOsStrings(&self.args),
            env: LossyEnvPairs(&self.env),
            program_exact: ExactOsStr(self.program.as_os_str()),
            args_exact: ExactOsStrings(&self.args),
            env_exact: ExactEnvPairs(&self.env),
            cwd: &self.cwd,
            workspace_root: &self.workspace_root,
            declared_mutation: self.declared_mutation,
            input_required_isolation: self.input_required_isolation,
            requested_isolation: self.requested_isolation,
            requested_isolation_source: self.requested_isolation_source,
            requested_policy_meta: &self.requested_policy_meta,
            policy_default_isolation: self.policy_default_isolation,
        }
        .serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use crate::audit::{ExecDecision, requested_policy_meta};

    use super::*;

    #[test]
    fn request_new_accepts_string_like_args() {
        let request = ExecRequest::new(
            "echo",
            vec!["hello", "world"],
            ".",
            ExecutionIsolation::None,
            ".",
        );

        assert_eq!(request.program, OsString::from("echo"));
        assert_eq!(
            request.args,
            vec![OsString::from("hello"), OsString::from("world")]
        );
        assert!(!request.declared_mutation);
        assert_eq!(
            request.requested_isolation_source,
            RequestedIsolationSource::Request
        );
        assert_eq!(
            request.input_required_isolation(),
            Some(ExecutionIsolation::None)
        );
        assert!(!request.declared_mutation_is_explicit());
    }

    #[cfg(unix)]
    #[test]
    fn request_keeps_non_utf8_arguments_on_unix() {
        use std::os::unix::ffi::OsStringExt;

        let non_utf8 = OsString::from_vec(vec![0x66, 0x6f, 0x80]);
        let request = ExecRequest::new(
            OsString::from("tool"),
            vec![non_utf8.clone()],
            ".",
            ExecutionIsolation::None,
            ".",
        );

        assert_eq!(request.args, vec![non_utf8]);
    }

    #[test]
    fn request_can_be_marked_as_mutating() {
        let request = ExecRequest::new("echo", vec!["hi"], ".", ExecutionIsolation::None, ".")
            .with_declared_mutation(true);
        assert!(request.declared_mutation);
        assert!(request.declared_mutation_is_explicit());
    }

    #[test]
    fn request_can_be_marked_as_policy_defaulted() {
        let request = ExecRequest::with_policy_default_isolation(
            "echo",
            vec!["hi"],
            ".",
            ExecutionIsolation::BestEffort,
            ".",
        );
        assert_eq!(request.required_isolation, ExecutionIsolation::BestEffort);
        assert_eq!(
            request.requested_isolation_source,
            RequestedIsolationSource::PolicyDefault
        );
        assert_eq!(request.input_required_isolation(), None);
    }

    #[test]
    fn request_resolution_tracks_effective_isolation_and_provenance() {
        let request =
            ExecRequest::new("echo", vec!["hi"], ".", ExecutionIsolation::BestEffort, ".")
                .with_declared_mutation(true);

        let resolution = RequestResolution::from_request(&request, ExecutionIsolation::BestEffort);

        assert_eq!(resolution.program, OsString::from("echo"));
        assert_eq!(resolution.args, vec![OsString::from("hi")]);
        assert_eq!(
            resolution.input_required_isolation,
            Some(ExecutionIsolation::BestEffort)
        );
        assert_eq!(
            resolution.requested_isolation,
            ExecutionIsolation::BestEffort
        );
        assert_eq!(
            resolution.requested_isolation_source,
            RequestedIsolationSource::Request
        );
        assert_eq!(
            resolution.requested_policy_meta,
            PolicyMetaV1::new()
                .with_version()
                .with_execution_isolation(ExecutionIsolation::BestEffort)
        );
        assert!(resolution.declared_mutation);
    }

    #[test]
    fn request_resolution_serializes_lossy_program_and_args() {
        let request = ExecRequest::new(
            "echo",
            vec!["hello"],
            ".",
            ExecutionIsolation::BestEffort,
            ".",
        );
        let resolution = RequestResolution::from_request(&request, ExecutionIsolation::BestEffort);

        let value = serde_json::to_value(&resolution).expect("serialize resolution");
        assert_eq!(value["program"], "echo");
        assert_eq!(value["args"], serde_json::json!(["hello"]));
        assert_eq!(
            value["program_exact"],
            serde_json::json!({
                "encoding": "utf8",
                "value": "echo"
            })
        );
        assert_eq!(
            value["args_exact"],
            serde_json::json!([{
                "encoding": "utf8",
                "value": "hello"
            }])
        );
        assert_eq!(value["input_required_isolation"], "best_effort");
    }

    #[cfg(unix)]
    #[test]
    fn request_resolution_serializes_non_utf8_arguments_exactly() {
        use std::os::unix::ffi::OsStringExt;

        let request = ExecRequest::new(
            "echo",
            vec![OsString::from_vec(vec![0x66, 0x6f, 0x80])],
            ".",
            ExecutionIsolation::BestEffort,
            ".",
        );
        let resolution = RequestResolution::from_request(&request, ExecutionIsolation::BestEffort);

        let value = serde_json::to_value(&resolution).expect("serialize resolution");
        assert_eq!(value["args"], serde_json::json!(["fo\u{fffd}"]));
        assert_eq!(
            value["args_exact"],
            serde_json::json!([{
                "encoding": "unix_bytes_hex",
                "value": "666f80"
            }])
        );
    }

    #[test]
    fn request_resolution_from_event_uses_effective_paths() {
        let request = ExecRequest::new(
            "echo",
            vec!["hello"],
            ".",
            ExecutionIsolation::BestEffort,
            ".",
        );
        let event = ExecEvent {
            decision: ExecDecision::Run,
            requested_isolation: ExecutionIsolation::BestEffort,
            requested_policy_meta: requested_policy_meta(ExecutionIsolation::BestEffort),
            supported_isolation: ExecutionIsolation::BestEffort,
            program: OsString::from("echo"),
            args: vec![OsString::from("hello")],
            env: vec![(OsString::from("PATH"), OsString::from("/usr/bin"))],
            cwd: PathBuf::from("/canonical/workspace"),
            workspace_root: PathBuf::from("/canonical/workspace"),
            declared_mutation: false,
            reason: None,
            sandbox_runtime: None,
        };

        let resolution = RequestResolution::from_event(&request, &event, ExecutionIsolation::None);

        assert_eq!(resolution.cwd, PathBuf::from("/canonical/workspace"));
        assert_eq!(
            resolution.workspace_root,
            PathBuf::from("/canonical/workspace")
        );
        assert_eq!(resolution.program, OsString::from("echo"));
        assert_eq!(resolution.env, request.env);
    }
}
