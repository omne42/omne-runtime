use std::ffi::OsString;
use std::path::PathBuf;

use policy_meta::{ExecutionIsolation, PolicyMetaV1};
use serde::ser::SerializeSeq;
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
    pub cwd: PathBuf,
    pub required_isolation: ExecutionIsolation,
    pub requested_isolation_source: RequestedIsolationSource,
    pub workspace_root: PathBuf,
    pub declared_mutation: bool,
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
            cwd: cwd.into(),
            required_isolation,
            requested_isolation_source: RequestedIsolationSource::Request,
            workspace_root: workspace_root.into(),
            declared_mutation: false,
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
            cwd: cwd.into(),
            required_isolation: policy_default_isolation,
            requested_isolation_source: RequestedIsolationSource::PolicyDefault,
            workspace_root: workspace_root.into(),
            declared_mutation: false,
        }
    }

    pub fn with_declared_mutation(mut self, declared_mutation: bool) -> Self {
        self.declared_mutation = declared_mutation;
        self
    }

    fn input_required_isolation(&self) -> Option<ExecutionIsolation> {
        match self.requested_isolation_source {
            RequestedIsolationSource::Request => Some(self.required_isolation),
            RequestedIsolationSource::PolicyDefault => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestResolution {
    #[serde(serialize_with = "serialize_os_string_lossy")]
    pub program: OsString,
    #[serde(serialize_with = "serialize_os_strings_lossy")]
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub workspace_root: PathBuf,
    pub declared_mutation: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_required_isolation: Option<ExecutionIsolation>,
    pub requested_isolation: ExecutionIsolation,
    pub requested_isolation_source: RequestedIsolationSource,
    pub requested_policy_meta: PolicyMetaV1,
    pub policy_default_isolation: ExecutionIsolation,
}

impl RequestResolution {
    pub(crate) fn from_request(
        request: &ExecRequest,
        policy_default_isolation: ExecutionIsolation,
    ) -> Self {
        Self {
            program: request.program.clone(),
            args: request.args.clone(),
            cwd: request.cwd.clone(),
            workspace_root: request.workspace_root.clone(),
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

fn serialize_os_string_lossy<S>(value: &OsString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&value.to_string_lossy())
}

fn serialize_os_strings_lossy<S>(values: &[OsString], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = serializer.serialize_seq(Some(values.len()))?;
    for value in values {
        seq.serialize_element(&value.to_string_lossy())?;
    }
    seq.end()
}

#[cfg(test)]
mod tests {
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
        assert_eq!(value["input_required_isolation"], "best_effort");
    }
}
