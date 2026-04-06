#![deny(unsafe_code)]

mod audit;
mod audit_log;
mod error;
mod gateway;
mod os_serialization;
#[cfg(all(test, unix))]
mod path_guard;
mod policy;
mod sandbox;
mod types;

pub use crate::audit::requested_policy_meta;
pub use crate::audit::{
    ExecDecision, ExecEvent, SandboxRuntimeMechanism, SandboxRuntimeObservation,
    SandboxRuntimeOutcome,
};
pub use crate::error::{ExecError, ExecResult};
pub use crate::gateway::{
    CapabilityReport, ExecGateway, ExecutionOutcome, PreflightError, PreparedChild, PreparedCommand,
};
pub use crate::policy::GatewayPolicy;
pub use crate::types::{ExecRequest, RequestResolution, RequestedIsolationSource};
