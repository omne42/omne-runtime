#![deny(unsafe_code)]

use std::io;
use std::path::Path;

#[cfg(test)]
use omne_fs_primitives::validate_appendable_regular_file_in_ambient_root;
use omne_fs_primitives::{
    ReadUtf8Error, open_appendable_regular_file_in_ambient_root,
    read_utf8_regular_file_in_ambient_root,
};

mod audit;
mod audit_log;
mod error;
mod gateway;
mod os_serialization;
pub mod path_guard;
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

#[doc(hidden)]
pub fn read_utf8_regular_file(
    path: &Path,
    context: &'static str,
    max_bytes: usize,
    size_subject: &'static str,
) -> io::Result<String> {
    read_utf8_regular_file_in_ambient_root(path, context, max_bytes)
        .map_err(|err| map_read_utf8_error(err, size_subject))
}

#[cfg(test)]
pub(crate) fn validate_appendable_regular_file(
    path: &Path,
    context: &'static str,
) -> io::Result<()> {
    validate_absolute_path(path, context)?;
    validate_appendable_regular_file_in_ambient_root(path, context)
}

pub(crate) fn open_appendable_regular_file(
    path: &Path,
    context: &'static str,
) -> io::Result<std::fs::File> {
    validate_absolute_path(path, context)?;
    open_appendable_regular_file_in_ambient_root(path, context).map(|file| file.into_std())
}

fn validate_absolute_path(path: &Path, context: &'static str) -> io::Result<()> {
    if path.is_absolute() {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{context} path must be absolute: {}", path.display()),
    ))
}

fn map_read_utf8_error(err: ReadUtf8Error, size_subject: &'static str) -> io::Error {
    match err {
        ReadUtf8Error::Io(err) => err,
        ReadUtf8Error::TooLarge { bytes, max_bytes } => io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{size_subject} exceeds size limit ({bytes} > {max_bytes} bytes)"),
        ),
        ReadUtf8Error::InvalidUtf8(err) => io::Error::new(io::ErrorKind::InvalidData, err),
    }
}
