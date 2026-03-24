// Narrow, auditable syscall/FFI boundary for filesystem-only platform details.
#[allow(unsafe_code)]
pub(crate) mod rename;
#[cfg(unix)]
#[allow(unsafe_code)]
pub(crate) mod unix_metadata;
#[cfg(windows)]
#[allow(unsafe_code)]
pub(crate) mod windows_path_compare;
