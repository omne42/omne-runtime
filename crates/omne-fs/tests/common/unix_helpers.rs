use std::ffi::CString;
use std::io::{self, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

pub fn create_fifo(path: &Path) {
    try_create_fifo(path).unwrap_or_else(|err| {
        panic!("mkfifo failed for {}: {}", path.display(), err);
    });
}

pub fn try_create_fifo(path: &Path) -> io::Result<()> {
    const MAX_MKFIFO_ATTEMPTS: usize = 64;
    const MAX_METADATA_NOT_FOUND_RETRIES: usize = 2;

    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            ErrorKind::InvalidInput,
            format!("invalid fifo path (contains NUL): {:?}", path),
        )
    })?;

    'mkfifo: for _ in 0..MAX_MKFIFO_ATTEMPTS {
        // SAFETY:
        // - Rust std has no FIFO-creation API, so the test helper must cross the libc boundary.
        // - `CString::new` guarantees `c_path` is NUL-terminated and contains no interior NULs.
        // - `c_path` lives across the synchronous `mkfifo` call and libc does not retain the
        //   pointer after return.
        // - The mode argument is a plain value and has no aliasing or lifetime requirements.
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        if rc == 0 {
            return Ok(());
        }

        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINTR) => continue,
            Some(libc::EEXIST) => {
                let mut metadata_not_found_retries = 0;
                loop {
                    match std::fs::symlink_metadata(path) {
                        Ok(metadata) => {
                            if metadata.file_type().is_fifo() {
                                return Ok(());
                            }
                            return Err(io::Error::new(
                                ErrorKind::AlreadyExists,
                                format!(
                                    "mkfifo target exists but is not a fifo: {}",
                                    path.display()
                                ),
                            ));
                        }
                        Err(meta_err)
                            if meta_err.kind() == ErrorKind::NotFound
                                && metadata_not_found_retries < MAX_METADATA_NOT_FOUND_RETRIES =>
                        {
                            metadata_not_found_retries += 1;
                            continue;
                        }
                        Err(meta_err) if meta_err.kind() == ErrorKind::NotFound => {
                            continue 'mkfifo;
                        }
                        Err(meta_err) => {
                            let raw_os_error = meta_err.raw_os_error();
                            return Err(io::Error::new(
                                meta_err.kind(),
                                format!(
                                    "symlink_metadata failed for {}: {} (raw_os_error={raw_os_error:?})",
                                    path.display(),
                                    meta_err
                                ),
                            ));
                        }
                    }
                }
            }
            _ => {
                let raw_os_error = err.raw_os_error();
                return Err(io::Error::new(
                    err.kind(),
                    format!(
                        "mkfifo failed for {}: {} (raw_os_error={raw_os_error:?})",
                        path.display(),
                        err
                    ),
                ));
            }
        }
    }

    Err(io::Error::new(
        ErrorKind::WouldBlock,
        format!(
            "mkfifo retry budget exhausted due to repeated race/EINTR after {} attempts for {}",
            MAX_MKFIFO_ATTEMPTS,
            path.display()
        ),
    ))
}
