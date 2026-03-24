use std::fs;

fn sync_ownership(src_meta: &fs::Metadata, tmp_file: &fs::File) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let tmp_meta = tmp_file.metadata()?;
    let src_uid: libc::uid_t = src_meta.uid();
    let src_gid: libc::gid_t = src_meta.gid();
    let tmp_uid: libc::uid_t = tmp_meta.uid();
    let tmp_gid: libc::gid_t = tmp_meta.gid();
    if src_uid == tmp_uid && src_gid == tmp_gid {
        return Ok(());
    }

    let uid: libc::uid_t = if src_uid == tmp_uid {
        libc::uid_t::MAX
    } else {
        src_uid
    };
    let gid: libc::gid_t = if src_gid == tmp_gid {
        libc::gid_t::MAX
    } else {
        src_gid
    };

    // SAFETY:
    // - POSIX exposes ownership changes on an already-open inode through `fchown`; std has no
    //   fd-scoped equivalent and reopening by path would widen TOCTOU risk.
    // - `tmp_file` is a live open file, so `as_raw_fd()` yields a valid descriptor for the full
    //   duration of the syscall.
    // - `uid`/`gid` are plain value types derived from metadata, and `*_MAX` is used only as the
    //   documented sentinel meaning "leave this field unchanged".
    let chown_rc = unsafe { libc::fchown(tmp_file.as_raw_fd(), uid, gid) };
    if chown_rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn preserve_unix_security_metadata(
    src_file: &fs::File,
    src_meta: &fs::Metadata,
    tmp_file: &fs::File,
    copy_xattrs: bool,
) -> std::io::Result<()> {
    sync_ownership(src_meta, tmp_file)?;

    if !copy_xattrs {
        return Ok(());
    }

    sync_xattrs(src_file, tmp_file)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn sync_xattrs(src_file: &fs::File, tmp_file: &fs::File) -> std::io::Result<()> {
    use std::collections::HashSet;
    use std::os::fd::AsRawFd;

    let src_fd = src_file.as_raw_fd();
    let dst_fd = tmp_file.as_raw_fd();

    let src_names = xattr_syscalls::list_fd(src_fd)?;
    let dst_names = xattr_syscalls::list_fd(dst_fd)?;
    let dst_names_empty = dst_names.is_empty();

    if src_names.is_empty() {
        for dst_name in dst_names {
            xattr_syscalls::remove_fd(dst_fd, dst_name.as_c_str())?;
        }
        return Ok(());
    }

    if !dst_names_empty {
        let mut src_name_set = HashSet::<&[u8]>::with_capacity(src_names.len());
        src_name_set.extend(src_names.iter().map(|name| name.as_bytes()));

        for dst_name in dst_names {
            if src_name_set.contains(dst_name.as_bytes()) {
                continue;
            }
            xattr_syscalls::remove_fd(dst_fd, dst_name.as_c_str())?;
        }
    }

    for name in src_names {
        let name_cstr = name.as_c_str();
        let src_value = xattr_syscalls::read_fd_required(src_fd, name_cstr)?;
        if !dst_names_empty {
            let dst_value = xattr_syscalls::read_fd(dst_fd, name_cstr)?;
            if dst_value.as_deref() == Some(src_value.as_slice()) {
                continue;
            }
        }
        xattr_syscalls::set_fd(dst_fd, name_cstr, &src_value)?;
    }

    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod xattr_syscalls {
    use std::ffi::{CStr, CString};

    // DESIGN INVARIANT (Linux/Android xattrs):
    // - Rust std provides ownership/mode timestamps, but does not expose extended attributes.
    // - We must preserve xattrs on already-open file handles so metadata copy remains bound to the
    //   same inode and does not reopen by path (which would widen TOCTOU/symlink races).
    // - Therefore this module uses fd-scoped libc xattr syscalls:
    //   `flistxattr`, `fgetxattr`, `fsetxattr`, and `fremovexattr`.
    // - All `unsafe` below is confined to syscall boundaries; pointer validity and buffer lengths
    //   are checked at each call site.
    // - The kernel reports xattr sizes dynamically; we enforce conservative caps to avoid
    //   pathological one-shot allocations from corrupted or hostile filesystems.

    const MAX_XATTR_VALUE_BYTES: usize = 1024 * 1024;
    const MAX_XATTR_NAME_LIST_BYTES: usize = 4 * 1024 * 1024;
    const MAX_XATTR_RACE_RETRIES: usize = 4;

    fn checked_kernel_len(len: libc::ssize_t, cap: usize, what: &str) -> std::io::Result<usize> {
        let len = usize::try_from(len).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{what} overflow"))
        })?;
        if len > cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{what} exceeds cap ({len} > {cap})"),
            ));
        }
        Ok(len)
    }

    #[inline]
    fn is_retryable_xattr_race(err: &std::io::Error) -> bool {
        err.raw_os_error() == Some(libc::ERANGE)
    }

    fn read_fd_impl(fd: libc::c_int, name: &CStr) -> std::io::Result<Option<Vec<u8>>> {
        for _ in 0..MAX_XATTR_RACE_RETRIES {
            // SAFETY:
            // - `fgetxattr` is required because std has no fd-scoped xattr API.
            // - `name` is a validated `CStr`, so the pointer is NUL-terminated and valid.
            // - Passing a null value pointer with length 0 is the kernel-defined probe form that
            //   asks for the required buffer length; no caller-owned memory is dereferenced.
            let len = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0) };
            if len < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENODATA) {
                    return Ok(None);
                }
                return Err(err);
            }
            let len = checked_kernel_len(len, MAX_XATTR_VALUE_BYTES, "xattr value length")?;
            if len == 0 {
                return Ok(Some(Vec::new()));
            }
            let mut buf = vec![0_u8; len];
            // SAFETY:
            // - `buf` is an owned, writable allocation sized from the kernel-reported length after
            //   overflow/cap checks, so the destination pointer is valid for `buf.len()` bytes.
            // - `name` remains a valid `CStr` for the duration of the call.
            // - The kernel writes into the caller-provided buffer synchronously and does not retain
            //   either pointer after return.
            let read = unsafe {
                libc::fgetxattr(
                    fd,
                    name.as_ptr(),
                    buf.as_mut_ptr().cast::<libc::c_void>(),
                    buf.len(),
                )
            };
            if read < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENODATA) {
                    return Ok(None);
                }
                if is_retryable_xattr_race(&err) {
                    continue;
                }
                return Err(err);
            }
            let read = usize::try_from(read).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "xattr read length overflow",
                )
            })?;
            buf.truncate(read);
            return Ok(Some(buf));
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::ResourceBusy,
            "xattr value changed concurrently during read",
        ))
    }

    pub(crate) fn read_fd_required(fd: libc::c_int, name: &CStr) -> std::io::Result<Vec<u8>> {
        read_fd_impl(fd, name)?.ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENODATA))
    }

    pub(crate) fn read_fd(fd: libc::c_int, name: &CStr) -> std::io::Result<Option<Vec<u8>>> {
        read_fd_impl(fd, name)
    }

    pub(crate) fn list_fd(fd: libc::c_int) -> std::io::Result<Vec<CString>> {
        for _ in 0..MAX_XATTR_RACE_RETRIES {
            // SAFETY:
            // - `flistxattr` is the fd-scoped primitive we need; std has no safe equivalent.
            // - Passing a null buffer with length 0 is the kernel-defined probe form used to fetch
            //   the required name-list size without exposing caller-owned memory.
            let list_len = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0) };
            if list_len < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let list_len = checked_kernel_len(
                list_len,
                MAX_XATTR_NAME_LIST_BYTES,
                "xattr name list length",
            )?;
            if list_len == 0 {
                return Ok(Vec::new());
            }

            let mut names = vec![0_u8; list_len];
            // SAFETY:
            // - `names` is an owned, writable allocation sized from the previously probed kernel
            //   length after overflow/cap checks.
            // - The cast to `*mut c_char` preserves the same allocation and does not change
            //   lifetime or aliasing guarantees.
            // - The kernel fills this buffer synchronously and does not retain the pointer.
            let list_read = unsafe {
                libc::flistxattr(fd, names.as_mut_ptr().cast::<libc::c_char>(), names.len())
            };
            if list_read < 0 {
                let err = std::io::Error::last_os_error();
                if is_retryable_xattr_race(&err) {
                    continue;
                }
                return Err(err);
            }
            let list_read = checked_kernel_len(
                list_read,
                MAX_XATTR_NAME_LIST_BYTES,
                "xattr name list read length",
            )?;

            return names[..list_read]
                .split(|byte| *byte == 0)
                .filter(|raw_name| !raw_name.is_empty())
                .map(|raw_name| {
                    CString::new(raw_name).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "xattr name contains interior NUL byte",
                        )
                    })
                })
                .collect();
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::ResourceBusy,
            "xattr name list changed concurrently during read",
        ))
    }

    pub(crate) fn remove_fd(fd: libc::c_int, name: &CStr) -> std::io::Result<()> {
        // SAFETY:
        // - `fremovexattr` is the only fd-scoped removal primitive; std does not expose one.
        // - `name` is a validated `CStr`, so the pointer is NUL-terminated and valid.
        // - The kernel consumes the pointer synchronously and does not retain it after return.
        let remove_rc = unsafe { libc::fremovexattr(fd, name.as_ptr()) };
        if remove_rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENODATA) {
            return Ok(());
        }
        Err(err)
    }

    pub(crate) fn set_fd(fd: libc::c_int, name: &CStr, value: &[u8]) -> std::io::Result<()> {
        // SAFETY:
        // - `fsetxattr` is required because std has no fd-scoped xattr write API.
        // - `name` is a validated `CStr`, and `value.as_ptr()` is valid for `value.len()` bytes by
        //   slice construction.
        // - The kernel copies from these buffers synchronously and does not retain either pointer.
        let set_rc = unsafe {
            libc::fsetxattr(
                fd,
                name.as_ptr(),
                value.as_ptr().cast::<libc::c_void>(),
                value.len(),
                0,
            )
        };
        if set_rc == 0 {
            return Ok(());
        }
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) fn preserve_unix_security_metadata(
    _src_file: &fs::File,
    src_meta: &fs::Metadata,
    tmp_file: &fs::File,
    _copy_xattrs: bool,
) -> std::io::Result<()> {
    sync_ownership(src_meta, tmp_file)
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod tests {
    use std::ffi::CString;
    use std::fs::{self, OpenOptions};
    use std::os::fd::AsRawFd;

    fn xattr_not_supported(err: &std::io::Error) -> bool {
        matches!(err.raw_os_error(), Some(code) if [
            libc::ENOTSUP,
            libc::EOPNOTSUPP,
            libc::EPERM,
            libc::EACCES
        ]
        .contains(&code))
    }

    fn set_xattr(file: &fs::File, name: &str, value: &[u8]) -> std::io::Result<()> {
        let name = CString::new(name).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "xattr name contained NUL")
        })?;
        // SAFETY:
        // - Test coverage still has to cross the real fd-scoped xattr syscall boundary because the
        //   production path uses that exact primitive and std has no safe equivalent.
        // - `file.as_raw_fd()` comes from a live open file, `name` is a validated `CString`, and
        //   `value` is a live slice valid for `value.len()` bytes.
        // - The kernel copies from these buffers synchronously and does not retain them.
        let rc = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast::<libc::c_void>(),
                value.len(),
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn get_xattr(file: &fs::File, name: &str) -> std::io::Result<Option<Vec<u8>>> {
        let name = CString::new(name).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "xattr name contained NUL")
        })?;
        // SAFETY:
        // - This is the real `fgetxattr` probe form used by the production code path.
        // - `file.as_raw_fd()` is a live descriptor, `name` is a validated `CString`, and the
        //   null-pointer/zero-length combination is the kernel-defined way to request the needed
        //   buffer size without exposing caller-owned memory.
        let len =
            unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
        if len < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ENODATA) {
                return Ok(None);
            }
            return Err(err);
        }
        let len = usize::try_from(len).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "xattr length overflow")
        })?;
        let mut out = vec![0_u8; len];
        // SAFETY:
        // - `out` is an owned, writable allocation sized from the previously probed length after
        //   overflow checks, so the pointer is valid for `out.len()` bytes.
        // - `name` stays alive for the full call and the kernel does not retain either pointer.
        let read = unsafe {
            libc::fgetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                out.as_mut_ptr().cast::<libc::c_void>(),
                out.len(),
            )
        };
        if read < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let read = usize::try_from(read).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "xattr read length overflow",
            )
        })?;
        out.truncate(read);
        Ok(Some(out))
    }

    fn remove_xattr(file: &fs::File, name: &str) -> std::io::Result<()> {
        let name = CString::new(name).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "xattr name contained NUL")
        })?;
        // SAFETY:
        // - `fremovexattr` is the real fd-scoped removal syscall under test.
        // - `file.as_raw_fd()` is valid for the duration of the call and `name` is a validated
        //   `CString`, so the kernel receives a valid NUL-terminated pointer.
        let rc = unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr()) };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENODATA) {
            return Ok(());
        }
        Err(err)
    }

    fn supports_user_xattrs(file: &fs::File) -> bool {
        const PROBE: &str = "user.omne_fs_probe";
        match set_xattr(file, PROBE, b"1") {
            Ok(()) => {
                let _ = remove_xattr(file, PROBE);
                true
            }
            Err(err) if xattr_not_supported(&err) => false,
            Err(err) => panic!("xattr probe failed: {err}"),
        }
    }

    #[test]
    fn preserve_unix_security_metadata_syncs_and_prunes_xattrs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        fs::write(&src_path, "src").expect("write src");
        fs::write(&dst_path, "dst").expect("write dst");

        let src_file = OpenOptions::new()
            .read(true)
            .open(&src_path)
            .expect("open src");
        let dst_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dst_path)
            .expect("open dst");
        if !supports_user_xattrs(&src_file) || !supports_user_xattrs(&dst_file) {
            return;
        }

        set_xattr(&src_file, "user.omne_fs_keep", b"keep").expect("set src keep");
        set_xattr(&src_file, "user.omne_fs_update", b"new").expect("set src update");
        set_xattr(&dst_file, "user.omne_fs_update", b"old").expect("set dst update");
        set_xattr(&dst_file, "user.omne_fs_remove", b"gone").expect("set dst remove");

        super::preserve_unix_security_metadata(
            &src_file,
            &src_file.metadata().expect("src metadata"),
            &dst_file,
            true,
        )
        .expect("preserve metadata");

        assert_eq!(
            get_xattr(&dst_file, "user.omne_fs_keep").expect("get dst keep"),
            Some(b"keep".to_vec())
        );
        assert_eq!(
            get_xattr(&dst_file, "user.omne_fs_update").expect("get dst update"),
            Some(b"new".to_vec())
        );
        assert_eq!(
            get_xattr(&dst_file, "user.omne_fs_remove").expect("get dst remove"),
            None
        );
    }

    #[test]
    fn preserve_unix_security_metadata_keeps_dst_xattrs_when_copy_disabled() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        fs::write(&src_path, "src").expect("write src");
        fs::write(&dst_path, "dst").expect("write dst");

        let src_file = OpenOptions::new()
            .read(true)
            .open(&src_path)
            .expect("open src");
        let dst_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dst_path)
            .expect("open dst");
        if !supports_user_xattrs(&src_file) || !supports_user_xattrs(&dst_file) {
            return;
        }

        set_xattr(&src_file, "user.omne_fs_src_only", b"src-only").expect("set src xattr");
        set_xattr(&dst_file, "user.omne_fs_dst_only", b"dst-only").expect("set dst xattr");

        super::preserve_unix_security_metadata(
            &src_file,
            &src_file.metadata().expect("src metadata"),
            &dst_file,
            false,
        )
        .expect("preserve metadata");

        assert_eq!(
            get_xattr(&dst_file, "user.omne_fs_src_only").expect("get dst src-only"),
            None
        );
        assert_eq!(
            get_xattr(&dst_file, "user.omne_fs_dst_only").expect("get dst dst-only"),
            Some(b"dst-only".to_vec())
        );
    }

    #[test]
    fn preserve_unix_security_metadata_removes_dst_xattrs_when_src_has_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let src_path = dir.path().join("src.txt");
        let dst_path = dir.path().join("dst.txt");
        fs::write(&src_path, "src").expect("write src");
        fs::write(&dst_path, "dst").expect("write dst");

        let src_file = OpenOptions::new()
            .read(true)
            .open(&src_path)
            .expect("open src");
        let dst_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&dst_path)
            .expect("open dst");
        if !supports_user_xattrs(&src_file) || !supports_user_xattrs(&dst_file) {
            return;
        }

        set_xattr(&dst_file, "user.omne_fs_dst_remove_a", b"a").expect("set dst xattr a");
        set_xattr(&dst_file, "user.omne_fs_dst_remove_b", b"b").expect("set dst xattr b");

        super::preserve_unix_security_metadata(
            &src_file,
            &src_file.metadata().expect("src metadata"),
            &dst_file,
            true,
        )
        .expect("preserve metadata");

        assert_eq!(
            get_xattr(&dst_file, "user.omne_fs_dst_remove_a").expect("get dst xattr a"),
            None
        );
        assert_eq!(
            get_xattr(&dst_file, "user.omne_fs_dst_remove_b").expect("get dst xattr b"),
            None
        );
    }
}
