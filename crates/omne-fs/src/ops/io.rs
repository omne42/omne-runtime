use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::{Error, Result};
pub(super) use crate::platform::rename::RenameReplaceError;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct FileIdentity(same_file::Handle);

#[derive(Debug)]
pub(super) struct PathIdentity(fs::Metadata);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MetadataIdentityCheck {
    Verified,
    Unverifiable,
}

#[derive(Debug)]
pub(super) struct DirectoryIdentity {
    metadata: PathIdentity,
    handle: Option<same_file::Handle>,
    #[cfg(test)]
    force_unverifiable: bool,
}

impl PathIdentity {
    pub(super) fn capture(path: &Path, relative: &Path) -> Result<Self> {
        let meta = fs::symlink_metadata(path)
            .map_err(|err| Error::io_path("symlink_metadata", relative, err))?;
        Ok(Self(meta))
    }

    pub(super) fn from_metadata(meta: fs::Metadata) -> Self {
        Self(meta)
    }

    pub(super) fn metadata(&self) -> &fs::Metadata {
        &self.0
    }

    pub(super) fn matches_metadata(&self, current_meta: &fs::Metadata) -> Option<bool> {
        metadata_same_file(&self.0, current_meta)
    }

    pub(super) fn verify_metadata<F>(
        &self,
        current_meta: &fs::Metadata,
        changed_error: F,
    ) -> Result<MetadataIdentityCheck>
    where
        F: Fn() -> Error,
    {
        match self.matches_metadata(current_meta) {
            Some(true) => Ok(MetadataIdentityCheck::Verified),
            Some(false) => Err(changed_error()),
            None => Ok(MetadataIdentityCheck::Unverifiable),
        }
    }
}

impl DirectoryIdentity {
    pub(super) fn capture<F>(path: &Path, relative: &Path, not_dir_error: F) -> Result<Self>
    where
        F: FnOnce() -> Error,
    {
        let meta = fs::symlink_metadata(path)
            .map_err(|err| Error::io_path("symlink_metadata", relative, err))?;
        Self::from_metadata(path, meta, not_dir_error)
    }

    pub(super) fn from_metadata<F>(
        path: &Path,
        meta: fs::Metadata,
        not_dir_error: F,
    ) -> Result<Self>
    where
        F: FnOnce() -> Error,
    {
        if meta.file_type().is_symlink() || !meta.is_dir() {
            return Err(not_dir_error());
        }
        Ok(Self {
            metadata: PathIdentity::from_metadata(meta),
            handle: same_file::Handle::from_path(path).ok(),
            #[cfg(test)]
            force_unverifiable: false,
        })
    }

    pub(super) fn metadata(&self) -> &fs::Metadata {
        self.metadata.metadata()
    }

    pub(super) fn verify_metadata<F>(
        &self,
        current_meta: &fs::Metadata,
        changed_error: F,
    ) -> Result<MetadataIdentityCheck>
    where
        F: Fn() -> Error,
    {
        #[cfg(test)]
        if self.force_unverifiable {
            return Ok(MetadataIdentityCheck::Unverifiable);
        }
        if current_meta.file_type().is_symlink() || !current_meta.is_dir() {
            return Err(changed_error());
        }
        self.metadata.verify_metadata(current_meta, changed_error)
    }

    pub(super) fn verify<F>(
        &self,
        path: &Path,
        relative: &Path,
        changed_error: F,
    ) -> Result<MetadataIdentityCheck>
    where
        F: Fn() -> Error,
    {
        #[cfg(test)]
        if self.force_unverifiable {
            return Ok(MetadataIdentityCheck::Unverifiable);
        }
        let current_meta = fs::symlink_metadata(path)
            .map_err(|err| Error::io_path("symlink_metadata", relative, err))?;
        if current_meta.file_type().is_symlink() || !current_meta.is_dir() {
            return Err(changed_error());
        }
        if let Some(expected_handle) = self.handle.as_ref() {
            match same_file::Handle::from_path(path) {
                Ok(current_handle) if current_handle == *expected_handle => {
                    return Ok(MetadataIdentityCheck::Verified);
                }
                Ok(_) => return Err(changed_error()),
                Err(_) => {}
            }
        }
        self.verify_metadata(&current_meta, changed_error)
    }

    pub(super) fn verify_best_effort<F>(
        &self,
        path: &Path,
        relative: &Path,
        changed_error: F,
    ) -> Result<()>
    where
        F: Fn() -> Error,
    {
        match self.verify(path, relative, changed_error)? {
            MetadataIdentityCheck::Verified | MetadataIdentityCheck::Unverifiable => Ok(()),
        }
    }

    pub(super) fn ensure_verified<F, G>(
        &self,
        path: &Path,
        relative: &Path,
        changed_error: F,
        unverifiable_error: G,
    ) -> Result<()>
    where
        F: Fn() -> Error,
        G: FnOnce() -> Error,
    {
        match self.verify(path, relative, changed_error)? {
            MetadataIdentityCheck::Verified => Ok(()),
            MetadataIdentityCheck::Unverifiable => Err(unverifiable_error()),
        }
    }

    #[cfg(test)]
    pub(super) fn unverifiable_for_tests(meta: fs::Metadata) -> Self {
        Self {
            metadata: PathIdentity::from_metadata(meta),
            handle: None,
            force_unverifiable: true,
        }
    }
}

impl FileIdentity {
    fn from_file(file: &fs::File) -> Option<Self> {
        let cloned = file.try_clone().ok()?;
        let handle = same_file::Handle::from_file(cloned).ok()?;
        Some(Self(handle))
    }

    pub(super) fn from_path(path: &Path) -> Option<Self> {
        same_file::Handle::from_path(path).ok().map(Self)
    }
}

#[cfg(unix)]
pub(super) fn metadata_same_file(a: &fs::Metadata, b: &fs::Metadata) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    Some(a.dev() == b.dev() && a.ino() == b.ino())
}

#[cfg(windows)]
pub(super) fn metadata_same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> Option<bool> {
    None
}

#[cfg(not(any(unix, windows)))]
pub(super) fn metadata_same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> Option<bool> {
    None
}

pub(super) fn open_regular_file_for_read(
    path: &Path,
    relative: &Path,
) -> Result<(fs::File, fs::Metadata)> {
    let (file, meta) = omne_fs_primitives::open_regular_readonly_nofollow(path)
        .map_err(|err| map_regular_open_error("open", path, relative, err))?;
    reject_symlink_metadata(&meta, relative)?;
    Ok((file, meta))
}

fn open_regular_file_for_write(path: &Path, relative: &Path) -> Result<(fs::File, fs::Metadata)> {
    let (file, meta) = omne_fs_primitives::open_regular_writeonly_nofollow(path)
        .map_err(|err| map_regular_open_error("open_for_write", path, relative, err))?;
    reject_symlink_metadata(&meta, relative)?;
    Ok((file, meta))
}

pub(super) fn ensure_regular_file_writable(path: &Path, relative: &Path) -> Result<fs::Metadata> {
    open_regular_file_for_write(path, relative).map(|(_file, meta)| meta)
}

#[cfg(windows)]
fn reject_symlink_metadata(meta: &fs::Metadata, relative: &Path) -> Result<()> {
    if meta.file_type().is_symlink() {
        return Err(Error::InvalidPath(format!(
            "path {} is a symlink",
            relative.display()
        )));
    }
    Ok(())
}

#[cfg(not(windows))]
fn reject_symlink_metadata(_meta: &fs::Metadata, _relative: &Path) -> Result<()> {
    Ok(())
}

fn map_regular_open_error(
    op: &'static str,
    path: &Path,
    relative: &Path,
    err: std::io::Error,
) -> Error {
    if omne_fs_primitives::is_symlink_or_reparse_open_error(&err) {
        return Error::InvalidPath(format!("path {} is a symlink", relative.display()));
    }

    if err.kind() == std::io::ErrorKind::InvalidInput
        && let Ok(metadata) = fs::symlink_metadata(path)
    {
        if metadata.file_type().is_symlink() {
            return Error::InvalidPath(format!("path {} is a symlink", relative.display()));
        }
        if !metadata.is_file() {
            return Error::InvalidPath(format!(
                "path {} is not a regular file",
                relative.display()
            ));
        }
    }

    Error::io_path(op, relative, err)
}

fn verify_expected_identity(
    relative: &Path,
    expected_identity: Option<&FileIdentity>,
    actual_identity: Option<FileIdentity>,
) -> Result<()> {
    match (expected_identity, actual_identity) {
        (Some(expected), Some(actual)) if *expected != actual => Err(Error::InvalidPath(format!(
            "path {} changed during operation",
            relative.display()
        ))),
        (Some(_), None) => Err(Error::InvalidPath(format!(
            "cannot verify identity for path {} on this platform",
            relative.display()
        ))),
        _ => Ok(()),
    }
}

pub(super) struct StagedTempFile {
    file: fs::File,
    path: tempfile::TempPath,
}

impl StagedTempFile {
    pub(super) fn new(parent: &Path, relative: &Path) -> Result<Self> {
        let tmp_file = tempfile::Builder::new()
            .prefix(".omne-fs.")
            .suffix(".tmp")
            .tempfile_in(parent)
            .map_err(|err| Error::io_path("create_temp", relative, err))?;
        let (file, path) = tmp_file.into_parts();
        Ok(Self { file, path })
    }

    pub(super) fn as_file(&self) -> &fs::File {
        &self.file
    }

    pub(super) fn as_file_mut(&mut self) -> &mut fs::File {
        &mut self.file
    }

    pub(super) fn path(&self) -> &Path {
        self.path.as_ref()
    }

    pub(super) fn write_all(&mut self, relative: &Path, bytes: &[u8]) -> Result<()> {
        self.file
            .write_all(bytes)
            .map_err(|err| Error::io_path("write", relative, err))
    }

    pub(super) fn set_permissions(&self, relative: &Path, perms: fs::Permissions) -> Result<()> {
        self.file
            .set_permissions(perms)
            .map_err(|err| Error::io_path("set_permissions", relative, err))
    }

    pub(super) fn sync_all(&mut self, relative: &Path) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|err| Error::io_path("sync", relative, err))
    }

    pub(super) fn commit_replace<F>(
        self,
        destination: &Path,
        overwrite: bool,
        map_rename_error: F,
    ) -> Result<()>
    where
        F: FnOnce(RenameReplaceError) -> Error,
    {
        let Self { file, path } = self;
        drop(file);
        rename_replace(path.as_ref(), destination, overwrite).map_err(map_rename_error)
    }
}

pub(super) fn file_matches_path(file: &fs::File, path: &Path) -> Option<bool> {
    let expected = FileIdentity::from_file(file)?;
    let actual = FileIdentity::from_path(path)?;
    Some(expected == actual)
}

#[cfg(all(test, unix))]
pub(super) fn open_private_temp_file(path: &Path) -> std::io::Result<fs::File> {
    let mut open_options = fs::OpenOptions::new();
    open_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open_options.mode(0o600);
    }
    open_options.open(path)
}

pub(super) fn read_bytes_limited(path: &Path, relative: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let (file, meta) = open_regular_file_for_read(path, relative)?;
    read_open_file_limited(file, relative, max_bytes, meta.len())
}

pub(super) fn read_string_limited_with_identity(
    path: &Path,
    relative: &Path,
    max_bytes: u64,
) -> Result<(String, FileIdentity)> {
    let (file, meta) = open_regular_file_for_read(path, relative)?;
    let identity = FileIdentity::from_file(&file).ok_or_else(|| {
        Error::InvalidPath(format!(
            "cannot verify identity for path {} on this platform",
            relative.display()
        ))
    })?;
    let bytes = read_open_file_limited(file, relative, max_bytes, meta.len())?;
    decode_utf8(relative, bytes).map(|text| (text, identity))
}

fn decode_utf8(relative: &Path, bytes: Vec<u8>) -> Result<String> {
    String::from_utf8(bytes).map_err(|err| Error::invalid_utf8(relative.to_path_buf(), err))
}

#[cfg(windows)]
pub(super) fn is_destination_exists_rename_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::AlreadyExists || matches!(err.raw_os_error(), Some(80 | 183))
}

#[cfg(not(windows))]
pub(super) fn is_destination_exists_rename_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::AlreadyExists
}

fn file_too_large(relative: &Path, size_bytes: u64, max_bytes: u64) -> Error {
    Error::FileTooLarge {
        path: relative.to_path_buf(),
        size_bytes,
        max_bytes,
    }
}

fn read_open_file_limited(
    file: fs::File,
    relative: &Path,
    max_bytes: u64,
    known_size: u64,
) -> Result<Vec<u8>> {
    if known_size > max_bytes {
        return Err(file_too_large(relative, known_size, max_bytes));
    }

    let mut file = file;
    let initial_capacity = usize::try_from(known_size.min(max_bytes)).unwrap_or(0);
    let (bytes, truncated) = omne_fs_primitives::read_to_end_limited_with_capacity(
        &mut file,
        usize::try_from(max_bytes).unwrap_or(usize::MAX),
        initial_capacity,
    )
    .map_err(|err| Error::io_path("read", relative, err))?;
    if truncated {
        let read_size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        return Err(file_too_large(relative, read_size, max_bytes));
    }
    Ok(bytes)
}

pub(super) fn write_bytes_atomic_checked(
    path: &Path,
    relative: &Path,
    bytes: &[u8],
    expected_identity: FileIdentity,
    preserve_unix_xattrs: bool,
) -> Result<()> {
    write_bytes_atomic_impl(
        path,
        relative,
        bytes,
        Some(expected_identity),
        true,
        preserve_unix_xattrs,
    )
}

fn write_bytes_atomic_impl(
    path: &Path,
    relative: &Path,
    bytes: &[u8],
    expected_identity: Option<FileIdentity>,
    recheck_before_commit: bool,
    preserve_unix_xattrs: bool,
) -> Result<()> {
    // Preserve prior behavior: fail if the original file isn't writable.
    let (existing_file, meta) = open_regular_file_for_write(path, relative)?;
    #[cfg(not(unix))]
    let _ = &existing_file;
    #[cfg(not(unix))]
    let _ = preserve_unix_xattrs;
    verify_expected_identity(
        relative,
        expected_identity.as_ref(),
        FileIdentity::from_file(&existing_file),
    )?;

    // Keep existing mode/readonly permissions, then preserve Unix security metadata.
    let perms = meta.permissions();

    let parent = path.parent().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid path {}: missing parent directory",
            relative.display()
        ))
    })?;
    let _ = path.file_name().ok_or_else(|| {
        Error::InvalidPath(format!(
            "invalid path {}: missing file name",
            relative.display()
        ))
    })?;

    let mut tmp_file = StagedTempFile::new(parent, relative)?;

    tmp_file.write_all(relative, bytes)?;

    tmp_file.set_permissions(relative, perms)?;
    #[cfg(unix)]
    crate::platform::unix_metadata::preserve_unix_security_metadata(
        &existing_file,
        &meta,
        tmp_file.as_file(),
        preserve_unix_xattrs,
    )
    .map_err(|err| Error::io_path("preserve_metadata", relative, err))?;
    // A single post-write/post-metadata sync is enough before the atomic replace.
    tmp_file.sync_all(relative)?;

    if recheck_before_commit {
        // Best-effort conflict detection: re-open with no-follow and re-check identity
        // right before commit to narrow the TOCTOU window between read and replace.
        let (recheck_file, _recheck_meta) = open_regular_file_for_write(path, relative)?;
        verify_expected_identity(
            relative,
            expected_identity.as_ref(),
            FileIdentity::from_file(&recheck_file),
        )?;
        drop(recheck_file);
    }

    // The expected identity may itself own an open file handle on Windows.
    // Release it before the final replace operation.
    drop(expected_identity);

    // Windows replacement APIs reject replacing a destination that this process still has open.
    // Close the original handle after we've copied metadata and finished identity checks.
    drop(existing_file);

    match file_matches_path(tmp_file.as_file(), tmp_file.path()) {
        Some(true) => {}
        Some(false) => {
            return Err(Error::InvalidPath(format!(
                "temporary file changed during replace for path {}",
                relative.display()
            )));
        }
        None => {
            return Err(Error::InvalidPath(format!(
                "cannot verify temporary file identity for path {} on this platform",
                relative.display()
            )));
        }
    }

    tmp_file.commit_replace(path, true, |err| match err {
        RenameReplaceError::Io(err) => Error::io_path("replace_file", relative, err),
        RenameReplaceError::CommittedButUnsynced(err) => {
            Error::committed_but_unsynced("replace_file", relative, err)
        }
    })?;

    Ok(())
}

pub(super) fn rename_replace(
    src_path: &Path,
    dest_path: &Path,
    replace_existing: bool,
) -> std::result::Result<(), RenameReplaceError> {
    crate::platform::rename::rename_replace(src_path, dest_path, replace_existing)
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn ensure_verified_rejects_unverifiable_directory_identity() {
        use std::fs;
        use std::path::Path;

        use crate::error::Error;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("created");
        fs::create_dir(&target).expect("create target dir");
        let metadata = fs::symlink_metadata(&target).expect("target metadata");
        let identity = super::DirectoryIdentity::unverifiable_for_tests(metadata);

        let err = identity
            .ensure_verified(
                &target,
                Path::new("created"),
                || Error::InvalidPath("changed".to_string()),
                || Error::InvalidPath("unverifiable".to_string()),
            )
            .expect_err("unverifiable identity must fail closed");

        match err {
            Error::InvalidPath(message) => assert!(message.contains("unverifiable")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
