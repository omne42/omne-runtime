use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct AtomicWriteOptions {
    pub overwrite_existing: bool,
    pub create_parent_directories: bool,
    pub require_non_empty: bool,
    pub require_executable_on_unix: bool,
    pub unix_mode: Option<u32>,
}

impl Default for AtomicWriteOptions {
    fn default() -> Self {
        Self {
            overwrite_existing: true,
            create_parent_directories: true,
            require_non_empty: false,
            require_executable_on_unix: false,
            unix_mode: None,
        }
    }
}

#[derive(Debug)]
pub struct StagedAtomicFile {
    destination: PathBuf,
    options: AtomicWriteOptions,
    staged: tempfile::NamedTempFile,
}

#[derive(Debug)]
pub enum AtomicWriteError {
    IoPath {
        op: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    CommittedButUnsynced {
        op: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    Validation(String),
}

impl AtomicWriteError {
    fn io_path(op: &'static str, path: &Path, source: io::Error) -> Self {
        Self::IoPath {
            op,
            path: path.to_path_buf(),
            source,
        }
    }

    fn committed_but_unsynced(op: &'static str, path: &Path, source: io::Error) -> Self {
        Self::CommittedButUnsynced {
            op,
            path: path.to_path_buf(),
            source,
        }
    }
}

impl fmt::Display for AtomicWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IoPath { op, path, source } => {
                write!(f, "io error during {op} ({}): {source}", path.display())
            }
            Self::CommittedButUnsynced { op, path, source } => write!(
                f,
                "filesystem update committed but parent sync failed during {op} ({}): {source}",
                path.display()
            ),
            Self::Validation(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for AtomicWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoPath { source, .. } | Self::CommittedButUnsynced { source, .. } => Some(source),
            Self::Validation(_) => None,
        }
    }
}

pub fn write_file_atomically(
    bytes: &[u8],
    destination: &Path,
    options: &AtomicWriteOptions,
) -> Result<(), AtomicWriteError> {
    let mut cursor = io::Cursor::new(bytes);
    write_file_atomically_from_reader(&mut cursor, destination, options)
}

pub fn write_file_atomically_from_reader<R>(
    reader: &mut R,
    destination: &Path,
    options: &AtomicWriteOptions,
) -> Result<(), AtomicWriteError>
where
    R: Read + ?Sized,
{
    let mut staged = stage_file_atomically(destination, options)?;
    io::copy(reader, staged.file_mut())
        .map_err(|err| AtomicWriteError::io_path("write", destination, err))?;
    staged.commit()
}

pub fn stage_file_atomically(
    destination: &Path,
    options: &AtomicWriteOptions,
) -> Result<StagedAtomicFile, AtomicWriteError> {
    stage_file_atomically_with_name(destination, options, None)
}

pub fn stage_file_atomically_with_name(
    destination: &Path,
    options: &AtomicWriteOptions,
    staged_file_name: Option<&str>,
) -> Result<StagedAtomicFile, AtomicWriteError> {
    if let Some(parent) = destination.parent()
        && options.create_parent_directories
    {
        fs::create_dir_all(parent)
            .map_err(|err| AtomicWriteError::io_path("create_dir_all", parent, err))?;
    }

    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let file_name = staged_file_name
        .and_then(normalize_staged_file_name)
        .or_else(|| {
            destination
                .file_name()
                .and_then(|value| value.to_str())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "tool".to_string());
    let staged = tempfile::Builder::new()
        .prefix(&format!(".{file_name}.tmp-"))
        .suffix(".tmp")
        .tempfile_in(parent)
        .map_err(|err| AtomicWriteError::io_path("create_temp", destination, err))?;

    Ok(StagedAtomicFile {
        destination: destination.to_path_buf(),
        options: options.clone(),
        staged,
    })
}

fn normalize_staged_file_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = trimmed.replace(['/', '\\'], "_");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

impl StagedAtomicFile {
    pub fn file(&self) -> &fs::File {
        self.staged.as_file()
    }

    pub fn file_mut(&mut self) -> &mut fs::File {
        self.staged.as_file_mut()
    }

    pub fn path(&self) -> &Path {
        self.staged.path()
    }

    pub fn commit(mut self) -> Result<(), AtomicWriteError> {
        self.staged
            .as_file_mut()
            .flush()
            .map_err(|err| AtomicWriteError::io_path("flush", &self.destination, err))?;

        #[cfg(unix)]
        if let Some(mode) = self.options.unix_mode {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(mode);
            self.staged
                .as_file_mut()
                .set_permissions(perms)
                .map_err(|err| {
                    AtomicWriteError::io_path("set_permissions", &self.destination, err)
                })?;
        }

        self.staged
            .as_file_mut()
            .sync_all()
            .map_err(|err| AtomicWriteError::io_path("sync", &self.destination, err))?;

        let staged_path = self.staged.path().to_path_buf();
        validate_staged_file(&staged_path, &self.options)?;

        let persisted = self.staged.into_temp_path();
        commit_replace(
            persisted,
            &self.destination,
            self.options.overwrite_existing,
        )
    }
}

fn validate_staged_file(
    staged_path: &Path,
    options: &AtomicWriteOptions,
) -> Result<(), AtomicWriteError> {
    let metadata = fs::metadata(staged_path)
        .map_err(|err| AtomicWriteError::io_path("metadata", staged_path, err))?;
    if !metadata.is_file() {
        return Err(AtomicWriteError::Validation(format!(
            "staged file `{}` is not a regular file",
            staged_path.display()
        )));
    }
    if options.require_non_empty && metadata.len() == 0 {
        return Err(AtomicWriteError::Validation(format!(
            "staged file `{}` is empty",
            staged_path.display()
        )));
    }
    #[cfg(unix)]
    if options.require_executable_on_unix {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(AtomicWriteError::Validation(format!(
                "staged file `{}` is not executable",
                staged_path.display()
            )));
        }
    }
    Ok(())
}

fn commit_replace(
    staged_path: tempfile::TempPath,
    destination: &Path,
    overwrite_existing: bool,
) -> Result<(), AtomicWriteError> {
    if overwrite_existing {
        staged_path
            .persist(destination)
            .map_err(|err| AtomicWriteError::io_path("persist", destination, err.error))?;
    } else {
        staged_path.persist_noclobber(destination).map_err(|err| {
            AtomicWriteError::io_path("persist_noclobber", destination, err.error)
        })?;
    }
    sync_parent_directory(destination)
        .map_err(|err| AtomicWriteError::committed_but_unsynced("sync_parent", destination, err))
}

#[cfg(all(not(windows), unix))]
fn sync_parent_directory(path: &Path) -> io::Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    let parent_dir = fs::File::open(parent)?;
    parent_dir.sync_all()
}

#[cfg(not(all(not(windows), unix)))]
fn sync_parent_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};

    use super::{
        AtomicWriteError, AtomicWriteOptions, stage_file_atomically,
        stage_file_atomically_with_name, write_file_atomically,
    };

    #[test]
    fn atomic_write_creates_parent_directories_and_writes_content() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("nested/tool");

        let options = AtomicWriteOptions {
            create_parent_directories: true,
            require_non_empty: true,
            ..AtomicWriteOptions::default()
        };
        write_file_atomically(b"tool", &destination, &options).expect("write file");

        let content = std::fs::read(&destination).expect("read destination");
        assert_eq!(content, b"tool");
    }

    #[test]
    fn atomic_write_rejects_empty_file_when_required() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tool");

        let options = AtomicWriteOptions {
            require_non_empty: true,
            ..AtomicWriteOptions::default()
        };
        let err = write_file_atomically(b"", &destination, &options).expect_err("should fail");
        assert!(matches!(err, AtomicWriteError::Validation(_)));
    }

    #[test]
    fn atomic_write_replaces_existing_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tool");
        std::fs::write(&destination, b"old").expect("seed file");

        let options = AtomicWriteOptions {
            overwrite_existing: true,
            require_non_empty: true,
            ..AtomicWriteOptions::default()
        };
        write_file_atomically(b"new", &destination, &options).expect("overwrite file");

        let content = std::fs::read(&destination).expect("read destination");
        assert_eq!(content, b"new");
    }

    #[test]
    fn staged_atomic_file_supports_read_before_commit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tool");

        let options = AtomicWriteOptions {
            require_non_empty: true,
            ..AtomicWriteOptions::default()
        };
        let mut staged = stage_file_atomically(&destination, &options).expect("stage file");
        staged.file_mut().write_all(b"tool").expect("write staged");
        staged
            .file_mut()
            .seek(SeekFrom::Start(0))
            .expect("rewind staged");
        let mut content = String::new();
        staged
            .file_mut()
            .read_to_string(&mut content)
            .expect("read staged");
        assert_eq!(content, "tool");
        staged.commit().expect("commit staged");

        let written = std::fs::read_to_string(&destination).expect("read destination");
        assert_eq!(written, "tool");
    }

    #[test]
    fn staged_atomic_file_uses_custom_temp_file_name_when_provided() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tool");
        let options = AtomicWriteOptions::default();
        let staged = stage_file_atomically_with_name(
            &destination,
            &options,
            Some("gh_9.9.9_linux_amd64.tar.gz"),
        )
        .expect("stage file");

        let name = staged
            .path()
            .file_name()
            .and_then(|value| value.to_str())
            .expect("temp file name");
        assert!(name.starts_with(".gh_9.9.9_linux_amd64.tar.gz.tmp-"));
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_sets_executable_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tool");

        let options = AtomicWriteOptions {
            unix_mode: Some(0o755),
            require_non_empty: true,
            require_executable_on_unix: true,
            ..AtomicWriteOptions::default()
        };
        write_file_atomically(b"#!/bin/sh\necho hi\n", &destination, &options).expect("write file");

        let mode = std::fs::metadata(&destination)
            .expect("metadata")
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0);
    }
}
