use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
#[cfg(target_os = "macos")]
use std::path::Component;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::OpenOptions;

use crate::cap_root::open_parent_root_for_leaf_path;
use crate::{
    Dir, MissingRootPolicy, RootDir, create_directory_component, open_directory_component,
};

static STAGED_ENTRY_COUNTER: AtomicU64 = AtomicU64::new(0);

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

#[derive(Debug, Clone)]
pub struct AtomicDirectoryOptions {
    pub overwrite_existing: bool,
    pub create_parent_directories: bool,
}

impl Default for AtomicDirectoryOptions {
    fn default() -> Self {
        Self {
            overwrite_existing: true,
            create_parent_directories: true,
        }
    }
}

#[derive(Debug)]
pub struct StagedAtomicFile {
    destination: PathBuf,
    destination_leaf: PathBuf,
    options: AtomicWriteOptions,
    parent_root: RootDir,
    staged_leaf: PathBuf,
    staged_path: PathBuf,
    staged: Option<fs::File>,
}

#[derive(Debug)]
pub struct StagedAtomicDirectory {
    destination: PathBuf,
    destination_leaf: PathBuf,
    options: AtomicDirectoryOptions,
    parent_root: RootDir,
    staged_leaf: PathBuf,
    staged_path: PathBuf,
    staged_root: Option<RootDir>,
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

#[derive(Debug)]
pub enum AtomicDirectoryError {
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
    CommittedButCleanupFailed {
        op: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    RollbackFailed {
        op: &'static str,
        path: PathBuf,
        backup_path: PathBuf,
        source: io::Error,
        staged_cleanup_path: Option<PathBuf>,
        staged_cleanup_source: Option<io::Error>,
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

impl AtomicDirectoryError {
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

    fn committed_but_cleanup_failed(op: &'static str, path: &Path, source: io::Error) -> Self {
        Self::CommittedButCleanupFailed {
            op,
            path: path.to_path_buf(),
            source,
        }
    }

    fn rollback_failed(
        op: &'static str,
        path: &Path,
        backup_path: PathBuf,
        source: io::Error,
        staged_cleanup_path: Option<PathBuf>,
        staged_cleanup_source: Option<io::Error>,
    ) -> Self {
        Self::RollbackFailed {
            op,
            path: path.to_path_buf(),
            backup_path,
            source,
            staged_cleanup_path,
            staged_cleanup_source,
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

impl fmt::Display for AtomicDirectoryError {
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
            Self::CommittedButCleanupFailed { op, path, source } => write!(
                f,
                "filesystem update committed but cleanup failed during {op} ({}): {source}",
                path.display()
            ),
            Self::RollbackFailed {
                op,
                path,
                backup_path,
                source,
                staged_cleanup_path,
                staged_cleanup_source,
            } => {
                write!(
                    f,
                    "atomic directory replace failed during {op} ({}); original directory remains recoverable at {}: {source}",
                    path.display(),
                    backup_path.display()
                )?;
                if let (Some(cleanup_path), Some(cleanup_source)) =
                    (staged_cleanup_path, staged_cleanup_source)
                {
                    write!(
                        f,
                        "; cleanup staged directory `{}` failed: {cleanup_source}",
                        cleanup_path.display()
                    )?;
                }
                Ok(())
            }
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

impl std::error::Error for AtomicDirectoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoPath { source, .. }
            | Self::CommittedButUnsynced { source, .. }
            | Self::CommittedButCleanupFailed { source, .. }
            | Self::RollbackFailed { source, .. } => Some(source),
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
    let (parent_root, destination_leaf) =
        prepare_atomic_destination_parent(destination, options.create_parent_directories)
            .map_err(|err| AtomicWriteError::io_path("prepare_parent", destination, err))?;
    let file_name = staged_file_name
        .and_then(normalize_staged_file_name)
        .or_else(|| {
            destination
                .file_name()
                .and_then(|value| value.to_str())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "tool".to_string());
    let prefix = format!(".{file_name}.tmp-");
    let (staged_leaf, staged) = create_staged_file_in_root(&parent_root, &prefix, ".tmp")
        .map_err(|err| AtomicWriteError::io_path("create_temp", destination, err))?;
    let staged_path = parent_root.path().join(&staged_leaf);

    Ok(StagedAtomicFile {
        destination: destination.to_path_buf(),
        destination_leaf,
        options: options.clone(),
        parent_root,
        staged_leaf,
        staged_path,
        staged: Some(staged),
    })
}

pub fn stage_directory_atomically(
    destination: &Path,
    options: &AtomicDirectoryOptions,
) -> Result<StagedAtomicDirectory, AtomicDirectoryError> {
    let (parent_root, destination_leaf) =
        prepare_atomic_destination_parent(destination, options.create_parent_directories)
            .map_err(|err| AtomicDirectoryError::io_path("prepare_parent", destination, err))?;
    let file_name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .map(ToString::to_string)
        .unwrap_or_else(|| "tree".to_string());
    let prefix = format!(".{file_name}.tmpdir-");
    let (staged_leaf, staged_root) = create_staged_directory_in_root(&parent_root, &prefix)
        .map_err(|err| AtomicDirectoryError::io_path("create_tempdir", destination, err))?;
    let staged_path = parent_root.path().join(&staged_leaf);

    Ok(StagedAtomicDirectory {
        destination: destination.to_path_buf(),
        destination_leaf,
        options: options.clone(),
        parent_root,
        staged_leaf,
        staged_path,
        staged_root: Some(staged_root),
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

fn prepare_atomic_destination_parent(
    destination: &Path,
    create_parent_directories: bool,
) -> io::Result<(RootDir, PathBuf)> {
    let policy = if create_parent_directories {
        MissingRootPolicy::Create
    } else {
        MissingRootPolicy::Error
    };
    let normalized_destination = normalize_platform_root_alias(destination)?;
    let (parent_root, destination_leaf, _) = open_parent_root_for_leaf_path(
        &normalized_destination,
        "atomic write destination",
        policy,
    )?
    .ok_or_else(|| io::Error::other("missing atomic write parent"))?;
    Ok((parent_root, PathBuf::from(destination_leaf)))
}

fn create_staged_file_in_root(
    parent_root: &RootDir,
    prefix: &str,
    suffix: &str,
) -> io::Result<(PathBuf, fs::File)> {
    for _ in 0..128 {
        let staged_leaf = PathBuf::from(next_staged_entry_name(prefix, suffix));
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        options.follow(FollowSymlinks::No);
        match parent_root
            .dir()
            .open_with(&staged_leaf, &options)
            .map(|file| file.into_std())
        {
            Ok(file) => return Ok((staged_leaf, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate unique staged file name",
    ))
}

fn create_staged_directory_in_root(
    parent_root: &RootDir,
    prefix: &str,
) -> io::Result<(PathBuf, RootDir)> {
    for _ in 0..128 {
        let staged_leaf = PathBuf::from(next_staged_entry_name(prefix, ""));
        match create_directory_component(parent_root.dir(), &staged_leaf) {
            Ok(()) => {
                let staged_dir = open_directory_component(parent_root.dir(), &staged_leaf)?;
                return Ok((
                    staged_leaf.clone(),
                    RootDir::from_parts(parent_root.path().join(&staged_leaf), staged_dir),
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to allocate unique staged directory name",
    ))
}

fn next_staged_entry_name(prefix: &str, suffix: &str) -> String {
    let sequence = STAGED_ENTRY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "{prefix}{pid:x}-{timestamp:x}-{sequence:x}{suffix}",
        pid = std::process::id()
    )
}

impl Drop for StagedAtomicFile {
    fn drop(&mut self) {
        let _ = self.staged.take();
        let _ = self.parent_root.dir().remove_file(&self.staged_leaf);
    }
}

impl Drop for StagedAtomicDirectory {
    fn drop(&mut self) {
        let _ = self.staged_root.take();
        let _ = self.parent_root.dir().remove_dir_all(&self.staged_leaf);
    }
}

fn missing_staged_file_error(staged_path: &Path) -> AtomicWriteError {
    AtomicWriteError::Validation(format!(
        "staged file `{}` is no longer available",
        staged_path.display()
    ))
}

fn missing_staged_directory_error(staged_path: &Path) -> AtomicDirectoryError {
    AtomicDirectoryError::Validation(format!(
        "staged directory `{}` is no longer available",
        staged_path.display()
    ))
}

fn normalize_platform_root_alias(path: &Path) -> io::Result<PathBuf> {
    #[cfg(not(target_os = "macos"))]
    {
        Ok(path.to_path_buf())
    }

    #[cfg(target_os = "macos")]
    {
        normalize_macos_root_alias(path)
    }
}

#[cfg(target_os = "macos")]
fn normalize_macos_root_alias(path: &Path) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    let mut visited = PathBuf::new();
    let mut normal_index = 0usize;
    let mut components = path.components().peekable();

    while let Some(component) = components.next() {
        visited.push(component.as_os_str());
        if !matches!(component, std::path::Component::Normal(_)) {
            continue;
        }

        match fs::symlink_metadata(&visited) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    && normal_index == 0
                    && is_macos_root_alias_component(component) =>
            {
                let mut canonical = fs::canonicalize(&visited)?;
                for remainder in components {
                    canonical.push(remainder.as_os_str());
                }
                return Ok(canonical);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(path.to_path_buf()),
            Err(error) => return Err(error),
        }

        normal_index += 1;
    }

    Ok(path.to_path_buf())
}

#[cfg(target_os = "macos")]
fn is_macos_root_alias_component(component: Component<'_>) -> bool {
    matches!(
        component,
        Component::Normal(part) if part == "var" || part == "tmp"
    )
}

impl StagedAtomicFile {
    pub fn file_mut(&mut self) -> &mut fs::File {
        self.staged.as_mut().expect("staged file missing")
    }

    pub fn staged_path(&self) -> &Path {
        &self.staged_path
    }

    pub fn commit(mut self) -> Result<(), AtomicWriteError> {
        let staged = self
            .staged
            .as_mut()
            .ok_or_else(|| missing_staged_file_error(&self.staged_path))?;
        staged
            .flush()
            .map_err(|err| AtomicWriteError::io_path("flush", &self.destination, err))?;

        #[cfg(unix)]
        if let Some(mode) = self.options.unix_mode {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(mode);
            staged.set_permissions(perms).map_err(|err| {
                AtomicWriteError::io_path("set_permissions", &self.destination, err)
            })?;
        }

        staged
            .sync_all()
            .map_err(|err| AtomicWriteError::io_path("sync", &self.destination, err))?;

        validate_staged_file(staged, &self.staged_path, &self.options)?;
        let _ = self.staged.take();

        commit_replace(
            &self.parent_root,
            &self.staged_leaf,
            &self.destination_leaf,
            &self.destination,
            self.options.overwrite_existing,
        )
    }
}

impl StagedAtomicDirectory {
    pub fn path(&self) -> &Path {
        &self.staged_path
    }

    pub fn try_clone_dir(&self) -> io::Result<Dir> {
        self.staged_root
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "staged directory `{}` is no longer available",
                        self.staged_path.display()
                    ),
                )
            })?
            .dir()
            .try_clone()
    }

    pub fn commit(mut self) -> Result<(), AtomicDirectoryError> {
        let staged_root = self
            .staged_root
            .as_ref()
            .ok_or_else(|| missing_staged_directory_error(&self.staged_path))?;
        validate_staged_directory(staged_root.dir(), &self.staged_path)?;
        sync_directory_tree(staged_root.dir(), &self.staged_path)?;
        let _ = self.staged_root.take();
        commit_replace_directory(
            &self.parent_root,
            &self.staged_leaf,
            &self.destination_leaf,
            &self.destination,
            &self.options,
        )
    }
}

fn validate_staged_file(
    staged_file: &fs::File,
    staged_path: &Path,
    options: &AtomicWriteOptions,
) -> Result<(), AtomicWriteError> {
    let metadata = staged_file
        .metadata()
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

fn validate_staged_directory(
    staged_root: &Dir,
    staged_path: &Path,
) -> Result<(), AtomicDirectoryError> {
    let metadata = staged_root
        .dir_metadata()
        .map_err(|err| AtomicDirectoryError::io_path("metadata", staged_path, err))?;
    if metadata.is_dir() {
        return Ok(());
    }
    Err(AtomicDirectoryError::Validation(format!(
        "staged directory `{}` is not a directory",
        staged_path.display()
    )))
}

#[cfg(all(not(windows), unix))]
fn sync_directory_tree(directory: &Dir, path: &Path) -> Result<(), AtomicDirectoryError> {
    for entry in directory
        .entries()
        .map_err(|err| AtomicDirectoryError::io_path("read_dir", path, err))?
    {
        let entry = entry.map_err(|err| AtomicDirectoryError::io_path("read_dir", path, err))?;
        let entry_name = entry.file_name();
        let entry_path = path.join(&entry_name);
        let file_type = entry
            .file_type()
            .map_err(|err| AtomicDirectoryError::io_path("file_type", &entry_path, err))?;

        if file_type.is_dir() {
            let child = entry
                .open_dir()
                .map_err(|err| AtomicDirectoryError::io_path("open_dir", &entry_path, err))?;
            sync_directory_tree(&child, &entry_path)?;
            continue;
        }

        if file_type.is_file() {
            let file = entry
                .open()
                .map_err(|err| AtomicDirectoryError::io_path("open", &entry_path, err))?;
            sync_regular_file_handle(&file)
                .map_err(|err| AtomicDirectoryError::io_path("sync", &entry_path, err))?;
            continue;
        }

        if file_type.is_symlink() {
            continue;
        }

        return Err(AtomicDirectoryError::Validation(format!(
            "staged directory `{}` contains unsupported entry `{}`",
            path.display(),
            entry_path.display()
        )));
    }

    sync_dir_handle(directory).map_err(|err| AtomicDirectoryError::io_path("sync", path, err))
}

#[cfg(all(not(windows), unix))]
fn sync_regular_file_handle(file: &cap_std::fs::File) -> io::Result<()> {
    file.sync_all()
}

#[cfg(not(all(not(windows), unix)))]
fn sync_directory_tree(_directory: &Dir, _path: &Path) -> Result<(), AtomicDirectoryError> {
    Ok(())
}

fn commit_replace(
    parent_root: &RootDir,
    staged_leaf: &Path,
    destination_leaf: &Path,
    destination: &Path,
    overwrite_existing: bool,
) -> Result<(), AtomicWriteError> {
    if overwrite_existing {
        parent_root
            .dir()
            .rename(staged_leaf, parent_root.dir(), destination_leaf)
            .map_err(|err| AtomicWriteError::io_path("rename", destination, err))?;
    } else {
        if parent_root.dir().symlink_metadata(destination_leaf).is_ok() {
            return Err(AtomicWriteError::io_path(
                "rename_noclobber",
                destination,
                io::Error::new(io::ErrorKind::AlreadyExists, "destination already exists"),
            ));
        }
        parent_root
            .dir()
            .rename(staged_leaf, parent_root.dir(), destination_leaf)
            .map_err(|err| AtomicWriteError::io_path("rename_noclobber", destination, err))?;
    }
    sync_root_directory(parent_root)
        .map_err(|err| AtomicWriteError::committed_but_unsynced("sync_parent", destination, err))
}

fn commit_replace_directory(
    parent_root: &RootDir,
    staged_leaf: &Path,
    destination_leaf: &Path,
    destination: &Path,
    options: &AtomicDirectoryOptions,
) -> Result<(), AtomicDirectoryError> {
    commit_replace_directory_with_cleanup_hooks(
        parent_root,
        staged_leaf,
        destination_leaf,
        destination,
        options,
        create_backup_directory_in_root,
        move_existing_directory_to_backup,
        remove_backup_root,
        remove_staged_directory,
    )
}

#[allow(clippy::too_many_arguments)]
fn commit_replace_directory_with_cleanup_hooks<
    CreateBackupDir,
    MoveExistingToBackup,
    BackupRootCleanup,
    StagedCleanup,
>(
    parent_root: &RootDir,
    staged_leaf: &Path,
    destination_leaf: &Path,
    destination: &Path,
    options: &AtomicDirectoryOptions,
    create_backup_dir: CreateBackupDir,
    move_existing_to_backup: MoveExistingToBackup,
    backup_root_cleanup: BackupRootCleanup,
    staged_cleanup: StagedCleanup,
) -> Result<(), AtomicDirectoryError>
where
    CreateBackupDir: Fn(&RootDir) -> io::Result<RootDir>,
    MoveExistingToBackup: Fn(&RootDir, &Path, &RootDir) -> io::Result<()>,
    BackupRootCleanup: Fn(RootDir) -> io::Result<()>,
    StagedCleanup: Fn(&RootDir, &Path) -> io::Result<()>,
{
    let mut backup_root = None;

    if options.overwrite_existing {
        let destination_metadata = match parent_root.dir().symlink_metadata(destination_leaf) {
            Ok(metadata) => Some(metadata),
            Err(err) if err.kind() == io::ErrorKind::NotFound => None,
            Err(err) => {
                let _ = staged_cleanup(parent_root, staged_leaf);
                return Err(AtomicDirectoryError::io_path(
                    "symlink_metadata",
                    destination,
                    err,
                ));
            }
        };

        if let Some(metadata) = destination_metadata {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                let _ = staged_cleanup(parent_root, staged_leaf);
                return Err(AtomicDirectoryError::Validation(format!(
                    "directory destination `{}` must be an existing directory or absent",
                    destination.display()
                )));
            }
            let holder = create_backup_dir(parent_root).map_err(|err| {
                let _ = staged_cleanup(parent_root, staged_leaf);
                AtomicDirectoryError::io_path("create_backup_dir", destination, err)
            })?;
            if let Err(err) = move_existing_to_backup(parent_root, destination_leaf, &holder) {
                let _ = staged_cleanup(parent_root, staged_leaf);
                let _ = backup_root_cleanup(holder);
                return Err(AtomicDirectoryError::io_path(
                    "rename_existing",
                    destination,
                    err,
                ));
            }
            backup_root = Some(holder);
        }
    }

    if let Err(err) = parent_root
        .dir()
        .rename(staged_leaf, parent_root.dir(), destination_leaf)
    {
        let staged_cleanup_path = parent_root.path().join(staged_leaf);
        let staged_cleanup_error = staged_cleanup(parent_root, staged_leaf).err();
        let restore_outcome = match backup_root.as_ref() {
            Some(holder) => {
                let backup_path = holder.path().join("previous");
                let restore_error = holder
                    .dir()
                    .rename(Path::new("previous"), parent_root.dir(), destination_leaf)
                    .err();
                Some((backup_path, restore_error))
            }
            None => None,
        };
        let mut error = AtomicDirectoryError::io_path("rename_staged", destination, err);
        if let Some((backup_path, Some(restore_error))) = restore_outcome {
            return Err(AtomicDirectoryError::rollback_failed(
                "restore_existing",
                destination,
                backup_path,
                restore_error,
                staged_cleanup_error.as_ref().map(|_| staged_cleanup_path),
                staged_cleanup_error,
            ));
        }
        if let Some(staged_cleanup_error) = staged_cleanup_error {
            error = AtomicDirectoryError::Validation(format!(
                "{error}; cleanup staged directory `{}` failed: {staged_cleanup_error}",
                staged_cleanup_path.display()
            ));
        }
        return Err(error);
    }

    if let Some(holder) = backup_root {
        backup_root_cleanup(holder).map_err(|err| {
            AtomicDirectoryError::committed_but_cleanup_failed(
                "remove_backup_dir",
                destination,
                err,
            )
        })?;
    }

    sync_root_directory(parent_root).map_err(|err| {
        AtomicDirectoryError::committed_but_unsynced("sync_parent", destination, err)
    })
}

fn remove_backup_root(holder: RootDir) -> io::Result<()> {
    holder.into_dir().remove_open_dir_all()
}

fn create_backup_directory_in_root(parent_root: &RootDir) -> io::Result<RootDir> {
    let (_, holder) = create_staged_directory_in_root(parent_root, ".directory-backup-")?;
    Ok(holder)
}

fn move_existing_directory_to_backup(
    parent_root: &RootDir,
    destination_leaf: &Path,
    holder: &RootDir,
) -> io::Result<()> {
    parent_root
        .dir()
        .rename(destination_leaf, holder.dir(), Path::new("previous"))
}

fn remove_staged_directory(parent_root: &RootDir, staged_leaf: &Path) -> io::Result<()> {
    parent_root.dir().remove_dir_all(staged_leaf)
}

#[cfg(all(not(windows), unix))]
fn sync_dir_handle(dir: &Dir) -> io::Result<()> {
    match rustix::fs::fsync(dir) {
        Ok(()) => Ok(()),
        Err(rustix::io::Errno::BADF) | Err(rustix::io::Errno::INVAL) => Ok(()),
        Err(err) => Err(io::Error::from(err)),
    }
}

#[cfg(all(not(windows), unix))]
fn sync_root_directory(root: &RootDir) -> io::Result<()> {
    sync_dir_handle(root.dir())
}

#[cfg(not(all(not(windows), unix)))]
fn sync_root_directory(_root: &RootDir) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom, Write};
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::path::Path;

    #[cfg(unix)]
    use super::sync_directory_tree;
    use super::{
        AtomicDirectoryOptions, AtomicWriteError, AtomicWriteOptions, stage_directory_atomically,
        stage_file_atomically, stage_file_atomically_with_name, write_file_atomically,
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
            .staged_path()
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

    #[test]
    fn staged_atomic_directory_replaces_existing_directory() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tree");
        std::fs::create_dir_all(&destination).expect("mkdir destination");
        std::fs::write(destination.join("old.txt"), b"old").expect("seed file");

        let staged = stage_directory_atomically(&destination, &AtomicDirectoryOptions::default())
            .expect("stage directory");
        std::fs::create_dir_all(staged.path().join("bin")).expect("mkdir staged");
        std::fs::write(staged.path().join("bin/tool"), b"new").expect("write staged file");

        staged.commit().expect("commit directory");

        assert!(!destination.join("old.txt").exists());
        assert_eq!(
            std::fs::read(destination.join("bin/tool")).expect("read staged file"),
            b"new"
        );
    }

    #[test]
    fn staged_atomic_directory_reports_committed_cleanup_failure_after_switch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tree");
        std::fs::create_dir_all(&destination).expect("mkdir destination");
        std::fs::write(destination.join("old.txt"), b"old").expect("seed file");

        let mut staged =
            stage_directory_atomically(&destination, &AtomicDirectoryOptions::default())
                .expect("stage directory");
        std::fs::create_dir_all(staged.path().join("bin")).expect("mkdir staged");
        std::fs::write(staged.path().join("bin/tool"), b"new").expect("write staged file");
        let staged_root = staged
            .staged_root
            .as_ref()
            .expect("staged directory missing");
        super::validate_staged_directory(staged_root.dir(), &staged.staged_path)
            .expect("validate staged directory");
        let _ = staged.staged_root.take();

        let err = super::commit_replace_directory_with_cleanup_hooks(
            &staged.parent_root,
            &staged.staged_leaf,
            &staged.destination_leaf,
            &destination,
            &staged.options,
            super::create_backup_directory_in_root,
            super::move_existing_directory_to_backup,
            |_| Err(std::io::Error::other("cleanup failed")),
            super::remove_staged_directory,
        )
        .expect_err("cleanup failure should surface");

        match err {
            super::AtomicDirectoryError::CommittedButCleanupFailed { op, path, source } => {
                assert_eq!(op, "remove_backup_dir");
                assert_eq!(path, destination);
                assert_eq!(source.to_string(), "cleanup failed");
            }
            other => panic!("unexpected error: {other:?}"),
        }

        assert!(!destination.join("old.txt").exists());
        assert_eq!(
            std::fs::read(destination.join("bin/tool")).expect("read switched directory"),
            b"new"
        );
    }

    #[test]
    fn staged_atomic_directory_cleans_staged_tree_when_create_backup_dir_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tree");
        std::fs::create_dir_all(&destination).expect("mkdir destination");
        std::fs::write(destination.join("old.txt"), b"old").expect("seed file");

        let staged = stage_directory_atomically(&destination, &AtomicDirectoryOptions::default())
            .expect("stage directory");
        std::fs::write(staged.path().join("new.txt"), b"new").expect("write staged file");
        let mut staged = staged;
        let _ = staged.staged_root.take();

        let err = super::commit_replace_directory_with_cleanup_hooks(
            &staged.parent_root,
            &staged.staged_leaf,
            &staged.destination_leaf,
            &destination,
            &staged.options,
            |_| Err(std::io::Error::other("backup dir creation failed")),
            super::move_existing_directory_to_backup,
            super::remove_backup_root,
            super::remove_staged_directory,
        )
        .expect_err("backup dir creation should fail");

        match err {
            super::AtomicDirectoryError::IoPath { op, path, .. } => {
                assert_eq!(op, "create_backup_dir");
                assert_eq!(path, destination);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            !staged.path().exists(),
            "create_backup_dir failure must clean staged directory"
        );
        assert!(destination.join("old.txt").is_file());
    }

    #[test]
    fn staged_atomic_directory_cleans_staged_tree_when_rename_existing_fails() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tree");
        std::fs::create_dir_all(&destination).expect("mkdir destination");
        std::fs::write(destination.join("old.txt"), b"old").expect("seed file");

        let staged = stage_directory_atomically(&destination, &AtomicDirectoryOptions::default())
            .expect("stage directory");
        std::fs::write(staged.path().join("new.txt"), b"new").expect("write staged file");
        let mut staged = staged;
        let _ = staged.staged_root.take();

        let err = super::commit_replace_directory_with_cleanup_hooks(
            &staged.parent_root,
            &staged.staged_leaf,
            &staged.destination_leaf,
            &destination,
            &staged.options,
            super::create_backup_directory_in_root,
            |_, _, _| Err(std::io::Error::other("rename existing failed")),
            super::remove_backup_root,
            super::remove_staged_directory,
        )
        .expect_err("rename_existing should fail");

        match err {
            super::AtomicDirectoryError::IoPath { op, path, .. } => {
                assert_eq!(op, "rename_existing");
                assert_eq!(path, destination);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            !staged.path().exists(),
            "rename_existing failure must clean staged directory"
        );
        assert!(destination.join("old.txt").is_file());
    }

    #[test]
    fn staged_atomic_directory_rejects_non_directory_destination() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tree");
        std::fs::write(&destination, b"not a dir").expect("seed file");

        let staged = stage_directory_atomically(&destination, &AtomicDirectoryOptions::default())
            .expect("stage directory");

        let staged_path = staged.path().to_path_buf();
        let err = staged
            .commit()
            .expect_err("non-directory destination must fail");
        assert!(matches!(err, super::AtomicDirectoryError::Validation(_)));
        assert!(
            !staged_path.exists(),
            "validation failure must clean staged directory"
        );
    }

    #[test]
    fn staged_atomic_file_commit_returns_error_after_staged_file_is_consumed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tool");
        let mut staged = stage_file_atomically(&destination, &AtomicWriteOptions::default())
            .expect("stage file");
        let _ = staged.staged.take();

        let err = staged
            .commit()
            .expect_err("missing staged file must fail closed");
        match err {
            super::AtomicWriteError::Validation(message) => {
                assert!(message.contains("is no longer available"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn staged_atomic_directory_clone_returns_error_after_staged_dir_is_consumed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tree");
        let mut staged =
            stage_directory_atomically(&destination, &AtomicDirectoryOptions::default())
                .expect("stage directory");
        let _ = staged.staged_root.take();

        let err = staged
            .try_clone_dir()
            .expect_err("missing staged directory must fail closed");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains("is no longer available"));
    }

    #[test]
    fn staged_atomic_directory_commit_returns_error_after_staged_dir_is_consumed() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tree");
        let mut staged =
            stage_directory_atomically(&destination, &AtomicDirectoryOptions::default())
                .expect("stage directory");
        let _ = staged.staged_root.take();

        let err = staged
            .commit()
            .expect_err("missing staged directory must fail closed");
        match err {
            super::AtomicDirectoryError::Validation(message) => {
                assert!(message.contains("is no longer available"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn staged_atomic_directory_reports_staged_cleanup_failure_after_rename_failure() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tree");
        let blocker = temp.path().join("tree.blocker");
        let stage_options = AtomicDirectoryOptions {
            overwrite_existing: false,
            ..AtomicDirectoryOptions::default()
        };
        let staged =
            stage_directory_atomically(&destination, &stage_options).expect("stage directory");
        std::fs::write(&blocker, b"blocker").expect("create rename blocker");

        let err = super::commit_replace_directory_with_cleanup_hooks(
            &staged.parent_root,
            &staged.staged_leaf,
            Path::new("tree.blocker"),
            &blocker,
            &stage_options,
            super::create_backup_directory_in_root,
            super::move_existing_directory_to_backup,
            super::remove_backup_root,
            |_, _| Err(std::io::Error::other("staged cleanup failed")),
        )
        .expect_err("rename failure should surface staged cleanup failure");

        match err {
            super::AtomicDirectoryError::Validation(message) => {
                assert!(message.contains("cleanup staged directory"));
                assert!(message.contains("staged cleanup failed"));
                assert!(message.contains("rename_staged"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(
            staged.path().exists(),
            "failing cleanup hook should leave staged tree behind"
        );
        assert!(blocker.is_file(), "rename blocker must remain in place");
    }

    #[test]
    fn staged_atomic_directory_reports_recoverable_backup_path_when_restore_fails() {
        use std::cell::RefCell;

        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tree");
        std::fs::create_dir_all(&destination).expect("mkdir destination");
        std::fs::write(destination.join("old.txt"), b"old").expect("seed file");

        let staged = stage_directory_atomically(&destination, &AtomicDirectoryOptions::default())
            .expect("stage directory");
        std::fs::write(staged.path().join("new.txt"), b"new").expect("write staged file");
        let backup_holder =
            super::create_backup_directory_in_root(&staged.parent_root).expect("backup holder");
        let expected_backup_path = backup_holder.path().join("previous");
        let backup_holder = RefCell::new(Some(backup_holder));

        let err = super::commit_replace_directory_with_cleanup_hooks(
            &staged.parent_root,
            &staged.staged_leaf,
            &staged.destination_leaf,
            &destination,
            &staged.options,
            move |_| {
                backup_holder
                    .borrow_mut()
                    .take()
                    .ok_or_else(|| std::io::Error::other("backup holder already consumed"))
            },
            |parent_root, destination_leaf, holder| {
                super::move_existing_directory_to_backup(parent_root, destination_leaf, holder)?;
                std::fs::write(parent_root.path().join(destination_leaf), b"blocker")?;
                Ok(())
            },
            super::remove_backup_root,
            super::remove_staged_directory,
        )
        .expect_err("restore failure should expose backup path");

        match err {
            super::AtomicDirectoryError::RollbackFailed {
                op,
                path,
                backup_path,
                source,
                staged_cleanup_path,
                staged_cleanup_source,
            } => {
                assert_eq!(op, "restore_existing");
                assert_eq!(path, destination);
                assert_eq!(backup_path, expected_backup_path);
                assert!(matches!(
                    source.kind(),
                    std::io::ErrorKind::AlreadyExists | std::io::ErrorKind::NotADirectory
                ));
                assert!(staged_cleanup_path.is_none());
                assert!(staged_cleanup_source.is_none());
            }
            other => panic!("unexpected error: {other:?}"),
        }

        assert!(expected_backup_path.join("old.txt").is_file());
        assert!(
            !staged.path().exists(),
            "staged directory should still be cleaned up"
        );
        assert!(
            destination.is_file(),
            "restore blocker should remain in place"
        );
    }

    #[cfg(unix)]
    #[test]
    fn stage_file_rejects_existing_symlink_ancestor_in_parent_chain() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let real_parent = temp.path().join("real-parent");
        std::fs::create_dir_all(&real_parent).expect("mkdir real parent");
        let linked_parent = temp.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).expect("create parent symlink");
        let destination = linked_parent.join("nested").join("tool");

        let err = stage_file_atomically(&destination, &AtomicWriteOptions::default())
            .expect_err("symlink ancestor must fail");
        assert!(matches!(
            err,
            AtomicWriteError::IoPath {
                op: "prepare_parent",
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn stage_file_rejects_missing_suffix_redirected_by_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let trusted_parent = temp.path().join("trusted");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&trusted_parent).expect("mkdir trusted parent");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        symlink(&outside, trusted_parent.join("logs")).expect("create target symlink");
        let destination = trusted_parent.join("logs").join("tool");

        let err = stage_file_atomically(&destination, &AtomicWriteOptions::default())
            .expect_err("symlinked missing suffix must fail");
        assert!(matches!(
            err,
            AtomicWriteError::IoPath {
                op: "prepare_parent",
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn stage_directory_rejects_existing_symlink_ancestor_in_parent_chain() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let real_parent = temp.path().join("real-parent");
        std::fs::create_dir_all(&real_parent).expect("mkdir real parent");
        let linked_parent = temp.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).expect("create parent symlink");
        let destination = linked_parent.join("nested").join("tree");

        let err = stage_directory_atomically(&destination, &AtomicDirectoryOptions::default())
            .expect_err("symlink ancestor must fail");
        assert!(matches!(
            err,
            super::AtomicDirectoryError::IoPath {
                op: "prepare_parent",
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn stage_directory_rejects_missing_suffix_redirected_by_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let trusted_parent = temp.path().join("trusted");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&trusted_parent).expect("mkdir trusted parent");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        symlink(&outside, trusted_parent.join("logs")).expect("create target symlink");
        let destination = trusted_parent.join("logs").join("tree");

        let err = stage_directory_atomically(&destination, &AtomicDirectoryOptions::default())
            .expect_err("symlinked missing suffix must fail");
        assert!(matches!(
            err,
            super::AtomicDirectoryError::IoPath {
                op: "prepare_parent",
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn staged_atomic_file_commit_does_not_follow_parent_swap_to_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let parent = temp.path().join("parent");
        let moved_parent = temp.path().join("parent-real");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&parent).expect("mkdir parent");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        let destination = parent.join("tool");

        let mut staged = stage_file_atomically(&destination, &AtomicWriteOptions::default())
            .expect("stage file");
        staged.file_mut().write_all(b"tool").expect("write staged");

        std::fs::rename(&parent, &moved_parent).expect("move parent");
        symlink(&outside, &parent).expect("replace parent with symlink");

        staged.commit().expect("commit staged file");

        assert!(!outside.join("tool").exists());
        assert_eq!(
            std::fs::read(moved_parent.join("tool")).expect("read committed file"),
            b"tool"
        );
    }

    #[cfg(unix)]
    #[test]
    fn staged_atomic_directory_commit_does_not_follow_parent_swap_to_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let parent = temp.path().join("parent");
        let moved_parent = temp.path().join("parent-real");
        let outside = temp.path().join("outside");
        std::fs::create_dir_all(&parent).expect("mkdir parent");
        std::fs::create_dir_all(&outside).expect("mkdir outside");
        let destination = parent.join("tree");

        let staged = stage_directory_atomically(&destination, &AtomicDirectoryOptions::default())
            .expect("stage directory");
        let staged_dir = staged.try_clone_dir().expect("clone staged dir");
        staged_dir.create_dir("bin").expect("mkdir staged bin");
        staged_dir
            .write("bin/tool", b"tool")
            .expect("write staged file");

        std::fs::rename(&parent, &moved_parent).expect("move parent");
        symlink(&outside, &parent).expect("replace parent with symlink");

        staged.commit().expect("commit staged directory");

        assert!(!outside.join("tree").exists());
        assert_eq!(
            std::fs::read(moved_parent.join("tree/bin/tool")).expect("read committed tree"),
            b"tool"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn atomic_write_allows_macos_tempdir_root_alias() {
        let temp = tempfile::tempdir().expect("tempdir");
        let destination = temp.path().join("tool");

        write_file_atomically(b"tool", &destination, &AtomicWriteOptions::default())
            .expect("write through macos tempdir root alias");
        assert_eq!(
            std::fs::read(&destination).expect("read destination"),
            b"tool"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_root_alias_matching_stays_narrow() {
        assert!(super::is_macos_root_alias_component(
            std::path::Component::Normal("var".as_ref())
        ));
        assert!(super::is_macos_root_alias_component(
            std::path::Component::Normal("tmp".as_ref())
        ));
        assert!(!super::is_macos_root_alias_component(
            std::path::Component::Normal("private".as_ref())
        ));
        assert!(!super::is_macos_root_alias_component(
            std::path::Component::Normal("Users".as_ref())
        ));
    }

    #[cfg(unix)]
    #[test]
    fn sync_directory_tree_skips_symlink_entries() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("tree");
        std::fs::create_dir_all(root.join("bin")).expect("mkdir");
        std::fs::write(root.join("bin/tool"), b"demo").expect("write tool");
        symlink("bin/tool", root.join("tool-link")).expect("create symlink");

        let root_dir = crate::open_ambient_root(
            &root,
            "test tree",
            crate::MissingRootPolicy::Error,
            |_dir, component, full_path, err| {
                std::io::Error::new(
                    err.kind(),
                    format!(
                        "failed to open {} for {}: {err}",
                        component.display(),
                        full_path.display()
                    ),
                )
            },
        )
        .expect("open tree")
        .expect("tree exists");

        sync_directory_tree(root_dir.dir(), &root).expect("sync tree with symlink");
    }
}
