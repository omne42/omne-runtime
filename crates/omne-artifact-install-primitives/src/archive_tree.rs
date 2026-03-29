use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use omne_fs_primitives::{
    AtomicDirectoryOptions, AtomicWriteOptions, lock_advisory_file_in_ambient_root,
    stage_directory_atomically, stage_file_atomically_with_name,
};
use omne_integrity_primitives::{Sha256Digest, verify_sha256_reader};
use tar::Archive as TarArchive;
use xz2::read::XzDecoder;
use zip::ZipArchive;

use crate::artifact_download::{
    ArtifactDownloadCandidate, ArtifactInstallError, candidate_failure_message,
    download_candidate_to_writer_with_options, failed_candidates_error,
};

pub const DEFAULT_MAX_ARCHIVE_TREE_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_MAX_ARCHIVE_TREE_ENTRIES: u64 = 65_536;
#[cfg(unix)]
const MAX_ZIP_SYMLINK_TARGET_BYTES: usize = 16 * 1024;
const ARCHIVE_TREE_INSTALL_LOCK_PREFIX: &str = ".archive-tree-install-";
const ARCHIVE_TREE_INSTALL_LOCK_SUFFIX: &str = ".lock";

#[derive(Debug, Clone, Copy)]
pub struct ArchiveTreeInstallRequest<'a> {
    pub canonical_url: &'a str,
    pub destination: &'a Path,
    pub asset_name: &'a str,
    pub expected_sha256: Option<&'a Sha256Digest>,
    pub max_download_bytes: Option<u64>,
}

pub fn is_archive_tree_asset_name(asset_name: &str) -> bool {
    asset_name.ends_with(".tar.gz")
        || asset_name.ends_with(".tar.xz")
        || asset_name.ends_with(".zip")
}

pub fn install_archive_tree_from_bytes(
    asset_name: &str,
    archive_bytes: &[u8],
    destination: &Path,
) -> Result<(), ArtifactInstallError> {
    install_archive_tree_from_reader_with_limits(
        asset_name,
        Cursor::new(archive_bytes),
        destination,
        ArchiveExtractionLimits::default(),
    )
}

pub async fn download_and_install_archive_tree(
    client: &reqwest::Client,
    candidates: &[ArtifactDownloadCandidate],
    request: &ArchiveTreeInstallRequest<'_>,
) -> Result<ArtifactDownloadCandidate, ArtifactInstallError> {
    if !is_archive_tree_asset_name(request.asset_name) {
        return Err(ArtifactInstallError::install(format!(
            "archive tree install requires a supported archive asset, got `{}`",
            request.asset_name
        )));
    }

    let mut errors = Vec::new();
    for candidate in candidates {
        let mut staged = stage_file_atomically_with_name(
            request.destination,
            &archive_download_stage_options(),
            Some(request.asset_name),
        )
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;

        let download_result = download_candidate_to_writer_with_options(
            client,
            candidate,
            staged.file_mut(),
            request.max_download_bytes,
        )
        .await;
        if let Err(err) = download_result {
            errors.push(candidate_failure_message(candidate, &err));
            continue;
        }

        if let Some(expected_sha256) = request.expected_sha256 {
            let verify_result = staged
                .file_mut()
                .seek(SeekFrom::Start(0))
                .map_err(|err| ArtifactInstallError::install(err.to_string()))
                .and_then(|_| {
                    verify_sha256_reader(staged.file_mut(), expected_sha256)
                        .map_err(|err| ArtifactInstallError::download(err.to_string()))
                });
            if let Err(err) = verify_result {
                errors.push(candidate_failure_message(candidate, &err));
                continue;
            }
        }

        let install_result = staged
            .file_mut()
            .seek(SeekFrom::Start(0))
            .map_err(|err| ArtifactInstallError::install(err.to_string()))
            .and_then(|_| {
                install_archive_tree_from_reader(
                    request.asset_name,
                    staged.file_mut(),
                    request.destination,
                )
            });
        if let Err(err) = install_result {
            errors.push(candidate_failure_message(candidate, &err));
            continue;
        }

        return Ok(candidate.clone());
    }

    Err(failed_candidates_error(request.canonical_url, errors))
}

fn install_archive_tree_from_reader<R>(
    asset_name: &str,
    reader: R,
    destination: &Path,
) -> Result<(), ArtifactInstallError>
where
    R: Read + Seek,
{
    install_archive_tree_from_reader_with_limits(
        asset_name,
        reader,
        destination,
        ArchiveExtractionLimits::default(),
    )
}

fn install_archive_tree_from_reader_with_limits<R>(
    asset_name: &str,
    reader: R,
    destination: &Path,
    limits: ArchiveExtractionLimits,
) -> Result<(), ArtifactInstallError>
where
    R: Read + Seek,
{
    let _install_lock = lock_archive_tree_destination(destination)?;
    let staged = stage_directory_atomically(destination, &archive_tree_stage_options())
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    let extract_result = if asset_name.ends_with(".zip") {
        extract_zip_tree(reader, staged.path(), limits)
    } else if asset_name.ends_with(".tar.gz") {
        extract_tar_tree(GzDecoder::new(reader), staged.path(), limits)
    } else if asset_name.ends_with(".tar.xz") {
        extract_tar_tree(XzDecoder::new(reader), staged.path(), limits)
    } else {
        Err(ArtifactInstallError::install(format!(
            "unsupported archive tree asset `{asset_name}`"
        )))
    };

    extract_result?;
    staged
        .commit()
        .map_err(|err| ArtifactInstallError::install(err.to_string()))
}

fn lock_archive_tree_destination(
    destination: &Path,
) -> Result<omne_fs_primitives::AdvisoryLockGuard, ArtifactInstallError> {
    let lock_root = destination.parent().unwrap_or_else(|| Path::new("."));
    let lock_file = archive_tree_install_lock_file_name(destination);
    lock_advisory_file_in_ambient_root(
        lock_root,
        "archive tree install lock root",
        &lock_file,
        "archive tree install lock file",
    )
    .map_err(|err| {
        ArtifactInstallError::install(format!(
            "failed to lock archive tree destination `{}`: {err}",
            destination.display()
        ))
    })
}

fn archive_tree_install_lock_file_name(destination: &Path) -> PathBuf {
    let label = destination
        .file_name()
        .map(|name| sanitize_lock_component(&name.to_string_lossy()))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "tree".to_string());
    PathBuf::from(format!(
        "{ARCHIVE_TREE_INSTALL_LOCK_PREFIX}{label}{ARCHIVE_TREE_INSTALL_LOCK_SUFFIX}"
    ))
}

fn sanitize_lock_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '.' | '-' | '_' => ch,
            _ => '_',
        })
        .collect()
}

fn extract_zip_tree<R>(
    reader: R,
    destination: &Path,
    limits: ArchiveExtractionLimits,
) -> Result<(), ArtifactInstallError>
where
    R: Read + Seek,
{
    let mut budget = ExtractionBudget::new(limits);
    let mut archive =
        ZipArchive::new(reader).map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
        let enclosed = entry
            .enclosed_name()
            .ok_or_else(|| {
                ArtifactInstallError::install(format!("unsafe archive entry path at index {index}"))
            })?
            .to_path_buf();
        budget.record_entry(&enclosed)?;
        let output_path = destination.join(&enclosed);
        if entry.is_dir() {
            ensure_archive_directory_chain(&enclosed, &output_path, destination, true)?;
            continue;
        }
        if zip_entry_is_symlink(&entry) {
            budget.reserve_bytes(&enclosed, entry.size())?;
            let link_target = read_zip_symlink_target(&enclosed, &mut entry)?;
            create_tar_symlink(&enclosed, &output_path, &link_target, destination)?;
            continue;
        }
        budget.reserve_bytes(&enclosed, entry.size())?;
        let unix_mode = zip_entry_unix_mode(&entry);
        write_archive_regular_file(&enclosed, &output_path, destination, &mut entry, unix_mode)?;
    }
    Ok(())
}

fn extract_tar_tree<R>(
    reader: R,
    destination: &Path,
    limits: ArchiveExtractionLimits,
) -> Result<(), ArtifactInstallError>
where
    R: Read,
{
    let mut budget = ExtractionBudget::new(limits);
    let mut archive = TarArchive::new(reader);
    let mut pending_hard_links = Vec::new();
    let entries = archive
        .entries()
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|err| ArtifactInstallError::install(err.to_string()))?;
        let path = entry
            .path()
            .map_err(|err| ArtifactInstallError::install(err.to_string()))?
            .into_owned();
        let sanitized = sanitize_archive_path(&path)?;
        budget.record_entry(&sanitized)?;
        let output_path = destination.join(&sanitized);
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            ensure_archive_directory_chain(&sanitized, &output_path, destination, true)?;
            continue;
        }
        if entry_type.is_file() {
            budget.reserve_bytes(&path, entry.size())?;
            let unix_mode = tar_entry_unix_mode(&entry)?;
            write_archive_regular_file(
                &sanitized,
                &output_path,
                destination,
                &mut entry,
                unix_mode,
            )?;
            continue;
        }
        if entry_type.is_symlink() {
            let link_target = entry
                .link_name()
                .map_err(|err| ArtifactInstallError::install(err.to_string()))?
                .ok_or_else(|| {
                    ArtifactInstallError::install(format!(
                        "missing symlink target for tar entry {}",
                        path.display()
                    ))
                })?;
            create_tar_symlink(&path, &output_path, &link_target, destination)?;
            continue;
        }
        if entry_type.is_hard_link() {
            let link_target = entry
                .link_name()
                .map_err(|err| ArtifactInstallError::install(err.to_string()))?
                .ok_or_else(|| {
                    ArtifactInstallError::install(format!(
                        "missing hard link target for tar entry {}",
                        path.display()
                    ))
                })?;
            pending_hard_links.push(prepare_tar_hard_link(
                &path,
                &output_path,
                &link_target,
                destination,
            )?);
            continue;
        }
        return Err(ArtifactInstallError::install(format!(
            "unsupported tar entry type for {}",
            path.display()
        )));
    }
    resolve_pending_tar_hard_links(&mut pending_hard_links, destination)?;
    Ok(())
}

#[derive(Debug)]
struct PendingTarHardLink {
    entry_path: PathBuf,
    output_path: PathBuf,
    link_target: PathBuf,
    resolved_target: PathBuf,
}

fn create_tar_symlink(
    entry_path: &Path,
    output_path: &Path,
    link_target: &Path,
    destination: &Path,
) -> Result<(), ArtifactInstallError> {
    let parent = output_path.parent().ok_or_else(|| {
        ArtifactInstallError::install(format!(
            "cannot determine symlink parent for tar entry {}",
            entry_path.display()
        ))
    })?;
    ensure_archive_directory_chain(entry_path, parent, destination, true)?;
    validate_archive_link_target(entry_path, parent, link_target, destination)?;
    remove_existing_regular_file_leaf(entry_path, output_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        symlink(link_target, output_path)
            .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        let _ = link_target;
        let _ = destination;
        Err(ArtifactInstallError::install(format!(
            "unsupported tar symlink entry for {} on this platform",
            output_path.display()
        )))
    }
}

fn prepare_tar_hard_link(
    entry_path: &Path,
    output_path: &Path,
    link_target: &Path,
    destination: &Path,
) -> Result<PendingTarHardLink, ArtifactInstallError> {
    let parent = output_path.parent().ok_or_else(|| {
        ArtifactInstallError::install(format!(
            "cannot determine hard link parent for tar entry {}",
            entry_path.display()
        ))
    })?;
    ensure_archive_directory_chain(entry_path, parent, destination, true)?;
    let resolved_target = validate_archive_hard_link_target(entry_path, link_target, destination)?;
    Ok(PendingTarHardLink {
        entry_path: entry_path.to_path_buf(),
        output_path: output_path.to_path_buf(),
        link_target: link_target.to_path_buf(),
        resolved_target,
    })
}

fn resolve_pending_tar_hard_links(
    pending_hard_links: &mut Vec<PendingTarHardLink>,
    destination: &Path,
) -> Result<(), ArtifactInstallError> {
    while !pending_hard_links.is_empty() {
        let mut remaining = Vec::new();
        let mut progressed = false;
        for pending in pending_hard_links.drain(..) {
            if try_create_tar_hard_link(&pending, destination)? {
                progressed = true;
            } else {
                remaining.push(pending);
            }
        }
        if !remaining.is_empty() && !progressed {
            let pending = remaining.remove(0);
            if let Some(target_parent) = pending.resolved_target.parent() {
                ensure_archive_directory_chain(
                    &pending.entry_path,
                    target_parent,
                    destination,
                    false,
                )?;
            }
            return Err(ArtifactInstallError::install(format!(
                "hard link target `{}` does not exist for tar entry {}",
                pending.link_target.display(),
                pending.entry_path.display()
            )));
        }
        *pending_hard_links = remaining;
    }
    Ok(())
}

fn try_create_tar_hard_link(
    pending: &PendingTarHardLink,
    destination: &Path,
) -> Result<bool, ArtifactInstallError> {
    let parent = pending.output_path.parent().ok_or_else(|| {
        ArtifactInstallError::install(format!(
            "cannot determine hard link parent for tar entry {}",
            pending.entry_path.display()
        ))
    })?;
    ensure_archive_directory_chain(&pending.entry_path, parent, destination, false)?;
    if let Some(target_parent) = pending.resolved_target.parent() {
        ensure_archive_directory_chain(&pending.entry_path, target_parent, destination, false)?;
    }
    let target_metadata = match fs::symlink_metadata(&pending.resolved_target) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(ArtifactInstallError::install(err.to_string())),
    };
    if target_metadata.file_type().is_symlink() || target_metadata.is_dir() {
        return Err(ArtifactInstallError::install(format!(
            "unsafe hard link target `{}` for {}",
            pending.link_target.display(),
            pending.entry_path.display()
        )));
    }
    remove_existing_regular_file_leaf(&pending.entry_path, &pending.output_path)?;
    fs::hard_link(&pending.resolved_target, &pending.output_path)
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    Ok(true)
}

fn write_archive_regular_file<R>(
    entry_path: &Path,
    output_path: &Path,
    destination: &Path,
    reader: &mut R,
    unix_mode: Option<u32>,
) -> Result<(), ArtifactInstallError>
where
    R: Read + ?Sized,
{
    #[cfg(not(unix))]
    let _ = unix_mode;
    let parent = output_path.parent().ok_or_else(|| {
        ArtifactInstallError::install(format!(
            "cannot determine parent directory for archive entry {}",
            entry_path.display()
        ))
    })?;
    ensure_archive_directory_chain(entry_path, parent, destination, true)?;
    remove_existing_regular_file_leaf(entry_path, output_path)?;
    let mut file =
        File::create(output_path).map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    std::io::copy(reader, &mut file)
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    #[cfg(unix)]
    if let Some(mode) = unix_mode {
        fs::set_permissions(output_path, fs::Permissions::from_mode(mode))
            .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    }
    Ok(())
}

fn remove_existing_regular_file_leaf(
    entry_path: &Path,
    output_path: &Path,
) -> Result<(), ArtifactInstallError> {
    match fs::symlink_metadata(output_path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(ArtifactInstallError::install(format!(
                "unsafe archive output `{}` is a symlink for {}",
                output_path.display(),
                entry_path.display()
            )))
        }
        Ok(metadata) if metadata.is_dir() => Err(ArtifactInstallError::install(format!(
            "unsafe archive output `{}` is a directory for {}",
            output_path.display(),
            entry_path.display()
        ))),
        Ok(_) => {
            fs::remove_file(output_path)
                .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(ArtifactInstallError::install(err.to_string())),
    }
}

#[cfg(unix)]
fn read_zip_symlink_target(
    entry_path: &Path,
    entry: &mut zip::read::ZipFile<'_>,
) -> Result<PathBuf, ArtifactInstallError> {
    let mut target = Vec::new();
    entry
        .take(
            u64::try_from(MAX_ZIP_SYMLINK_TARGET_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut target)
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    if target.len() > MAX_ZIP_SYMLINK_TARGET_BYTES {
        return Err(ArtifactInstallError::install(format!(
            "zip symlink target for {} exceeds limit of {} bytes",
            entry_path.display(),
            MAX_ZIP_SYMLINK_TARGET_BYTES
        )));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(target)))
}

#[cfg(not(unix))]
fn read_zip_symlink_target(
    entry_path: &Path,
    entry: &mut zip::read::ZipFile<'_>,
) -> Result<PathBuf, ArtifactInstallError> {
    let _ = entry;
    Err(ArtifactInstallError::install(format!(
        "unsupported zip symlink entry for {} on this platform",
        entry_path.display()
    )))
}

fn zip_entry_unix_mode(entry: &zip::read::ZipFile<'_>) -> Option<u32> {
    entry.unix_mode().map(sanitize_unix_mode)
}

fn zip_entry_is_symlink(entry: &zip::read::ZipFile<'_>) -> bool {
    entry
        .unix_mode()
        .is_some_and(|mode| (mode & 0o170000) == 0o120000)
}

fn tar_entry_unix_mode<R>(entry: &tar::Entry<'_, R>) -> Result<Option<u32>, ArtifactInstallError>
where
    R: Read,
{
    #[cfg(unix)]
    {
        entry
            .header()
            .mode()
            .map(|mode| Some(sanitize_unix_mode(mode)))
            .map_err(|err| ArtifactInstallError::install(err.to_string()))
    }
    #[cfg(not(unix))]
    {
        let _ = entry;
        Ok(None)
    }
}

fn sanitize_unix_mode(mode: u32) -> u32 {
    mode & 0o777
}

fn ensure_archive_directory_chain(
    entry_path: &Path,
    directory: &Path,
    destination: &Path,
    create_missing: bool,
) -> Result<(), ArtifactInstallError> {
    let relative = directory.strip_prefix(destination).map_err(|_| {
        ArtifactInstallError::install(format!(
            "unsafe archive parent `{}` for {}",
            directory.display(),
            entry_path.display()
        ))
    })?;
    let mut current = destination.to_path_buf();
    for component in relative.components() {
        let Component::Normal(part) = component else {
            return Err(ArtifactInstallError::install(format!(
                "unsafe archive parent `{}` for {}",
                directory.display(),
                entry_path.display()
            )));
        };
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ArtifactInstallError::install(format!(
                    "unsafe archive parent uses symlink ancestor `{}` for {}",
                    current.display(),
                    entry_path.display()
                )));
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err(ArtifactInstallError::install(format!(
                    "unsafe archive parent component `{}` is not a directory for {}",
                    current.display(),
                    entry_path.display()
                )));
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound && create_missing => {
                fs::create_dir(&current)
                    .map_err(|create_err| ArtifactInstallError::install(create_err.to_string()))?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => break,
            Err(err) => return Err(ArtifactInstallError::install(err.to_string())),
        }
    }
    Ok(())
}

fn validate_archive_link_target(
    entry_path: &Path,
    parent: &Path,
    link_target: &Path,
    destination: &Path,
) -> Result<PathBuf, ArtifactInstallError> {
    if link_target.is_absolute() {
        return Err(ArtifactInstallError::install(format!(
            "absolute archive link target is not allowed for {}",
            entry_path.display()
        )));
    }

    let mut resolved = parent.to_path_buf();
    for component in link_target.components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                if !resolved.pop() || !resolved.starts_with(destination) {
                    return Err(ArtifactInstallError::install(format!(
                        "unsafe archive link target `{}` for {}",
                        link_target.display(),
                        entry_path.display()
                    )));
                }
            }
            _ => {
                return Err(ArtifactInstallError::install(format!(
                    "unsafe archive link target `{}` for {}",
                    link_target.display(),
                    entry_path.display()
                )));
            }
        }
    }

    if !resolved.starts_with(destination) {
        return Err(ArtifactInstallError::install(format!(
            "unsafe archive link target `{}` for {}",
            link_target.display(),
            entry_path.display()
        )));
    }

    Ok(resolved)
}

fn validate_archive_hard_link_target(
    entry_path: &Path,
    link_target: &Path,
    destination: &Path,
) -> Result<PathBuf, ArtifactInstallError> {
    if link_target.is_absolute() {
        return Err(ArtifactInstallError::install(format!(
            "absolute archive link target is not allowed for {}",
            entry_path.display()
        )));
    }

    let sanitized = sanitize_archive_path(link_target).map_err(|_| {
        ArtifactInstallError::install(format!(
            "unsafe archive link target `{}` for {}",
            link_target.display(),
            entry_path.display()
        ))
    })?;
    Ok(destination.join(sanitized))
}

fn sanitize_archive_path(path: &Path) -> Result<PathBuf, ArtifactInstallError> {
    let mut sanitized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => sanitized.push(part),
            Component::CurDir => {}
            _ => {
                return Err(ArtifactInstallError::install(format!(
                    "unsafe tar archive entry path `{}`",
                    path.display()
                )));
            }
        }
    }
    if sanitized.as_os_str().is_empty() {
        return Err(ArtifactInstallError::install(
            "empty tar archive entry path",
        ));
    }
    Ok(sanitized)
}

fn archive_download_stage_options() -> AtomicWriteOptions {
    AtomicWriteOptions {
        create_parent_directories: true,
        ..AtomicWriteOptions::default()
    }
}

fn archive_tree_stage_options() -> AtomicDirectoryOptions {
    AtomicDirectoryOptions {
        overwrite_existing: true,
        create_parent_directories: true,
    }
}

#[derive(Debug, Clone, Copy)]
struct ArchiveExtractionLimits {
    max_extracted_bytes: u64,
    max_entries: u64,
}

impl Default for ArchiveExtractionLimits {
    fn default() -> Self {
        Self {
            max_extracted_bytes: DEFAULT_MAX_ARCHIVE_TREE_EXTRACTED_BYTES,
            max_entries: DEFAULT_MAX_ARCHIVE_TREE_ENTRIES,
        }
    }
}

struct ExtractionBudget {
    limits: ArchiveExtractionLimits,
    extracted_bytes: u64,
    entries: u64,
}

impl ExtractionBudget {
    fn new(limits: ArchiveExtractionLimits) -> Self {
        Self {
            limits,
            extracted_bytes: 0,
            entries: 0,
        }
    }

    fn record_entry(&mut self, path: &Path) -> Result<(), ArtifactInstallError> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > self.limits.max_entries {
            return Err(ArtifactInstallError::install(format!(
                "archive entry count exceeds limit of {} while extracting `{}`",
                self.limits.max_entries,
                path.display()
            )));
        }
        Ok(())
    }

    fn reserve_bytes(&mut self, path: &Path, bytes: u64) -> Result<(), ArtifactInstallError> {
        self.extracted_bytes = self.extracted_bytes.checked_add(bytes).ok_or_else(|| {
            ArtifactInstallError::install(format!(
                "archive extracted byte budget overflow while extracting `{}`",
                path.display()
            ))
        })?;
        if self.extracted_bytes > self.limits.max_extracted_bytes {
            return Err(ArtifactInstallError::install(format!(
                "archive extracted bytes exceed limit of {} while extracting `{}`",
                self.limits.max_extracted_bytes,
                path.display()
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;
    #[cfg(unix)]
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use omne_fs_primitives::lock_advisory_file_in_ambient_root;

    use crate::artifact_download::{ArtifactDownloadCandidate, ArtifactDownloadCandidateKind};

    use super::{
        ArchiveExtractionLimits, ArchiveTreeInstallRequest, archive_tree_install_lock_file_name,
        download_and_install_archive_tree, install_archive_tree_from_reader_with_limits,
    };
    #[cfg(unix)]
    use super::{MAX_ZIP_SYMLINK_TARGET_BYTES, extract_tar_tree, extract_zip_tree};

    fn make_zip_archive(entries: &[(&str, &[u8], u32)]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut writer = Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut writer);
            for (path, body, mode) in entries {
                let options = zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored)
                    .unix_permissions(*mode);
                if (mode & 0o170000) == 0o120000 {
                    archive.add_symlink(*path, String::from_utf8_lossy(body), options)?;
                } else {
                    archive.start_file(*path, options)?;
                    archive.write_all(body)?;
                }
            }
            archive.finish()?;
        }
        Ok(writer.into_inner())
    }

    #[cfg(unix)]
    enum TarEntry<'a> {
        Directory(&'a str, u32),
        File(&'a str, &'a [u8], u32),
        Symlink(&'a str, &'a str),
        HardLink(&'a str, &'a str),
    }

    #[cfg(unix)]
    fn make_tar_archive(entries: &[TarEntry<'_>]) -> Result<Vec<u8>, Box<dyn Error>> {
        use tar::{Builder, EntryType, Header};

        let mut archive = Builder::new(Vec::new());
        for entry in entries {
            match entry {
                TarEntry::Directory(path, mode) => {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Directory);
                    header.set_mode(*mode);
                    header.set_size(0);
                    archive.append_data(&mut header, path, std::io::empty())?;
                }
                TarEntry::File(path, body, mode) => {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Regular);
                    header.set_mode(*mode);
                    header.set_size(body.len() as u64);
                    archive.append_data(&mut header, path, *body)?;
                }
                TarEntry::Symlink(path, target) => {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Symlink);
                    header.set_mode(0o777);
                    header.set_size(0);
                    archive.append_link(&mut header, path, target)?;
                }
                TarEntry::HardLink(path, target) => {
                    let mut header = Header::new_gnu();
                    header.set_entry_type(EntryType::Link);
                    header.set_mode(0o644);
                    header.set_size(0);
                    archive.append_link(&mut header, path, target)?;
                }
            }
        }
        Ok(archive.into_inner()?)
    }

    fn spawn_mock_http_server(
        listener: TcpListener,
        routes: HashMap<String, Vec<u8>>,
        expected_requests: usize,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            for _ in 0..expected_requests {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buffer = [0_u8; 8192];
                let Ok(size) = stream.read(&mut buffer) else {
                    continue;
                };
                if size == 0 {
                    continue;
                }
                let request = String::from_utf8_lossy(&buffer[..size]);
                let request_line = request.lines().next().unwrap_or_default();
                let path = request_line.split_whitespace().nth(1).unwrap_or("/");
                let (status, body) = if let Some(body) = routes.get(path) {
                    ("200 OK", body.clone())
                } else {
                    ("404 Not Found", b"not found".to_vec())
                };
                let headers = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(headers.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        })
    }

    #[tokio::test]
    async fn archive_tree_download_retries_after_invalid_canonical_archive()
    -> Result<(), Box<dyn Error>> {
        let archive_name = "demo-tree.zip";
        let valid_archive = make_zip_archive(&[
            ("bin/demo.exe", b"MZ".as_slice(), 0o755),
            ("LICENSE", b"demo-license\n".as_slice(), 0o644),
        ])?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let base = format!("http://{addr}");
        let canonical_url = format!("{base}/{archive_name}");
        let mirror_url = format!("{base}/mirror/{archive_name}");

        let mut routes = HashMap::new();
        routes.insert(format!("/{archive_name}"), b"not a zip archive".to_vec());
        routes.insert(format!("/mirror/{archive_name}"), valid_archive);
        let handle = spawn_mock_http_server(listener, routes, 2);

        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");
        fs::create_dir_all(&destination)?;
        fs::write(destination.join("old.txt"), "stale")?;

        let client = reqwest::Client::builder().build()?;
        let selected = download_and_install_archive_tree(
            &client,
            &[
                ArtifactDownloadCandidate {
                    url: canonical_url.clone(),
                    kind: ArtifactDownloadCandidateKind::Canonical,
                },
                ArtifactDownloadCandidate {
                    url: mirror_url,
                    kind: ArtifactDownloadCandidateKind::Mirror,
                },
            ],
            &ArchiveTreeInstallRequest {
                canonical_url: &canonical_url,
                destination: &destination,
                asset_name: archive_name,
                expected_sha256: None,
                max_download_bytes: None,
            },
        )
        .await?;

        assert_eq!(selected.kind, ArtifactDownloadCandidateKind::Mirror);
        assert!(!destination.join("old.txt").exists());
        assert!(destination.join("bin/demo.exe").exists());
        assert!(destination.join("LICENSE").exists());

        handle.join().expect("mock server thread join");
        Ok(())
    }

    #[test]
    fn archive_tree_extract_rejects_extracted_byte_budget_overflow() -> Result<(), Box<dyn Error>> {
        let archive = make_zip_archive(&[("bin/demo", b"0123456789abcdef".as_slice(), 0o755)])?;
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");

        let err = install_archive_tree_from_reader_with_limits(
            "demo.zip",
            Cursor::new(archive),
            &destination,
            ArchiveExtractionLimits {
                max_extracted_bytes: 8,
                max_entries: 16,
            },
        )
        .expect_err("archive should exceed extracted-byte budget");

        assert_eq!(
            err.kind(),
            crate::artifact_download::ArtifactInstallErrorKind::Install
        );
        assert!(
            err.to_string()
                .contains("archive extracted bytes exceed limit"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn archive_tree_extract_rejects_entry_count_budget_overflow() -> Result<(), Box<dyn Error>> {
        let archive = make_zip_archive(&[
            ("bin/demo", b"demo".as_slice(), 0o755),
            ("LICENSE", b"license".as_slice(), 0o644),
        ])?;
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");

        let err = install_archive_tree_from_reader_with_limits(
            "demo.zip",
            Cursor::new(archive),
            &destination,
            ArchiveExtractionLimits {
                max_extracted_bytes: 1024,
                max_entries: 1,
            },
        )
        .expect_err("archive should exceed entry-count budget");

        assert!(
            err.to_string()
                .contains("archive entry count exceeds limit"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[test]
    fn archive_tree_install_serializes_same_destination() -> Result<(), Box<dyn Error>> {
        let archive = make_zip_archive(&[("bin/demo", b"demo".as_slice(), 0o755)])?;
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");
        let lock_root = destination.parent().expect("destination parent");
        let lock_file = archive_tree_install_lock_file_name(&destination);
        let guard = lock_advisory_file_in_ambient_root(
            lock_root,
            "archive tree install lock root",
            &lock_file,
            "archive tree install lock file",
        )?;
        let (tx, rx) = mpsc::channel();
        let destination_for_thread = destination.clone();
        let handle = thread::spawn(move || {
            let result = install_archive_tree_from_reader_with_limits(
                "demo.zip",
                Cursor::new(archive),
                &destination_for_thread,
                ArchiveExtractionLimits::default(),
            );
            tx.send(result).expect("send install result");
        });

        assert!(
            matches!(
                rx.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "same-destination install should wait for the advisory lock"
        );

        drop(guard);

        rx.recv_timeout(Duration::from_secs(2))
            .expect("install should complete after lock release")?;
        handle.join().expect("install thread join");
        assert_eq!(fs::read(destination.join("bin/demo"))?, b"demo");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn zip_symlink_targets_respect_length_limit() -> Result<(), Box<dyn Error>> {
        let oversized_target = "a".repeat(MAX_ZIP_SYMLINK_TARGET_BYTES + 1);
        let archive = make_zip_archive(&[("alias", oversized_target.as_bytes(), 0o120777)])?;
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");
        fs::create_dir_all(&destination)?;

        let err = extract_zip_tree(
            Cursor::new(archive),
            &destination,
            ArchiveExtractionLimits::default(),
        )
        .expect_err("oversized zip symlink target should be rejected");

        assert!(
            err.to_string().contains("zip symlink target"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn tar_symlink_entries_fail_closed_on_symlink_ancestor() -> Result<(), Box<dyn Error>> {
        let archive = make_tar_archive(&[
            TarEntry::Directory("safe", 0o755),
            TarEntry::Symlink("alias", "safe"),
            TarEntry::Symlink("alias/nested", "safe/target"),
        ])?;
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");
        fs::create_dir_all(&destination)?;

        let err = extract_tar_tree(
            Cursor::new(archive),
            &destination,
            ArchiveExtractionLimits::default(),
        )
        .expect_err("tar symlink parent with symlink ancestor must be rejected");

        assert!(
            err.to_string().contains("symlink ancestor"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn tar_regular_files_fail_closed_on_symlink_ancestor() -> Result<(), Box<dyn Error>> {
        let archive = make_tar_archive(&[
            TarEntry::Directory("safe", 0o755),
            TarEntry::Symlink("alias", "safe"),
            TarEntry::File("alias/escaped.txt", b"escape".as_slice(), 0o644),
        ])?;
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");
        fs::create_dir_all(&destination)?;

        let err = extract_tar_tree(
            Cursor::new(archive),
            &destination,
            ArchiveExtractionLimits::default(),
        )
        .expect_err("tar regular file under symlink ancestor must be rejected");

        assert!(
            err.to_string().contains("symlink ancestor"),
            "unexpected error: {err}"
        );
        assert!(!destination.join("safe/escaped.txt").exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn tar_hard_link_entries_fail_closed_on_symlink_ancestor() -> Result<(), Box<dyn Error>> {
        let archive = make_tar_archive(&[
            TarEntry::Directory("safe", 0o755),
            TarEntry::File("safe/file.txt", b"demo".as_slice(), 0o644),
            TarEntry::Symlink("alias", "safe"),
            TarEntry::HardLink("alias/file-copy.txt", "safe/file.txt"),
        ])?;
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");
        fs::create_dir_all(&destination)?;

        let err = extract_tar_tree(
            Cursor::new(archive),
            &destination,
            ArchiveExtractionLimits::default(),
        )
        .expect_err("tar hard-link parent with symlink ancestor must be rejected");

        assert!(
            err.to_string().contains("symlink ancestor"),
            "unexpected error: {err}"
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn tar_forward_hard_links_resolve_after_target_is_extracted() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::MetadataExt;

        let archive = make_tar_archive(&[
            TarEntry::Directory("bin", 0o755),
            TarEntry::HardLink("bin/demo-copy", "bin/demo"),
            TarEntry::File("bin/demo", b"demo".as_slice(), 0o755),
        ])?;
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");
        fs::create_dir_all(&destination)?;

        extract_tar_tree(
            Cursor::new(archive),
            &destination,
            ArchiveExtractionLimits::default(),
        )?;

        let target = destination.join("bin/demo");
        let linked = destination.join("bin/demo-copy");
        assert_eq!(fs::read(&target)?, b"demo");
        assert_eq!(fs::read(&linked)?, b"demo");
        assert_eq!(fs::metadata(&target)?.ino(), fs::metadata(&linked)?.ino());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn zip_symlink_entries_extract_as_symlinks() -> Result<(), Box<dyn Error>> {
        let archive = make_zip_archive(&[
            ("safe/target.txt", b"demo".as_slice(), 0o644),
            ("alias", b"safe/target.txt".as_slice(), 0o120777),
        ])?;
        {
            let mut zip = zip::ZipArchive::new(Cursor::new(&archive))?;
            let alias_entry = zip.by_name("alias")?;
            assert_eq!(alias_entry.unix_mode(), Some(0o120777));
        }
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");
        fs::create_dir_all(&destination)?;

        extract_zip_tree(
            Cursor::new(archive),
            &destination,
            ArchiveExtractionLimits::default(),
        )?;

        let alias = destination.join("alias");
        assert!(fs::symlink_metadata(&alias)?.file_type().is_symlink());
        assert_eq!(fs::read_link(&alias)?, PathBuf::from("safe/target.txt"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn archive_tree_strips_special_unix_mode_bits_from_regular_files() -> Result<(), Box<dyn Error>>
    {
        use std::os::unix::fs::PermissionsExt;

        let archive = make_tar_archive(&[TarEntry::File("bin/demo", b"demo".as_slice(), 0o6755)])?;
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");
        fs::create_dir_all(&destination)?;

        extract_tar_tree(
            Cursor::new(archive),
            &destination,
            ArchiveExtractionLimits::default(),
        )?;

        let mode = fs::metadata(destination.join("bin/demo"))?
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(mode, 0o755);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn zip_regular_files_fail_closed_on_symlink_ancestor() -> Result<(), Box<dyn Error>> {
        let archive = make_zip_archive(&[
            ("safe/target.txt", b"demo".as_slice(), 0o644),
            ("alias", b"safe".as_slice(), 0o120777),
            ("alias/escaped.txt", b"escape".as_slice(), 0o644),
        ])?;
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join("tree");
        fs::create_dir_all(&destination)?;

        let err = extract_zip_tree(
            Cursor::new(archive),
            &destination,
            ArchiveExtractionLimits::default(),
        )
        .expect_err("zip regular file under symlink ancestor must be rejected");

        assert!(
            err.to_string().contains("symlink ancestor"),
            "unexpected error: {err}"
        );
        assert!(!destination.join("safe/escaped.txt").exists());
        Ok(())
    }
}
