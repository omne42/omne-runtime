use std::fmt;
use std::io::{Read, Seek};
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use tar::Archive as TarArchive;
use xz2::read::XzDecoder;
use zip::ZipArchive;

use crate::binary_archive::BinaryArchiveFormat;

pub const DEFAULT_MAX_ARCHIVE_TREE_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_MAX_ARCHIVE_TREE_ENTRIES: u64 = 65_536;
pub const MAX_ZIP_SYMLINK_TARGET_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct ArchiveTreeExtractionLimits {
    pub max_extracted_bytes: u64,
    pub max_entries: u64,
}

impl Default for ArchiveTreeExtractionLimits {
    fn default() -> Self {
        Self {
            max_extracted_bytes: DEFAULT_MAX_ARCHIVE_TREE_EXTRACTED_BYTES,
            max_entries: DEFAULT_MAX_ARCHIVE_TREE_ENTRIES,
        }
    }
}

pub trait ArchiveTreeVisitor {
    type Error;

    fn visit_directory(&mut self, path: &Path) -> Result<(), Self::Error>;

    fn visit_regular_file<R: Read>(
        &mut self,
        path: &Path,
        reader: &mut R,
        unix_mode: Option<u32>,
    ) -> Result<(), Self::Error>;

    fn visit_symlink(&mut self, path: &Path, target: &Path) -> Result<(), Self::Error>;

    fn visit_hard_link(&mut self, path: &Path, target: &Path) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum WalkArchiveTreeError<E> {
    UnsupportedArchiveType {
        asset_name: String,
    },
    ArchiveRead {
        archive_format: BinaryArchiveFormat,
        stage: &'static str,
        detail: String,
    },
    InvalidArchivePath {
        archive_format: BinaryArchiveFormat,
        archive_path: String,
        detail: String,
    },
    UnsupportedArchiveEntry {
        archive_format: BinaryArchiveFormat,
        archive_path: String,
        detail: String,
    },
    ExtractionBudgetExceeded {
        archive_format: BinaryArchiveFormat,
        archive_path: String,
        limit_bytes: u64,
    },
    ArchiveEntryBudgetExceeded {
        archive_format: BinaryArchiveFormat,
        archive_path: String,
        limit_entries: u64,
    },
    Visitor(E),
}

impl<E> WalkArchiveTreeError<E> {
    fn archive_read(
        archive_format: BinaryArchiveFormat,
        stage: &'static str,
        detail: impl Into<String>,
    ) -> Self {
        Self::ArchiveRead {
            archive_format,
            stage,
            detail: detail.into(),
        }
    }

    fn invalid_archive_path(
        archive_format: BinaryArchiveFormat,
        archive_path: &Path,
        detail: impl Into<String>,
    ) -> Self {
        Self::InvalidArchivePath {
            archive_format,
            archive_path: archive_path.display().to_string(),
            detail: detail.into(),
        }
    }

    fn unsupported_archive_entry(
        archive_format: BinaryArchiveFormat,
        archive_path: &Path,
        detail: impl Into<String>,
    ) -> Self {
        Self::UnsupportedArchiveEntry {
            archive_format,
            archive_path: archive_path.display().to_string(),
            detail: detail.into(),
        }
    }
}

impl<E> fmt::Display for WalkArchiveTreeError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArchiveType { asset_name } => {
                write!(f, "unsupported archive type for `{asset_name}`")
            }
            Self::ArchiveRead {
                archive_format,
                stage,
                detail,
            } => write!(
                f,
                "{archive_format} archive read failed during {stage}: {detail}"
            ),
            Self::InvalidArchivePath {
                archive_format,
                archive_path,
                detail,
            } => write!(
                f,
                "{archive_format} archive entry `{archive_path}` is invalid: {detail}"
            ),
            Self::UnsupportedArchiveEntry {
                archive_format,
                archive_path,
                detail,
            } => write!(
                f,
                "{archive_format} archive entry `{archive_path}` is unsupported: {detail}"
            ),
            Self::ExtractionBudgetExceeded {
                archive_format,
                archive_path,
                limit_bytes,
            } => write!(
                f,
                "{archive_format} archive extracted bytes exceed limit of {limit_bytes} while visiting `{archive_path}`"
            ),
            Self::ArchiveEntryBudgetExceeded {
                archive_format,
                archive_path,
                limit_entries,
            } => write!(
                f,
                "{archive_format} archive entry count exceeds limit of {limit_entries} while visiting `{archive_path}`"
            ),
            Self::Visitor(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl<E> std::error::Error for WalkArchiveTreeError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Visitor(error) => Some(error),
            _ => None,
        }
    }
}

pub fn walk_archive_tree<R, V>(
    asset_name: &str,
    reader: R,
    limits: ArchiveTreeExtractionLimits,
    visitor: &mut V,
) -> Result<(), WalkArchiveTreeError<V::Error>>
where
    R: Read + Seek,
    V: ArchiveTreeVisitor,
{
    let archive_format = BinaryArchiveFormat::from_asset_name(asset_name).ok_or_else(|| {
        WalkArchiveTreeError::UnsupportedArchiveType {
            asset_name: asset_name.to_string(),
        }
    })?;

    match archive_format {
        BinaryArchiveFormat::TarGz => {
            walk_tar_tree(archive_format, GzDecoder::new(reader), limits, visitor)
        }
        BinaryArchiveFormat::TarXz => {
            walk_tar_tree(archive_format, XzDecoder::new(reader), limits, visitor)
        }
        BinaryArchiveFormat::Zip => walk_zip_tree(archive_format, reader, limits, visitor),
    }
}

pub fn walk_tar_archive_tree<R, V>(
    reader: R,
    limits: ArchiveTreeExtractionLimits,
    visitor: &mut V,
) -> Result<(), WalkArchiveTreeError<V::Error>>
where
    R: Read,
    V: ArchiveTreeVisitor,
{
    walk_tar_tree(BinaryArchiveFormat::TarGz, reader, limits, visitor)
}

pub fn walk_zip_archive_tree<R, V>(
    reader: R,
    limits: ArchiveTreeExtractionLimits,
    visitor: &mut V,
) -> Result<(), WalkArchiveTreeError<V::Error>>
where
    R: Read + Seek,
    V: ArchiveTreeVisitor,
{
    walk_zip_tree(BinaryArchiveFormat::Zip, reader, limits, visitor)
}

fn walk_zip_tree<R, V>(
    archive_format: BinaryArchiveFormat,
    reader: R,
    limits: ArchiveTreeExtractionLimits,
    visitor: &mut V,
) -> Result<(), WalkArchiveTreeError<V::Error>>
where
    R: Read + Seek,
    V: ArchiveTreeVisitor,
{
    let mut budget = ArchiveTreeBudget::new(archive_format, limits);
    let mut archive = ZipArchive::new(reader).map_err(|err| {
        WalkArchiveTreeError::archive_read(archive_format, "open", err.to_string())
    })?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|err| {
            WalkArchiveTreeError::archive_read(archive_format, "read_entry", err.to_string())
        })?;
        let enclosed = entry.enclosed_name().ok_or_else(|| {
            WalkArchiveTreeError::invalid_archive_path(
                archive_format,
                Path::new(&format!("#{index}")),
                "path escapes archive root",
            )
        })?;
        let enclosed = sanitize_archive_path(archive_format, enclosed)?;
        budget.record_entry(&enclosed)?;
        if entry.is_dir() {
            visitor
                .visit_directory(&enclosed)
                .map_err(WalkArchiveTreeError::Visitor)?;
            continue;
        }
        if zip_entry_is_symlink(&entry) {
            budget.reserve_bytes(&enclosed, entry.size())?;
            let link_target = read_zip_symlink_target(archive_format, &enclosed, &mut entry)?;
            visitor
                .visit_symlink(&enclosed, &link_target)
                .map_err(WalkArchiveTreeError::Visitor)?;
            continue;
        }

        budget.reserve_bytes(&enclosed, entry.size())?;
        let unix_mode = zip_entry_unix_mode(&entry);
        visitor
            .visit_regular_file(&enclosed, &mut entry, unix_mode)
            .map_err(WalkArchiveTreeError::Visitor)?;
    }
    Ok(())
}

fn walk_tar_tree<R, V>(
    archive_format: BinaryArchiveFormat,
    reader: R,
    limits: ArchiveTreeExtractionLimits,
    visitor: &mut V,
) -> Result<(), WalkArchiveTreeError<V::Error>>
where
    R: Read,
    V: ArchiveTreeVisitor,
{
    let mut budget = ArchiveTreeBudget::new(archive_format, limits);
    let mut archive = TarArchive::new(reader);
    let entries = archive.entries().map_err(|err| {
        WalkArchiveTreeError::archive_read(archive_format, "entries", err.to_string())
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|err| {
            WalkArchiveTreeError::archive_read(archive_format, "read_entry", err.to_string())
        })?;
        let path = entry.path().map_err(|err| {
            WalkArchiveTreeError::archive_read(archive_format, "entry_path", err.to_string())
        })?;
        let path = path.into_owned();
        let sanitized = sanitize_archive_path(archive_format, &path)?;
        budget.record_entry(&sanitized)?;
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            visitor
                .visit_directory(&sanitized)
                .map_err(WalkArchiveTreeError::Visitor)?;
            continue;
        }
        if entry_type.is_file() {
            budget.reserve_bytes(&sanitized, entry.size())?;
            let unix_mode = tar_entry_unix_mode(archive_format, &entry)?;
            visitor
                .visit_regular_file(&sanitized, &mut entry, unix_mode)
                .map_err(WalkArchiveTreeError::Visitor)?;
            continue;
        }
        if entry_type.is_symlink() {
            let link_target = entry.link_name().map_err(|err| {
                WalkArchiveTreeError::archive_read(
                    archive_format,
                    "symlink_target",
                    err.to_string(),
                )
            })?;
            let link_target = link_target.ok_or_else(|| {
                WalkArchiveTreeError::unsupported_archive_entry(
                    archive_format,
                    &sanitized,
                    "missing symlink target",
                )
            })?;
            visitor
                .visit_symlink(&sanitized, &link_target)
                .map_err(WalkArchiveTreeError::Visitor)?;
            continue;
        }
        if entry_type.is_hard_link() {
            let link_target = entry.link_name().map_err(|err| {
                WalkArchiveTreeError::archive_read(
                    archive_format,
                    "hard_link_target",
                    err.to_string(),
                )
            })?;
            let link_target = link_target.ok_or_else(|| {
                WalkArchiveTreeError::unsupported_archive_entry(
                    archive_format,
                    &sanitized,
                    "missing hard link target",
                )
            })?;
            visitor
                .visit_hard_link(&sanitized, &link_target)
                .map_err(WalkArchiveTreeError::Visitor)?;
            continue;
        }

        return Err(WalkArchiveTreeError::unsupported_archive_entry(
            archive_format,
            &sanitized,
            format!("entry type `{entry_type:?}`"),
        ));
    }
    Ok(())
}

fn sanitize_archive_path<E>(
    archive_format: BinaryArchiveFormat,
    path: &Path,
) -> Result<PathBuf, WalkArchiveTreeError<E>> {
    let mut sanitized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => sanitized.push(part),
            Component::CurDir => {}
            _ => {
                return Err(WalkArchiveTreeError::invalid_archive_path(
                    archive_format,
                    path,
                    "path must stay within the archive root",
                ));
            }
        }
    }
    if sanitized.as_os_str().is_empty() {
        return Err(WalkArchiveTreeError::invalid_archive_path(
            archive_format,
            path,
            "path must not be empty",
        ));
    }
    Ok(sanitized)
}

fn zip_entry_unix_mode(entry: &zip::read::ZipFile<'_>) -> Option<u32> {
    entry.unix_mode().map(sanitize_unix_mode)
}

fn zip_entry_is_symlink(entry: &zip::read::ZipFile<'_>) -> bool {
    entry
        .unix_mode()
        .is_some_and(|mode| (mode & 0o170000) == 0o120000)
}

#[cfg(unix)]
fn read_zip_symlink_target<E>(
    archive_format: BinaryArchiveFormat,
    archive_path: &Path,
    entry: &mut zip::read::ZipFile<'_>,
) -> Result<PathBuf, WalkArchiveTreeError<E>> {
    let mut target = Vec::new();
    entry
        .take(
            u64::try_from(MAX_ZIP_SYMLINK_TARGET_BYTES)
                .unwrap_or(u64::MAX)
                .saturating_add(1),
        )
        .read_to_end(&mut target)
        .map_err(|err| {
            WalkArchiveTreeError::archive_read(
                archive_format,
                "zip_symlink_target",
                err.to_string(),
            )
        })?;
    if target.len() > MAX_ZIP_SYMLINK_TARGET_BYTES {
        return Err(WalkArchiveTreeError::unsupported_archive_entry(
            archive_format,
            archive_path,
            format!("zip symlink target exceeds limit of {MAX_ZIP_SYMLINK_TARGET_BYTES} bytes"),
        ));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_vec(target)))
}

#[cfg(not(unix))]
fn read_zip_symlink_target<E>(
    archive_format: BinaryArchiveFormat,
    archive_path: &Path,
    entry: &mut zip::read::ZipFile<'_>,
) -> Result<PathBuf, WalkArchiveTreeError<E>> {
    let _ = entry;
    Err(WalkArchiveTreeError::unsupported_archive_entry(
        archive_format,
        archive_path,
        "zip symlink entries are not supported on this platform",
    ))
}

fn tar_entry_unix_mode<R, E>(
    archive_format: BinaryArchiveFormat,
    entry: &tar::Entry<'_, R>,
) -> Result<Option<u32>, WalkArchiveTreeError<E>>
where
    R: Read,
{
    #[cfg(unix)]
    {
        entry
            .header()
            .mode()
            .map(|mode| Some(sanitize_unix_mode(mode)))
            .map_err(|err| {
                WalkArchiveTreeError::archive_read(archive_format, "tar_mode", err.to_string())
            })
    }
    #[cfg(not(unix))]
    {
        let _ = archive_format;
        let _ = entry;
        Ok(None)
    }
}

fn sanitize_unix_mode(mode: u32) -> u32 {
    mode & 0o777
}

struct ArchiveTreeBudget {
    archive_format: BinaryArchiveFormat,
    limits: ArchiveTreeExtractionLimits,
    extracted_bytes: u64,
    entries: u64,
}

impl ArchiveTreeBudget {
    fn new(archive_format: BinaryArchiveFormat, limits: ArchiveTreeExtractionLimits) -> Self {
        Self {
            archive_format,
            limits,
            extracted_bytes: 0,
            entries: 0,
        }
    }

    fn record_entry<E>(&mut self, path: &Path) -> Result<(), WalkArchiveTreeError<E>> {
        self.entries = self.entries.saturating_add(1);
        if self.entries > self.limits.max_entries {
            return Err(WalkArchiveTreeError::ArchiveEntryBudgetExceeded {
                archive_format: self.archive_format,
                archive_path: path.display().to_string(),
                limit_entries: self.limits.max_entries,
            });
        }
        Ok(())
    }

    fn reserve_bytes<E>(&mut self, path: &Path, bytes: u64) -> Result<(), WalkArchiveTreeError<E>> {
        self.extracted_bytes = self.extracted_bytes.checked_add(bytes).ok_or_else(|| {
            WalkArchiveTreeError::ExtractionBudgetExceeded {
                archive_format: self.archive_format,
                archive_path: path.display().to_string(),
                limit_bytes: self.limits.max_extracted_bytes,
            }
        })?;
        if self.extracted_bytes > self.limits.max_extracted_bytes {
            return Err(WalkArchiveTreeError::ExtractionBudgetExceeded {
                archive_format: self.archive_format,
                archive_path: path.display().to_string(),
                limit_bytes: self.limits.max_extracted_bytes,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_escape_paths() {
        let err =
            sanitize_archive_path::<()>(BinaryArchiveFormat::TarGz, Path::new("../etc/passwd"))
                .expect_err("escape path should fail");
        assert!(format!("{err:?}").contains("within the archive root"));
    }

    #[test]
    fn accepts_normalized_paths() {
        let path = sanitize_archive_path::<()>(BinaryArchiveFormat::Zip, Path::new("./bin/tool"))
            .expect("normalized path");
        assert_eq!(path, PathBuf::from("bin/tool"));
    }
}
