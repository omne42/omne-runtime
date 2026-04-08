use std::fmt;
use std::io::{Cursor, Read, Seek, Write};

pub const DEFAULT_MAX_EXTRACTED_BINARY_BYTES: u64 = 256 * 1024 * 1024;
pub const DEFAULT_MAX_ARCHIVE_SCAN_ENTRIES: u64 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryArchiveFormat {
    TarGz,
    TarXz,
    Zip,
}

impl BinaryArchiveFormat {
    pub fn from_asset_name(asset_name: &str) -> Option<Self> {
        if asset_name.ends_with(".tar.gz") {
            Some(Self::TarGz)
        } else if asset_name.ends_with(".tar.xz") {
            Some(Self::TarXz)
        } else if asset_name.ends_with(".zip") {
            Some(Self::Zip)
        } else {
            None
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::TarGz => "tar.gz",
            Self::TarXz => "tar.xz",
            Self::Zip => "zip",
        }
    }
}

impl fmt::Display for BinaryArchiveFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

pub fn is_binary_archive_asset_name(asset_name: &str) -> bool {
    BinaryArchiveFormat::from_asset_name(asset_name).is_some()
}

#[derive(Debug, Clone, Copy)]
pub struct BinaryArchiveRequest<'a> {
    pub binary_name: &'a str,
    /// Exact archive-relative path to the desired binary, normalized with `/`.
    pub archive_binary_hint: Option<&'a str>,
}

impl<'a> BinaryArchiveRequest<'a> {
    pub const fn new(binary_name: &'a str) -> Self {
        Self {
            binary_name,
            archive_binary_hint: None,
        }
    }

    pub const fn with_archive_binary_hint(self, archive_binary_hint: Option<&'a str>) -> Self {
        Self {
            binary_name: self.binary_name,
            archive_binary_hint,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedArchiveBinary {
    pub archive_path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveBinaryMatch {
    pub archive_format: BinaryArchiveFormat,
    pub archive_path: String,
}

#[derive(Debug)]
pub enum ExtractBinaryFromArchiveError {
    UnsupportedArchiveType {
        asset_name: String,
    },
    ArchiveRead {
        archive_format: BinaryArchiveFormat,
        stage: &'static str,
        detail: String,
    },
    BinaryNotFound {
        archive_format: BinaryArchiveFormat,
        binary_name: String,
    },
    AmbiguousBinaryMatches {
        archive_format: BinaryArchiveFormat,
        binary_name: String,
        first_archive_path: String,
        second_archive_path: String,
    },
    MatchedEntryNotRegularFile {
        archive_format: BinaryArchiveFormat,
        archive_path: String,
    },
    ExtractionBudgetExceeded {
        archive_format: BinaryArchiveFormat,
        archive_path: String,
        limit_bytes: u64,
    },
    ArchiveScanBudgetExceeded {
        archive_format: BinaryArchiveFormat,
        limit_entries: u64,
    },
}

impl ExtractBinaryFromArchiveError {
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
}

impl fmt::Display for ExtractBinaryFromArchiveError {
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
            Self::BinaryNotFound {
                archive_format,
                binary_name,
            } => write!(
                f,
                "binary `{binary_name}` not found in {archive_format} archive"
            ),
            Self::AmbiguousBinaryMatches {
                archive_format,
                binary_name,
                first_archive_path,
                second_archive_path,
            } => write!(
                f,
                "binary `{binary_name}` is ambiguous in {archive_format} archive: matched both `{first_archive_path}` and `{second_archive_path}`; provide an exact archive_binary_hint"
            ),
            Self::MatchedEntryNotRegularFile {
                archive_format,
                archive_path,
            } => write!(
                f,
                "matched archive entry `{archive_path}` in {archive_format} archive is not a regular file"
            ),
            Self::ExtractionBudgetExceeded {
                archive_format,
                archive_path,
                limit_bytes,
            } => write!(
                f,
                "matched archive entry `{archive_path}` in {archive_format} archive exceeds extraction budget of {limit_bytes} bytes"
            ),
            Self::ArchiveScanBudgetExceeded {
                archive_format,
                limit_entries,
            } => write!(
                f,
                "{archive_format} archive scan exceeds entry budget of {limit_entries} entries before locating the requested binary"
            ),
        }
    }
}

impl std::error::Error for ExtractBinaryFromArchiveError {}

pub fn extract_binary_from_archive(
    asset_name: &str,
    content: &[u8],
    request: &BinaryArchiveRequest<'_>,
) -> Result<ExtractedArchiveBinary, ExtractBinaryFromArchiveError> {
    extract_binary_from_archive_reader(asset_name, Cursor::new(content), request)
}

fn extract_binary_from_archive_reader<R>(
    asset_name: &str,
    reader: R,
    request: &BinaryArchiveRequest<'_>,
) -> Result<ExtractedArchiveBinary, ExtractBinaryFromArchiveError>
where
    R: Read + Seek,
{
    extract_binary_from_archive_reader_with_limit(
        asset_name,
        reader,
        request,
        DEFAULT_MAX_EXTRACTED_BINARY_BYTES,
    )
}

fn extract_binary_from_archive_reader_with_limit<R>(
    asset_name: &str,
    reader: R,
    request: &BinaryArchiveRequest<'_>,
    max_entry_bytes: u64,
) -> Result<ExtractedArchiveBinary, ExtractBinaryFromArchiveError>
where
    R: Read + Seek,
{
    extract_binary_from_archive_reader_with_limits(
        asset_name,
        reader,
        request,
        max_entry_bytes,
        DEFAULT_MAX_ARCHIVE_SCAN_ENTRIES,
    )
}

fn extract_binary_from_archive_reader_with_limits<R>(
    asset_name: &str,
    reader: R,
    request: &BinaryArchiveRequest<'_>,
    max_entry_bytes: u64,
    max_scan_entries: u64,
) -> Result<ExtractedArchiveBinary, ExtractBinaryFromArchiveError>
where
    R: Read + Seek,
{
    let archive_format = BinaryArchiveFormat::from_asset_name(asset_name).ok_or_else(|| {
        ExtractBinaryFromArchiveError::UnsupportedArchiveType {
            asset_name: asset_name.to_string(),
        }
    })?;

    match archive_format {
        BinaryArchiveFormat::TarGz => {
            extract_from_tar_gz(reader, request, max_entry_bytes, max_scan_entries)
        }
        BinaryArchiveFormat::TarXz => {
            extract_from_tar_xz(reader, request, max_entry_bytes, max_scan_entries)
        }
        BinaryArchiveFormat::Zip => {
            extract_from_zip(reader, request, max_entry_bytes, max_scan_entries)
        }
    }
}

pub fn extract_binary_from_archive_reader_to_writer<R, W>(
    asset_name: &str,
    reader: R,
    request: &BinaryArchiveRequest<'_>,
    writer: &mut W,
) -> Result<ArchiveBinaryMatch, ExtractBinaryFromArchiveError>
where
    R: Read + Seek,
    W: Write + ?Sized,
{
    extract_binary_from_archive_reader_to_writer_with_limit(
        asset_name,
        reader,
        request,
        writer,
        DEFAULT_MAX_EXTRACTED_BINARY_BYTES,
    )
}

fn extract_binary_from_archive_reader_to_writer_with_limit<R, W>(
    asset_name: &str,
    reader: R,
    request: &BinaryArchiveRequest<'_>,
    writer: &mut W,
    max_entry_bytes: u64,
) -> Result<ArchiveBinaryMatch, ExtractBinaryFromArchiveError>
where
    R: Read + Seek,
    W: Write + ?Sized,
{
    extract_binary_from_archive_reader_to_writer_with_limits(
        asset_name,
        reader,
        request,
        writer,
        max_entry_bytes,
        DEFAULT_MAX_ARCHIVE_SCAN_ENTRIES,
    )
}

fn extract_binary_from_archive_reader_to_writer_with_limits<R, W>(
    asset_name: &str,
    reader: R,
    request: &BinaryArchiveRequest<'_>,
    writer: &mut W,
    max_entry_bytes: u64,
    max_scan_entries: u64,
) -> Result<ArchiveBinaryMatch, ExtractBinaryFromArchiveError>
where
    R: Read + Seek,
    W: Write + ?Sized,
{
    let archive_format = BinaryArchiveFormat::from_asset_name(asset_name).ok_or_else(|| {
        ExtractBinaryFromArchiveError::UnsupportedArchiveType {
            asset_name: asset_name.to_string(),
        }
    })?;

    match archive_format {
        BinaryArchiveFormat::TarGz => extract_from_tar_gz_to_writer(
            reader,
            request,
            writer,
            max_entry_bytes,
            max_scan_entries,
        ),
        BinaryArchiveFormat::TarXz => extract_from_tar_xz_to_writer(
            reader,
            request,
            writer,
            max_entry_bytes,
            max_scan_entries,
        ),
        BinaryArchiveFormat::Zip => {
            extract_from_zip_to_writer(reader, request, writer, max_entry_bytes, max_scan_entries)
        }
    }
}

fn extract_from_tar_gz<R>(
    reader: R,
    request: &BinaryArchiveRequest<'_>,
    max_entry_bytes: u64,
    max_scan_entries: u64,
) -> Result<ExtractedArchiveBinary, ExtractBinaryFromArchiveError>
where
    R: Read,
{
    let archive_format = BinaryArchiveFormat::TarGz;
    let mut scan_budget = ArchiveScanBudget::new(archive_format, max_scan_entries);
    let normalized_hint = normalize_archive_binary_hint(request.archive_binary_hint);
    let mut pending_match = None;
    let decoder = flate2::read::GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|err| {
        ExtractBinaryFromArchiveError::archive_read(archive_format, "read_entries", err.to_string())
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|err| {
            ExtractBinaryFromArchiveError::archive_read(
                archive_format,
                "read_entry",
                err.to_string(),
            )
        })?;
        scan_budget.record_entry()?;
        let path = entry
            .path()
            .map_err(|err| {
                ExtractBinaryFromArchiveError::archive_read(
                    archive_format,
                    "read_entry_path",
                    err.to_string(),
                )
            })?
            .to_string_lossy()
            .replace('\\', "/");
        if let Some(hint) = normalized_hint.as_deref() {
            if path == hint {
                ensure_tar_entry_is_regular_file(
                    archive_format,
                    &path,
                    entry.header().entry_type(),
                )?;
                return read_matched_entry(archive_format, path, &mut entry, max_entry_bytes);
            }
            continue;
        }
        if is_binary_entry_match_without_hint(&path, request.binary_name) {
            ensure_tar_entry_is_regular_file(archive_format, &path, entry.header().entry_type())?;
            record_buffered_match(
                &mut pending_match,
                read_matched_entry(archive_format, path, &mut entry, max_entry_bytes)?,
                archive_format,
                request.binary_name,
            )?;
        }
    }
    finish_buffered_match(pending_match, archive_format, request.binary_name)
}

fn extract_from_tar_gz_to_writer<R, W>(
    reader: R,
    request: &BinaryArchiveRequest<'_>,
    writer: &mut W,
    max_entry_bytes: u64,
    max_scan_entries: u64,
) -> Result<ArchiveBinaryMatch, ExtractBinaryFromArchiveError>
where
    R: Read,
    W: Write + ?Sized,
{
    let archive_format = BinaryArchiveFormat::TarGz;
    let mut scan_budget = ArchiveScanBudget::new(archive_format, max_scan_entries);
    let normalized_hint = normalize_archive_binary_hint(request.archive_binary_hint);
    let mut pending_match = None;
    let decoder = flate2::read::GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|err| {
        ExtractBinaryFromArchiveError::archive_read(archive_format, "read_entries", err.to_string())
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|err| {
            ExtractBinaryFromArchiveError::archive_read(
                archive_format,
                "read_entry",
                err.to_string(),
            )
        })?;
        scan_budget.record_entry()?;
        let path = entry
            .path()
            .map_err(|err| {
                ExtractBinaryFromArchiveError::archive_read(
                    archive_format,
                    "read_entry_path",
                    err.to_string(),
                )
            })?
            .to_string_lossy()
            .replace('\\', "/");
        if let Some(hint) = normalized_hint.as_deref() {
            if path == hint {
                ensure_tar_entry_is_regular_file(
                    archive_format,
                    &path,
                    entry.header().entry_type(),
                )?;
                return write_matched_entry(
                    archive_format,
                    path,
                    &mut entry,
                    writer,
                    max_entry_bytes,
                );
            }
            continue;
        }
        if is_binary_entry_match_without_hint(&path, request.binary_name) {
            ensure_tar_entry_is_regular_file(archive_format, &path, entry.header().entry_type())?;
            record_buffered_match(
                &mut pending_match,
                read_matched_entry(archive_format, path, &mut entry, max_entry_bytes)?,
                archive_format,
                request.binary_name,
            )?;
        }
    }
    write_buffered_match(
        writer,
        finish_buffered_match(pending_match, archive_format, request.binary_name)?,
        archive_format,
    )
}

fn extract_from_tar_xz<R>(
    reader: R,
    request: &BinaryArchiveRequest<'_>,
    max_entry_bytes: u64,
    max_scan_entries: u64,
) -> Result<ExtractedArchiveBinary, ExtractBinaryFromArchiveError>
where
    R: Read,
{
    let archive_format = BinaryArchiveFormat::TarXz;
    let mut scan_budget = ArchiveScanBudget::new(archive_format, max_scan_entries);
    let normalized_hint = normalize_archive_binary_hint(request.archive_binary_hint);
    let mut pending_match = None;
    let decoder = xz2::read::XzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|err| {
        ExtractBinaryFromArchiveError::archive_read(archive_format, "read_entries", err.to_string())
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|err| {
            ExtractBinaryFromArchiveError::archive_read(
                archive_format,
                "read_entry",
                err.to_string(),
            )
        })?;
        scan_budget.record_entry()?;
        let path = entry
            .path()
            .map_err(|err| {
                ExtractBinaryFromArchiveError::archive_read(
                    archive_format,
                    "read_entry_path",
                    err.to_string(),
                )
            })?
            .to_string_lossy()
            .replace('\\', "/");
        if let Some(hint) = normalized_hint.as_deref() {
            if path == hint {
                ensure_tar_entry_is_regular_file(
                    archive_format,
                    &path,
                    entry.header().entry_type(),
                )?;
                return read_matched_entry(archive_format, path, &mut entry, max_entry_bytes);
            }
            continue;
        }
        if is_binary_entry_match_without_hint(&path, request.binary_name) {
            ensure_tar_entry_is_regular_file(archive_format, &path, entry.header().entry_type())?;
            record_buffered_match(
                &mut pending_match,
                read_matched_entry(archive_format, path, &mut entry, max_entry_bytes)?,
                archive_format,
                request.binary_name,
            )?;
        }
    }
    finish_buffered_match(pending_match, archive_format, request.binary_name)
}

fn extract_from_tar_xz_to_writer<R, W>(
    reader: R,
    request: &BinaryArchiveRequest<'_>,
    writer: &mut W,
    max_entry_bytes: u64,
    max_scan_entries: u64,
) -> Result<ArchiveBinaryMatch, ExtractBinaryFromArchiveError>
where
    R: Read,
    W: Write + ?Sized,
{
    let archive_format = BinaryArchiveFormat::TarXz;
    let mut scan_budget = ArchiveScanBudget::new(archive_format, max_scan_entries);
    let normalized_hint = normalize_archive_binary_hint(request.archive_binary_hint);
    let mut pending_match = None;
    let decoder = xz2::read::XzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);
    let entries = archive.entries().map_err(|err| {
        ExtractBinaryFromArchiveError::archive_read(archive_format, "read_entries", err.to_string())
    })?;
    for entry in entries {
        let mut entry = entry.map_err(|err| {
            ExtractBinaryFromArchiveError::archive_read(
                archive_format,
                "read_entry",
                err.to_string(),
            )
        })?;
        scan_budget.record_entry()?;
        let path = entry
            .path()
            .map_err(|err| {
                ExtractBinaryFromArchiveError::archive_read(
                    archive_format,
                    "read_entry_path",
                    err.to_string(),
                )
            })?
            .to_string_lossy()
            .replace('\\', "/");
        if let Some(hint) = normalized_hint.as_deref() {
            if path == hint {
                ensure_tar_entry_is_regular_file(
                    archive_format,
                    &path,
                    entry.header().entry_type(),
                )?;
                return write_matched_entry(
                    archive_format,
                    path,
                    &mut entry,
                    writer,
                    max_entry_bytes,
                );
            }
            continue;
        }
        if is_binary_entry_match_without_hint(&path, request.binary_name) {
            ensure_tar_entry_is_regular_file(archive_format, &path, entry.header().entry_type())?;
            record_buffered_match(
                &mut pending_match,
                read_matched_entry(archive_format, path, &mut entry, max_entry_bytes)?,
                archive_format,
                request.binary_name,
            )?;
        }
    }
    write_buffered_match(
        writer,
        finish_buffered_match(pending_match, archive_format, request.binary_name)?,
        archive_format,
    )
}

fn extract_from_zip<R>(
    reader: R,
    request: &BinaryArchiveRequest<'_>,
    max_entry_bytes: u64,
    max_scan_entries: u64,
) -> Result<ExtractedArchiveBinary, ExtractBinaryFromArchiveError>
where
    R: Read + Seek,
{
    let archive_format = BinaryArchiveFormat::Zip;
    let mut scan_budget = ArchiveScanBudget::new(archive_format, max_scan_entries);
    let normalized_hint = normalize_archive_binary_hint(request.archive_binary_hint);
    let mut pending_match = None;
    let mut archive = zip::ZipArchive::new(reader).map_err(|err| {
        ExtractBinaryFromArchiveError::archive_read(archive_format, "open_archive", err.to_string())
    })?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|err| {
            ExtractBinaryFromArchiveError::archive_read(
                archive_format,
                "read_entry",
                format!("entry #{index}: {err}"),
            )
        })?;
        scan_budget.record_entry()?;
        let path = entry.name().replace('\\', "/");
        if let Some(hint) = normalized_hint.as_deref() {
            if path == hint {
                ensure_zip_entry_is_regular_file(archive_format, &path, &entry)?;
                return read_matched_entry(archive_format, path, &mut entry, max_entry_bytes);
            }
            continue;
        }
        if is_binary_entry_match_without_hint(&path, request.binary_name) {
            ensure_zip_entry_is_regular_file(archive_format, &path, &entry)?;
            record_buffered_match(
                &mut pending_match,
                read_matched_entry(archive_format, path, &mut entry, max_entry_bytes)?,
                archive_format,
                request.binary_name,
            )?;
        }
        if entry.is_dir() {
            continue;
        }
    }
    finish_buffered_match(pending_match, archive_format, request.binary_name)
}

fn extract_from_zip_to_writer<R, W>(
    reader: R,
    request: &BinaryArchiveRequest<'_>,
    writer: &mut W,
    max_entry_bytes: u64,
    max_scan_entries: u64,
) -> Result<ArchiveBinaryMatch, ExtractBinaryFromArchiveError>
where
    R: Read + Seek,
    W: Write + ?Sized,
{
    let archive_format = BinaryArchiveFormat::Zip;
    let mut scan_budget = ArchiveScanBudget::new(archive_format, max_scan_entries);
    let normalized_hint = normalize_archive_binary_hint(request.archive_binary_hint);
    let mut pending_match = None;
    let mut archive = zip::ZipArchive::new(reader).map_err(|err| {
        ExtractBinaryFromArchiveError::archive_read(archive_format, "open_archive", err.to_string())
    })?;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index).map_err(|err| {
            ExtractBinaryFromArchiveError::archive_read(
                archive_format,
                "read_entry",
                format!("entry #{index}: {err}"),
            )
        })?;
        scan_budget.record_entry()?;
        let path = entry.name().replace('\\', "/");
        if let Some(hint) = normalized_hint.as_deref() {
            if path == hint {
                ensure_zip_entry_is_regular_file(archive_format, &path, &entry)?;
                return write_matched_entry(
                    archive_format,
                    path,
                    &mut entry,
                    writer,
                    max_entry_bytes,
                );
            }
            continue;
        }
        if is_binary_entry_match_without_hint(&path, request.binary_name) {
            ensure_zip_entry_is_regular_file(archive_format, &path, &entry)?;
            record_buffered_match(
                &mut pending_match,
                read_matched_entry(archive_format, path, &mut entry, max_entry_bytes)?,
                archive_format,
                request.binary_name,
            )?;
        }
        if entry.is_dir() {
            continue;
        }
    }
    write_buffered_match(
        writer,
        finish_buffered_match(pending_match, archive_format, request.binary_name)?,
        archive_format,
    )
}

fn read_matched_entry<R>(
    archive_format: BinaryArchiveFormat,
    archive_path: String,
    reader: &mut R,
    max_entry_bytes: u64,
) -> Result<ExtractedArchiveBinary, ExtractBinaryFromArchiveError>
where
    R: Read,
{
    let mut bytes = Vec::new();
    write_matched_entry(
        archive_format,
        archive_path.clone(),
        reader,
        &mut bytes,
        max_entry_bytes,
    )?;
    Ok(ExtractedArchiveBinary {
        archive_path,
        bytes,
    })
}

fn write_matched_entry<R, W>(
    archive_format: BinaryArchiveFormat,
    archive_path: String,
    reader: &mut R,
    writer: &mut W,
    max_entry_bytes: u64,
) -> Result<ArchiveBinaryMatch, ExtractBinaryFromArchiveError>
where
    R: Read,
    W: Write + ?Sized,
{
    copy_entry_with_limit(
        reader,
        writer,
        archive_format,
        &archive_path,
        max_entry_bytes,
    )?;
    Ok(ArchiveBinaryMatch {
        archive_format,
        archive_path,
    })
}

fn record_buffered_match(
    pending_match: &mut Option<ExtractedArchiveBinary>,
    candidate: ExtractedArchiveBinary,
    archive_format: BinaryArchiveFormat,
    binary_name: &str,
) -> Result<(), ExtractBinaryFromArchiveError> {
    if let Some(first_match) = pending_match {
        return Err(ExtractBinaryFromArchiveError::AmbiguousBinaryMatches {
            archive_format,
            binary_name: binary_name.to_string(),
            first_archive_path: first_match.archive_path.clone(),
            second_archive_path: candidate.archive_path,
        });
    }

    *pending_match = Some(candidate);
    Ok(())
}

fn finish_buffered_match(
    pending_match: Option<ExtractedArchiveBinary>,
    archive_format: BinaryArchiveFormat,
    binary_name: &str,
) -> Result<ExtractedArchiveBinary, ExtractBinaryFromArchiveError> {
    pending_match.ok_or_else(|| ExtractBinaryFromArchiveError::BinaryNotFound {
        archive_format,
        binary_name: binary_name.to_string(),
    })
}

fn write_buffered_match<W>(
    writer: &mut W,
    buffered_match: ExtractedArchiveBinary,
    archive_format: BinaryArchiveFormat,
) -> Result<ArchiveBinaryMatch, ExtractBinaryFromArchiveError>
where
    W: Write + ?Sized,
{
    writer
        .write_all(&buffered_match.bytes)
        .map_err(|err| {
            ExtractBinaryFromArchiveError::archive_read(
                archive_format,
                "write_entry_content",
                format!("{}: {err}", buffered_match.archive_path),
            )
        })?;
    Ok(ArchiveBinaryMatch {
        archive_format,
        archive_path: buffered_match.archive_path,
    })
}

fn copy_entry_with_limit<R, W>(
    reader: &mut R,
    writer: &mut W,
    archive_format: BinaryArchiveFormat,
    archive_path: &str,
    max_entry_bytes: u64,
) -> Result<(), ExtractBinaryFromArchiveError>
where
    R: Read,
    W: Write + ?Sized,
{
    let mut copied = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).map_err(|err| {
            ExtractBinaryFromArchiveError::archive_read(
                archive_format,
                "read_entry_content",
                format!("{archive_path}: {err}"),
            )
        })?;
        if read == 0 {
            return Ok(());
        }
        copied = copied.saturating_add(read as u64);
        if copied > max_entry_bytes {
            return Err(ExtractBinaryFromArchiveError::ExtractionBudgetExceeded {
                archive_format,
                archive_path: archive_path.to_string(),
                limit_bytes: max_entry_bytes,
            });
        }
        writer.write_all(&buffer[..read]).map_err(|err| {
            ExtractBinaryFromArchiveError::archive_read(
                archive_format,
                "write_entry_content",
                format!("{archive_path}: {err}"),
            )
        })?;
    }
}

fn ensure_tar_entry_is_regular_file(
    archive_format: BinaryArchiveFormat,
    archive_path: &str,
    entry_type: tar::EntryType,
) -> Result<(), ExtractBinaryFromArchiveError> {
    if entry_type.is_file() {
        return Ok(());
    }
    Err(ExtractBinaryFromArchiveError::MatchedEntryNotRegularFile {
        archive_format,
        archive_path: archive_path.to_string(),
    })
}

fn ensure_zip_entry_is_regular_file(
    archive_format: BinaryArchiveFormat,
    archive_path: &str,
    entry: &zip::read::ZipFile<'_>,
) -> Result<(), ExtractBinaryFromArchiveError> {
    if entry.is_dir() {
        return Err(ExtractBinaryFromArchiveError::MatchedEntryNotRegularFile {
            archive_format,
            archive_path: archive_path.to_string(),
        });
    }
    if let Some(mode) = entry.unix_mode() {
        let file_type = mode & 0o170000;
        if file_type != 0 && file_type != 0o100000 {
            return Err(ExtractBinaryFromArchiveError::MatchedEntryNotRegularFile {
                archive_format,
                archive_path: archive_path.to_string(),
            });
        }
    }
    Ok(())
}

struct ArchiveScanBudget {
    archive_format: BinaryArchiveFormat,
    max_entries: u64,
    scanned_entries: u64,
}

impl ArchiveScanBudget {
    fn new(archive_format: BinaryArchiveFormat, max_entries: u64) -> Self {
        Self {
            archive_format,
            max_entries,
            scanned_entries: 0,
        }
    }

    fn record_entry(&mut self) -> Result<(), ExtractBinaryFromArchiveError> {
        self.scanned_entries = self.scanned_entries.saturating_add(1);
        if self.scanned_entries > self.max_entries {
            return Err(ExtractBinaryFromArchiveError::ArchiveScanBudgetExceeded {
                archive_format: self.archive_format,
                limit_entries: self.max_entries,
            });
        }
        Ok(())
    }
}

fn normalize_archive_binary_hint(archive_binary_hint: Option<&str>) -> Option<String> {
    let hint = archive_binary_hint?;
    let hint = hint.trim().replace('\\', "/");
    let hint = hint.trim_start_matches('/');
    (!hint.is_empty()).then_some(hint.to_string())
}

fn is_binary_entry_match_without_hint(path: &str, binary_name: &str) -> bool {
    path.ends_with(&format!("/bin/{binary_name}"))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{
        ArchiveBinaryMatch, BinaryArchiveFormat, BinaryArchiveRequest,
        ExtractBinaryFromArchiveError, extract_binary_from_archive,
        extract_binary_from_archive_reader, extract_binary_from_archive_reader_to_writer,
        extract_binary_from_archive_reader_to_writer_with_limit,
        extract_binary_from_archive_reader_to_writer_with_limits,
        extract_binary_from_archive_reader_with_limit,
        extract_binary_from_archive_reader_with_limits, is_binary_archive_asset_name,
    };

    #[test]
    fn supported_archive_asset_detection_matches_expected_extensions() {
        assert!(is_binary_archive_asset_name("tool.tar.gz"));
        assert!(is_binary_archive_asset_name("tool.tar.xz"));
        assert!(is_binary_archive_asset_name("tool.zip"));
        assert!(!is_binary_archive_asset_name("tool.tgz"));
    }

    #[test]
    fn extracts_tar_gz_binary_by_bin_suffix() {
        let archive = make_tar_gz_archive(&[(
            "gh_9.9.9_linux_amd64/bin/gh",
            b"#!/bin/sh\necho gh\n".as_slice(),
            0o755,
        )]);
        let extracted = extract_binary_from_archive(
            "gh_9.9.9_linux_amd64.tar.gz",
            &archive,
            &BinaryArchiveRequest {
                binary_name: "gh",
                archive_binary_hint: None,
            },
        )
        .expect("extract gh");

        assert_eq!(extracted.archive_path, "gh_9.9.9_linux_amd64/bin/gh");
        assert_eq!(extracted.bytes, b"#!/bin/sh\necho gh\n");
    }

    #[test]
    fn extracts_tar_xz_binary_by_hint() {
        let archive = make_tar_xz_archive(&[(
            "node-v1.0.0-linux-x64/bin/node",
            b"mock-node".as_slice(),
            0o755,
        )]);
        let extracted = extract_binary_from_archive(
            "node-v1.0.0-linux-x64.tar.xz",
            &archive,
            &BinaryArchiveRequest {
                binary_name: "node",
                archive_binary_hint: Some("node-v1.0.0-linux-x64/bin/node"),
            },
        )
        .expect("extract node");

        assert_eq!(extracted.archive_path, "node-v1.0.0-linux-x64/bin/node");
        assert_eq!(extracted.bytes, b"mock-node");
    }

    #[test]
    fn archive_binary_hint_requires_exact_archive_path() {
        let archive = make_tar_xz_archive(&[
            ("node-v1.0.0-linux-x64/bin/node", b"first".as_slice(), 0o755),
            (
                "node-v1.0.0-linux-arm64/bin/node",
                b"second".as_slice(),
                0o755,
            ),
        ]);
        let err = extract_binary_from_archive(
            "node-v1.0.0.tar.xz",
            &archive,
            &BinaryArchiveRequest {
                binary_name: "node",
                archive_binary_hint: Some("bin/node"),
            },
        )
        .expect_err("suffix hint must not match by traversal order");

        match err {
            ExtractBinaryFromArchiveError::BinaryNotFound {
                archive_format,
                binary_name,
            } => {
                assert_eq!(archive_format, BinaryArchiveFormat::TarXz);
                assert_eq!(binary_name, "node");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn archive_binary_hint_normalizes_slashes_for_exact_match() {
        let archive = make_tar_xz_archive(&[
            ("node-v1.0.0-linux-x64/bin/node", b"first".as_slice(), 0o755),
            (
                "node-v1.0.0-linux-arm64/bin/node",
                b"second".as_slice(),
                0o755,
            ),
        ]);
        let err = extract_binary_from_archive(
            "node-v1.0.0.tar.xz",
            &archive,
            &BinaryArchiveRequest {
                binary_name: "node",
                archive_binary_hint: Some("\\node-v1.0.0-linux-arm64\\bin\\node"),
            },
        )
        .expect("normalized exact hint should match");

        assert_eq!(err.archive_path, "node-v1.0.0-linux-arm64/bin/node");
        assert_eq!(err.bytes, b"second");
    }

    #[test]
    fn ambiguous_tar_gz_binary_without_hint_fails_closed() {
        let archive = make_tar_gz_archive(&[
            ("demo-linux-x64/bin/demo", b"first".as_slice(), 0o755),
            ("demo-linux-arm64/bin/demo", b"second".as_slice(), 0o755),
        ]);

        let err = extract_binary_from_archive(
            "demo.tar.gz",
            &archive,
            &BinaryArchiveRequest {
                binary_name: "demo",
                archive_binary_hint: None,
            },
        )
        .expect_err("ambiguous match should fail closed");

        assert_ambiguous_binary_error(err, BinaryArchiveFormat::TarGz, "demo");
    }

    #[test]
    fn ambiguous_tar_xz_binary_without_hint_fails_closed() {
        let archive = make_tar_xz_archive(&[
            ("demo-linux-x64/bin/demo", b"first".as_slice(), 0o755),
            ("demo-linux-arm64/bin/demo", b"second".as_slice(), 0o755),
        ]);

        let err = extract_binary_from_archive(
            "demo.tar.xz",
            &archive,
            &BinaryArchiveRequest {
                binary_name: "demo",
                archive_binary_hint: None,
            },
        )
        .expect_err("ambiguous match should fail closed");

        assert_ambiguous_binary_error(err, BinaryArchiveFormat::TarXz, "demo");
    }

    #[test]
    fn ambiguous_zip_binary_without_hint_fails_closed_for_writer_path() {
        let archive = make_zip_archive(&[
            ("demo-linux-x64/bin/demo", b"first".as_slice(), 0o755),
            ("demo-linux-arm64/bin/demo", b"second".as_slice(), 0o755),
        ]);
        let mut writer = Vec::new();

        let err = extract_binary_from_archive_reader_to_writer(
            "demo.zip",
            Cursor::new(archive),
            &BinaryArchiveRequest {
                binary_name: "demo",
                archive_binary_hint: None,
            },
            &mut writer,
        )
        .expect_err("ambiguous match should fail closed");

        assert!(writer.is_empty());
        assert_ambiguous_binary_error(err, BinaryArchiveFormat::Zip, "demo");
    }

    #[test]
    fn zip_git_layout_requires_exact_hint_instead_of_tool_specific_fallback() {
        let archive = make_zip_archive(&[("PortableGit/cmd/git.exe", b"MZ".as_slice(), 0o755)]);
        let err = extract_binary_from_archive(
            "MinGit-1.2.3-64-bit.zip",
            &archive,
            &BinaryArchiveRequest {
                binary_name: "git.exe",
                archive_binary_hint: None,
            },
        )
        .expect_err("product-specific layout should require an explicit archive hint");

        assert!(matches!(
            err,
            ExtractBinaryFromArchiveError::BinaryNotFound {
                archive_format: BinaryArchiveFormat::Zip,
                binary_name,
            } if binary_name == "git.exe"
        ));
    }

    #[test]
    fn zip_git_layout_can_still_be_selected_by_exact_hint() {
        let archive = make_zip_archive(&[("PortableGit/cmd/git.exe", b"MZ".as_slice(), 0o755)]);
        let extracted = extract_binary_from_archive(
            "MinGit-1.2.3-64-bit.zip",
            &archive,
            &BinaryArchiveRequest {
                binary_name: "git.exe",
                archive_binary_hint: Some("PortableGit/cmd/git.exe"),
            },
        )
        .expect("explicit hint should select product-specific layout");

        assert_eq!(extracted.archive_path, "PortableGit/cmd/git.exe");
        assert_eq!(extracted.bytes, b"MZ");
    }

    #[test]
    fn builder_path_reaches_exact_hint_selection() {
        let archive = make_zip_archive(&[("PortableGit/cmd/git.exe", b"MZ".as_slice(), 0o755)]);
        let request = BinaryArchiveRequest::new("git.exe")
            .with_archive_binary_hint(Some("PortableGit/cmd/git.exe"));
        let extracted = extract_binary_from_archive("MinGit-1.2.3-64-bit.zip", &archive, &request)
            .expect("explicit hint should remain the only selector");

        assert_eq!(extracted.archive_path, "PortableGit/cmd/git.exe");
        assert_eq!(extracted.bytes, b"MZ");
    }

    #[test]
    fn extracts_tar_gz_binary_from_reader() {
        let archive = make_tar_gz_archive(&[(
            "gh_9.9.9_linux_amd64/bin/gh",
            b"#!/bin/sh\necho gh\n".as_slice(),
            0o755,
        )]);
        let extracted = extract_binary_from_archive_reader(
            "gh_9.9.9_linux_amd64.tar.gz",
            Cursor::new(archive),
            &BinaryArchiveRequest {
                binary_name: "gh",
                archive_binary_hint: None,
            },
        )
        .expect("extract gh from reader");

        assert_eq!(extracted.archive_path, "gh_9.9.9_linux_amd64/bin/gh");
        assert_eq!(extracted.bytes, b"#!/bin/sh\necho gh\n");
    }

    #[test]
    fn extracts_tar_gz_binary_from_reader_to_writer() {
        let archive = make_tar_gz_archive(&[(
            "gh_9.9.9_linux_amd64/bin/gh",
            b"#!/bin/sh\necho gh\n".as_slice(),
            0o755,
        )]);
        let mut out = Vec::new();
        let path = extract_binary_from_archive_reader_to_writer(
            "gh_9.9.9_linux_amd64.tar.gz",
            Cursor::new(archive),
            &BinaryArchiveRequest {
                binary_name: "gh",
                archive_binary_hint: None,
            },
            &mut out,
        )
        .expect("extract gh from reader to writer");

        assert_eq!(
            path,
            ArchiveBinaryMatch {
                archive_format: BinaryArchiveFormat::TarGz,
                archive_path: "gh_9.9.9_linux_amd64/bin/gh".to_string(),
            }
        );
        assert_eq!(out, b"#!/bin/sh\necho gh\n");
    }

    #[test]
    fn unsupported_archive_type_is_rejected() {
        let err = extract_binary_from_archive(
            "tool.tar",
            b"",
            &BinaryArchiveRequest {
                binary_name: "tool",
                archive_binary_hint: None,
            },
        )
        .expect_err("unsupported archive should fail");

        assert!(matches!(
            err,
            ExtractBinaryFromArchiveError::UnsupportedArchiveType { .. }
        ));
    }

    #[test]
    fn missing_binary_reports_archive_format() {
        let archive = make_tar_gz_archive(&[("bin/other", b"other".as_slice(), 0o755)]);
        let err = extract_binary_from_archive(
            "tool.tar.gz",
            &archive,
            &BinaryArchiveRequest {
                binary_name: "tool",
                archive_binary_hint: None,
            },
        )
        .expect_err("missing binary should fail");

        match err {
            ExtractBinaryFromArchiveError::BinaryNotFound {
                archive_format,
                binary_name,
            } => {
                assert_eq!(archive_format, BinaryArchiveFormat::TarGz);
                assert_eq!(binary_name, "tool");
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn matched_tar_symlink_is_rejected() {
        let archive = make_special_tar_gz_archive(&[TarEntry::symlink(
            "gh_9.9.9_linux_amd64/bin/gh",
            "../lib/gh",
        )]);
        let err = extract_binary_from_archive(
            "gh_9.9.9_linux_amd64.tar.gz",
            &archive,
            &BinaryArchiveRequest {
                binary_name: "gh",
                archive_binary_hint: None,
            },
        )
        .expect_err("symlink should be rejected");

        assert!(matches!(
            err,
            ExtractBinaryFromArchiveError::MatchedEntryNotRegularFile { .. }
        ));
    }

    #[test]
    fn matched_zip_directory_is_rejected() {
        let archive = make_zip_archive_with_directory("demo/bin/demo/", 0o755);
        let err = extract_binary_from_archive(
            "demo.zip",
            &archive,
            &BinaryArchiveRequest {
                binary_name: "demo",
                archive_binary_hint: Some("demo/bin/demo/"),
            },
        )
        .expect_err("zip directory should be rejected");

        assert!(matches!(
            err,
            ExtractBinaryFromArchiveError::MatchedEntryNotRegularFile { .. }
        ));
    }

    #[test]
    fn matched_entry_respects_extraction_budget() {
        let archive = make_repeat_tar_gz_archive("demo/bin/demo", 32, 0o755, b'X');
        let err = extract_binary_from_archive_reader_with_limit(
            "demo.tar.gz",
            Cursor::new(archive),
            &BinaryArchiveRequest {
                binary_name: "demo",
                archive_binary_hint: None,
            },
            16,
        )
        .expect_err("entry should exceed budget");

        assert!(matches!(
            err,
            ExtractBinaryFromArchiveError::ExtractionBudgetExceeded { .. }
        ));
    }

    #[test]
    fn writer_extraction_path_respects_budget() {
        let archive = make_repeat_tar_gz_archive("demo/bin/demo", 32, 0o755, b'X');
        let mut out = Vec::new();
        let err = extract_binary_from_archive_reader_to_writer_with_limit(
            "demo.tar.gz",
            Cursor::new(archive),
            &BinaryArchiveRequest {
                binary_name: "demo",
                archive_binary_hint: None,
            },
            &mut out,
            16,
        )
        .expect_err("entry should exceed budget");

        assert!(matches!(
            err,
            ExtractBinaryFromArchiveError::ExtractionBudgetExceeded { .. }
        ));
        assert!(out.len() <= 16);
    }

    #[test]
    fn archive_scan_budget_limits_tar_entry_search() {
        let archive = make_tar_gz_archive(&[
            ("bin/first", b"first".as_slice(), 0o755),
            ("bin/second", b"second".as_slice(), 0o755),
        ]);
        let err = extract_binary_from_archive_reader_with_limits(
            "demo.tar.gz",
            Cursor::new(archive),
            &BinaryArchiveRequest {
                binary_name: "second",
                archive_binary_hint: Some("bin/second"),
            },
            1024,
            1,
        )
        .expect_err("scan should exceed entry budget before reaching the second entry");

        assert!(matches!(
            err,
            ExtractBinaryFromArchiveError::ArchiveScanBudgetExceeded {
                archive_format: BinaryArchiveFormat::TarGz,
                limit_entries: 1,
            }
        ));
    }

    #[test]
    fn archive_scan_budget_limits_zip_writer_search() {
        let archive = make_zip_archive(&[
            ("bin/first", b"first".as_slice(), 0o755),
            ("bin/second", b"second".as_slice(), 0o755),
        ]);
        let mut out = Vec::new();
        let err = extract_binary_from_archive_reader_to_writer_with_limits(
            "demo.zip",
            Cursor::new(archive),
            &BinaryArchiveRequest {
                binary_name: "second",
                archive_binary_hint: Some("bin/second"),
            },
            &mut out,
            1024,
            1,
        )
        .expect_err("scan should exceed entry budget before reaching the second entry");

        assert!(matches!(
            err,
            ExtractBinaryFromArchiveError::ArchiveScanBudgetExceeded {
                archive_format: BinaryArchiveFormat::Zip,
                limit_entries: 1,
            }
        ));
        assert!(out.is_empty());
    }

    #[test]
    fn default_budget_accepts_large_windows_binary_entries() {
        let archive = make_repeat_zip_archive(
            "node-v22.14.0-win-x64/node.exe",
            80 * 1024 * 1024,
            0o755,
            b'Z',
        );
        let mut out = CountingWriter::default();
        let matched = extract_binary_from_archive_reader_to_writer(
            "node-v22.14.0-win-x64.zip",
            Cursor::new(archive),
            &BinaryArchiveRequest {
                binary_name: "node.exe",
                archive_binary_hint: Some("node-v22.14.0-win-x64/node.exe"),
            },
            &mut out,
        )
        .expect("large windows binary should fit within the default extraction budget");

        assert_eq!(matched.archive_path, "node-v22.14.0-win-x64/node.exe");
        assert_eq!(out.bytes_written, 80 * 1024 * 1024);
    }

    fn assert_ambiguous_binary_error(
        err: ExtractBinaryFromArchiveError,
        archive_format: BinaryArchiveFormat,
        binary_name: &str,
    ) {
        match err {
            ExtractBinaryFromArchiveError::AmbiguousBinaryMatches {
                archive_format: actual_format,
                binary_name: actual_binary_name,
                first_archive_path,
                second_archive_path,
            } => {
                assert_eq!(actual_format, archive_format);
                assert_eq!(actual_binary_name, binary_name);
                assert_ne!(first_archive_path, second_archive_path);
                assert!(first_archive_path.ends_with(&format!("/bin/{binary_name}")));
                assert!(second_archive_path.ends_with(&format!("/bin/{binary_name}")));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    fn make_tar_gz_archive(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for (path, body, mode) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(*mode);
            header.set_cksum();
            builder
                .append_data(&mut header, *path, &mut Cursor::new(*body))
                .expect("append tar.gz entry");
        }
        let encoder = builder.into_inner().expect("finalize tar.gz builder");
        encoder.finish().expect("finalize gzip stream")
    }

    fn make_tar_xz_archive(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
        let mut builder = tar::Builder::new(encoder);
        for (path, body, mode) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(body.len() as u64);
            header.set_mode(*mode);
            header.set_cksum();
            builder
                .append_data(&mut header, *path, &mut Cursor::new(*body))
                .expect("append tar.xz entry");
        }
        let encoder = builder.into_inner().expect("finalize tar.xz builder");
        encoder.finish().expect("finalize xz stream")
    }

    fn make_repeat_tar_gz_archive(path: &str, size: usize, mode: u32, byte: u8) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(size as u64);
        header.set_mode(mode);
        header.set_cksum();
        builder
            .append_data(
                &mut header,
                path,
                RepeatReader {
                    remaining: size,
                    byte,
                },
            )
            .expect("append repeated tar.gz entry");
        let encoder = builder.into_inner().expect("finalize tar.gz builder");
        encoder.finish().expect("finalize gzip stream")
    }

    fn make_special_tar_gz_archive(entries: &[TarEntry<'_>]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for entry in entries {
            let mut header = tar::Header::new_gnu();
            header.set_mode(entry.mode);
            match entry.kind {
                TarEntryKind::Symlink(target) => {
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_size(0);
                    header.set_link_name(target).expect("set symlink target");
                    header.set_cksum();
                    builder
                        .append_data(&mut header, entry.path, std::io::empty())
                        .expect("append symlink entry");
                }
            }
        }
        let encoder = builder.into_inner().expect("finalize tar.gz builder");
        encoder.finish().expect("finalize gzip stream")
    }

    fn make_zip_archive(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
        use std::io::Write;

        let mut writer = Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut writer);
            for (path, body, mode) in entries {
                let options = zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored)
                    .unix_permissions(*mode);
                archive.start_file(*path, options).expect("start zip entry");
                archive.write_all(body).expect("write zip entry");
            }
            archive.finish().expect("finish zip archive");
        }
        writer.into_inner()
    }

    fn make_repeat_zip_archive(path: &str, size: usize, mode: u32, byte: u8) -> Vec<u8> {
        use std::io::Write;

        let mut writer = Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut writer);
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated)
                .unix_permissions(mode);
            archive.start_file(path, options).expect("start zip entry");
            let chunk = vec![byte; 64 * 1024];
            let full_chunks = size / chunk.len();
            let tail = size % chunk.len();
            for _ in 0..full_chunks {
                archive.write_all(&chunk).expect("write zip chunk");
            }
            if tail > 0 {
                archive
                    .write_all(&chunk[..tail])
                    .expect("write zip tail chunk");
            }
            archive.finish().expect("finish zip archive");
        }
        writer.into_inner()
    }

    fn make_zip_archive_with_directory(path: &str, mode: u32) -> Vec<u8> {
        let mut writer = Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut writer);
            let options = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored)
                .unix_permissions(mode);
            archive
                .add_directory(path, options)
                .expect("add zip directory entry");
            archive.finish().expect("finish zip archive");
        }
        writer.into_inner()
    }

    struct RepeatReader {
        remaining: usize,
        byte: u8,
    }

    impl std::io::Read for RepeatReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Ok(0);
            }
            let len = self.remaining.min(buf.len());
            buf[..len].fill(self.byte);
            self.remaining -= len;
            Ok(len)
        }
    }

    #[derive(Default)]
    struct CountingWriter {
        bytes_written: usize,
    }

    impl std::io::Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes_written += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct TarEntry<'a> {
        path: &'a str,
        kind: TarEntryKind<'a>,
        mode: u32,
    }

    impl<'a> TarEntry<'a> {
        fn symlink(path: &'a str, target: &'a str) -> Self {
            Self {
                path,
                kind: TarEntryKind::Symlink(target),
                mode: 0o777,
            }
        }
    }

    enum TarEntryKind<'a> {
        Symlink(&'a str),
    }
}
