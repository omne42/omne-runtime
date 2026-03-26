use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

use omne_archive_primitives::{
    ArchiveBinaryMatch, BinaryArchiveRequest, extract_binary_from_archive_reader_to_writer,
};
use omne_fs_primitives::{
    AtomicWriteOptions, stage_file_atomically, stage_file_atomically_with_name,
};
use omne_integrity_primitives::{Sha256Digest, verify_sha256_reader};

use crate::artifact_download::{
    ArtifactDownloadCandidate, ArtifactInstallError, candidate_failure_message,
    download_candidate_to_writer_with_options, failed_candidates_error,
};

#[derive(Debug, Clone, Copy)]
pub struct DownloadBinaryRequest<'a> {
    pub canonical_url: &'a str,
    pub destination: &'a Path,
    pub asset_name: &'a str,
    pub expected_sha256: Option<&'a Sha256Digest>,
    pub max_download_bytes: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
pub struct BinaryArchiveInstallRequest<'a> {
    pub canonical_url: &'a str,
    pub destination: &'a Path,
    pub asset_name: &'a str,
    pub binary_name: &'a str,
    pub tool_name: &'a str,
    pub archive_binary_hint: Option<&'a str>,
    pub expected_sha256: Option<&'a Sha256Digest>,
    pub max_download_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledArchiveBinary {
    pub source: ArtifactDownloadCandidate,
    pub archive_match: ArchiveBinaryMatch,
}

pub fn install_binary_from_archive(
    asset_name: &str,
    content: &[u8],
    binary_name: &str,
    tool_name: &str,
    destination: &Path,
    archive_binary_hint: Option<&str>,
) -> Result<ArchiveBinaryMatch, ArtifactInstallError> {
    let mut reader = Cursor::new(content);
    install_binary_from_archive_reader(
        asset_name,
        &mut reader,
        binary_name,
        tool_name,
        destination,
        archive_binary_hint,
    )
}

pub async fn download_binary_to_destination(
    client: &reqwest::Client,
    candidates: &[ArtifactDownloadCandidate],
    request: &DownloadBinaryRequest<'_>,
) -> Result<ArtifactDownloadCandidate, ArtifactInstallError> {
    let mut errors = Vec::new();
    for candidate in candidates {
        let mut staged = stage_file_atomically_with_name(
            request.destination,
            &binary_write_options(),
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
            staged
                .file_mut()
                .seek(SeekFrom::Start(0))
                .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
            verify_sha256_reader(staged.file_mut(), expected_sha256)
                .map_err(|err| ArtifactInstallError::download(err.to_string()))?;
        }

        staged
            .commit()
            .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
        return Ok(candidate.clone());
    }

    Err(failed_candidates_error(request.canonical_url, errors))
}

pub async fn download_and_install_binary_from_archive(
    client: &reqwest::Client,
    candidates: &[ArtifactDownloadCandidate],
    request: &BinaryArchiveInstallRequest<'_>,
) -> Result<InstalledArchiveBinary, ArtifactInstallError> {
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
            staged
                .file_mut()
                .seek(SeekFrom::Start(0))
                .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
            verify_sha256_reader(staged.file_mut(), expected_sha256)
                .map_err(|err| ArtifactInstallError::download(err.to_string()))?;
        }

        staged
            .file_mut()
            .seek(SeekFrom::Start(0))
            .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
        let archive_match = install_binary_from_archive_reader(
            request.asset_name,
            staged.file_mut(),
            request.binary_name,
            request.tool_name,
            request.destination,
            request.archive_binary_hint,
        )?;
        return Ok(InstalledArchiveBinary {
            source: candidate.clone(),
            archive_match,
        });
    }

    Err(failed_candidates_error(request.canonical_url, errors))
}

fn install_binary_from_archive_reader<R>(
    asset_name: &str,
    reader: &mut R,
    binary_name: &str,
    tool_name: &str,
    destination: &Path,
    archive_binary_hint: Option<&str>,
) -> Result<ArchiveBinaryMatch, ArtifactInstallError>
where
    R: Read + Seek + ?Sized,
{
    let mut staged = stage_file_atomically(destination, &binary_write_options())
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    let matched = extract_binary_from_archive_reader_to_writer(
        asset_name,
        reader,
        &BinaryArchiveRequest {
            binary_name,
            tool_name,
            archive_binary_hint,
        },
        staged.file_mut(),
    )
    .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    staged
        .commit()
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    Ok(matched)
}

fn archive_download_stage_options() -> AtomicWriteOptions {
    AtomicWriteOptions {
        create_parent_directories: true,
        ..AtomicWriteOptions::default()
    }
}

fn binary_write_options() -> AtomicWriteOptions {
    AtomicWriteOptions {
        overwrite_existing: true,
        create_parent_directories: true,
        require_non_empty: true,
        require_executable_on_unix: true,
        unix_mode: Some(0o755),
    }
}
