use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use omne_archive_primitives::{
    ArchiveBinaryMatch, BinaryArchiveRequest, extract_binary_from_archive_reader_to_writer,
};
use omne_fs_primitives::{
    AtomicWriteOptions, lock_advisory_file_in_ambient_root, stage_file_atomically,
    stage_file_atomically_with_name,
};
use omne_integrity_primitives::{Sha256Digest, verify_sha256_reader};

use crate::artifact_download::{
    ArtifactDownloadCandidate, ArtifactDownloader, ArtifactInstallError,
    ArtifactInstallErrorDetail, candidate_failure_message,
    download_candidate_to_writer_with_options, failed_candidates_error,
    require_download_candidates, run_blocking_install,
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
    destination: &Path,
    archive_binary_hint: Option<&str>,
) -> Result<ArchiveBinaryMatch, ArtifactInstallError> {
    let mut reader = Cursor::new(content);
    install_binary_from_archive_reader(
        asset_name,
        &mut reader,
        binary_name,
        destination,
        archive_binary_hint,
    )
}

pub async fn download_binary_to_destination<D>(
    downloader: &D,
    candidates: &[ArtifactDownloadCandidate],
    request: &DownloadBinaryRequest<'_>,
) -> Result<ArtifactDownloadCandidate, ArtifactInstallError>
where
    D: ArtifactDownloader + ?Sized,
{
    require_download_candidates(candidates, request.canonical_url)?;

    let mut errors = Vec::new();
    for candidate in candidates {
        let expected_sha256 = request.expected_sha256.cloned();
        let destination = request.destination.to_path_buf();
        let mut staged = stage_file_atomically_with_name(
            request.destination,
            &binary_write_options(),
            Some(request.asset_name),
        )
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;

        let download_result = download_candidate_to_writer_with_options(
            downloader,
            candidate,
            staged.file_mut(),
            request.max_download_bytes,
        )
        .await;
        if let Err(err) = download_result {
            errors.push(candidate_failure_message(candidate, &err));
            continue;
        }

        let install_result = run_blocking_install(move || {
            verify_downloaded_candidate(staged.file_mut(), expected_sha256.as_ref())
                .and_then(|_| commit_binary_stage_with_lock(staged, &destination))
        })
        .await;
        if let Err(err) = install_result {
            errors.push(candidate_failure_message(candidate, &err));
            continue;
        }
        return Ok(candidate.clone());
    }

    Err(failed_candidates_error(request.canonical_url, errors))
}

pub async fn download_and_install_binary_from_archive<D>(
    downloader: &D,
    candidates: &[ArtifactDownloadCandidate],
    request: &BinaryArchiveInstallRequest<'_>,
) -> Result<InstalledArchiveBinary, ArtifactInstallError>
where
    D: ArtifactDownloader + ?Sized,
{
    require_download_candidates(candidates, request.canonical_url)?;

    let mut errors = Vec::new();
    for candidate in candidates {
        let expected_sha256 = request.expected_sha256.cloned();
        let asset_name = request.asset_name.to_string();
        let binary_name = request.binary_name.to_string();
        let destination = request.destination.to_path_buf();
        let archive_binary_hint = request.archive_binary_hint.map(ToString::to_string);
        let mut staged = stage_file_atomically_with_name(
            request.destination,
            &archive_download_stage_options(),
            Some(request.asset_name),
        )
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;

        let download_result = download_candidate_to_writer_with_options(
            downloader,
            candidate,
            staged.file_mut(),
            request.max_download_bytes,
        )
        .await;
        if let Err(err) = download_result {
            errors.push(candidate_failure_message(candidate, &err));
            continue;
        }

        let install_result = run_blocking_install(move || {
            verify_downloaded_candidate(staged.file_mut(), expected_sha256.as_ref())
                .and_then(|_| {
                    staged
                        .file_mut()
                        .seek(SeekFrom::Start(0))
                        .map_err(|err| ArtifactInstallError::install(err.to_string()))
                })
                .and_then(|_| {
                    install_binary_from_archive_reader(
                        &asset_name,
                        staged.file_mut(),
                        &binary_name,
                        &destination,
                        archive_binary_hint.as_deref(),
                    )
                })
        })
        .await;
        let archive_match = match install_result {
            Ok(archive_match) => archive_match,
            Err(err) => {
                errors.push(candidate_failure_message(candidate, &err));
                continue;
            }
        };
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
    destination: &Path,
    archive_binary_hint: Option<&str>,
) -> Result<ArchiveBinaryMatch, ArtifactInstallError>
where
    R: Read + Seek + ?Sized,
{
    let _install_lock = lock_binary_destination(destination)?;
    let mut staged = stage_file_atomically(destination, &binary_write_options())
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    let matched = extract_binary_from_archive_reader_to_writer(
        asset_name,
        reader,
        &BinaryArchiveRequest {
            binary_name,
            archive_binary_hint,
        },
        staged.file_mut(),
    )
    .map_err(map_extract_binary_error)?;
    staged
        .commit()
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    Ok(matched)
}

fn map_extract_binary_error(
    err: omne_archive_primitives::ExtractBinaryFromArchiveError,
) -> ArtifactInstallError {
    let message = err.to_string();
    let detail = ArtifactInstallErrorDetail::from_extract_binary_error(err);
    ArtifactInstallError::install_with_detail(message, detail)
}

fn commit_binary_stage_with_lock(
    staged: omne_fs_primitives::StagedAtomicFile,
    destination: &Path,
) -> Result<(), ArtifactInstallError> {
    let _install_lock = lock_binary_destination(destination)?;
    staged
        .commit()
        .map_err(|err| ArtifactInstallError::install(err.to_string()))
}

fn verify_downloaded_candidate<R>(
    reader: &mut R,
    expected_sha256: Option<&Sha256Digest>,
) -> Result<(), ArtifactInstallError>
where
    R: Read + Seek + ?Sized,
{
    let Some(expected_sha256) = expected_sha256 else {
        return Ok(());
    };

    reader
        .seek(SeekFrom::Start(0))
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    verify_sha256_reader(reader, expected_sha256)
        .map_err(|err| ArtifactInstallError::download(err.to_string()))
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

const BINARY_INSTALL_LOCK_PREFIX: &str = ".binary-install-";
const BINARY_INSTALL_LOCK_SUFFIX: &str = ".lock";

fn lock_binary_destination(
    destination: &Path,
) -> Result<omne_fs_primitives::AdvisoryLockGuard, ArtifactInstallError> {
    let lock_root = destination.parent().unwrap_or_else(|| Path::new("."));
    let lock_file = binary_install_lock_file_name(destination);
    lock_advisory_file_in_ambient_root(
        lock_root,
        "binary install lock root",
        &lock_file,
        "binary install lock file",
    )
    .map_err(|err| {
        ArtifactInstallError::install(format!(
            "failed to lock binary destination `{}`: {err}",
            destination.display()
        ))
    })
}

fn binary_install_lock_file_name(destination: &Path) -> PathBuf {
    let label = destination
        .file_name()
        .map(|name| sanitize_lock_component(&name.to_string_lossy()))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "binary".to_string());
    PathBuf::from(format!(
        "{BINARY_INSTALL_LOCK_PREFIX}{label}{BINARY_INSTALL_LOCK_SUFFIX}"
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use omne_fs_primitives::lock_advisory_file_in_ambient_root;
    use omne_integrity_primitives::hash_sha256;
    use tokio::time::timeout;

    use crate::artifact_download::{
        ArtifactDownloadCandidate, ArtifactDownloadCandidateKind, ArtifactDownloader,
        ArtifactInstallError, ArtifactInstallErrorDetail,
    };

    use super::{
        BinaryArchiveInstallRequest, DownloadBinaryRequest, binary_install_lock_file_name,
        download_and_install_binary_from_archive, download_binary_to_destination,
        install_binary_from_archive,
    };

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

    fn make_zip_archive(entries: &[(&str, &[u8], u32)]) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut writer = Cursor::new(Vec::new());
        {
            let mut archive = zip::ZipWriter::new(&mut writer);
            for (path, body, mode) in entries {
                let options = zip::write::FileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored)
                    .unix_permissions(*mode);
                archive.start_file(*path, options)?;
                archive.write_all(body)?;
            }
            archive.finish()?;
        }
        Ok(writer.into_inner())
    }

    struct StubDownloader {
        routes: HashMap<String, Vec<u8>>,
    }

    impl ArtifactDownloader for StubDownloader {
        async fn download_to_writer<W>(
            &self,
            url: &str,
            writer: &mut W,
            max_bytes: Option<u64>,
        ) -> Result<(), ArtifactInstallError>
        where
            W: Write + ?Sized,
        {
            let body = self.routes.get(url).ok_or_else(|| {
                ArtifactInstallError::download(format!("missing stub route: {url}"))
            })?;
            if let Some(limit) = max_bytes
                && body.len() as u64 > limit
            {
                return Err(ArtifactInstallError::download(format!(
                    "response body too large ({} > {} bytes)",
                    body.len(),
                    limit
                )));
            }
            writer
                .write_all(body)
                .map_err(|err| ArtifactInstallError::install(err.to_string()))
        }
    }

    #[tokio::test]
    async fn direct_binary_download_retries_after_checksum_failure() -> Result<(), Box<dyn Error>> {
        let asset_name = format!("demo{}", std::env::consts::EXE_SUFFIX);
        let good_binary = b"good-binary".to_vec();
        let bad_binary = b"bad-binary".to_vec();
        let expected_sha256 = hash_sha256(&good_binary);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let base = format!("http://{addr}");
        let canonical_url = format!("{base}/{asset_name}");
        let mirror_url = format!("{base}/mirror/{asset_name}");

        let mut routes = HashMap::new();
        routes.insert(format!("/{asset_name}"), bad_binary);
        routes.insert(format!("/mirror/{asset_name}"), good_binary.clone());
        let handle = spawn_mock_http_server(listener, routes, 2);

        let temp = tempfile::tempdir()?;
        let destination = temp.path().join(&asset_name);
        let client = reqwest::Client::builder().build()?;
        let selected = download_binary_to_destination(
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
            &DownloadBinaryRequest {
                canonical_url: &canonical_url,
                destination: &destination,
                asset_name: &asset_name,
                expected_sha256: Some(&expected_sha256),
                max_download_bytes: None,
            },
        )
        .await?;

        assert_eq!(selected.kind, ArtifactDownloadCandidateKind::Mirror);
        assert_eq!(std::fs::read(&destination)?, good_binary);

        handle.join().expect("mock server thread join");
        Ok(())
    }

    #[tokio::test]
    async fn direct_binary_download_accepts_non_reqwest_downloader() -> Result<(), Box<dyn Error>> {
        let asset_name = format!("demo{}", std::env::consts::EXE_SUFFIX);
        let binary = b"generic-downloader".to_vec();
        let expected_sha256 = hash_sha256(&binary);
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join(&asset_name);
        let canonical_url = format!("https://example.invalid/{asset_name}");
        let downloader = StubDownloader {
            routes: HashMap::from([(canonical_url.clone(), binary.clone())]),
        };

        let selected = download_binary_to_destination(
            &downloader,
            &[ArtifactDownloadCandidate {
                url: canonical_url.clone(),
                kind: ArtifactDownloadCandidateKind::Canonical,
            }],
            &DownloadBinaryRequest {
                canonical_url: &canonical_url,
                destination: &destination,
                asset_name: &asset_name,
                expected_sha256: Some(&expected_sha256),
                max_download_bytes: None,
            },
        )
        .await?;

        assert_eq!(selected.kind, ArtifactDownloadCandidateKind::Canonical);
        assert_eq!(std::fs::read(&destination)?, binary);
        Ok(())
    }

    #[tokio::test]
    async fn direct_binary_download_rejects_empty_candidate_lists() -> Result<(), Box<dyn Error>> {
        let asset_name = format!("demo{}", std::env::consts::EXE_SUFFIX);
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join(&asset_name);
        let canonical_url = format!("https://example.invalid/{asset_name}");
        let downloader = StubDownloader {
            routes: HashMap::new(),
        };

        let err = download_binary_to_destination(
            &downloader,
            &[],
            &DownloadBinaryRequest {
                canonical_url: &canonical_url,
                destination: &destination,
                asset_name: &asset_name,
                expected_sha256: None,
                max_download_bytes: None,
            },
        )
        .await
        .expect_err("empty candidate lists must be rejected");

        assert!(err.candidate_failures().is_empty());
        assert!(
            err.to_string()
                .contains("requires at least one download candidate"),
            "unexpected message: {err}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn archive_binary_download_retries_after_extract_failure() -> Result<(), Box<dyn Error>> {
        let asset_name = "demo.zip";
        let binary_name = format!("demo{}", std::env::consts::EXE_SUFFIX);
        let archive_path = format!("demo/bin/{binary_name}");
        let good_archive = make_zip_archive(&[(archive_path.as_str(), b"good-binary", 0o755)])?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let base = format!("http://{addr}");
        let canonical_url = format!("{base}/{asset_name}");
        let mirror_url = format!("{base}/mirror/{asset_name}");

        let mut routes = HashMap::new();
        routes.insert(format!("/{asset_name}"), b"not a zip archive".to_vec());
        routes.insert(format!("/mirror/{asset_name}"), good_archive);
        let handle = spawn_mock_http_server(listener, routes, 2);

        let temp = tempfile::tempdir()?;
        let destination = temp.path().join(&binary_name);
        let client = reqwest::Client::builder().build()?;
        let installed = download_and_install_binary_from_archive(
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
            &BinaryArchiveInstallRequest {
                canonical_url: &canonical_url,
                destination: &destination,
                asset_name,
                binary_name: &binary_name,
                archive_binary_hint: None,
                expected_sha256: None,
                max_download_bytes: None,
            },
        )
        .await?;

        assert_eq!(installed.source.kind, ArtifactDownloadCandidateKind::Mirror);
        assert_eq!(std::fs::read(&destination)?, b"good-binary");

        handle.join().expect("mock server thread join");
        Ok(())
    }

    #[tokio::test]
    async fn archive_binary_download_rejects_empty_candidate_lists() -> Result<(), Box<dyn Error>> {
        let asset_name = "demo.zip";
        let binary_name = format!("demo{}", std::env::consts::EXE_SUFFIX);
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join(&binary_name);
        let canonical_url = format!("https://example.invalid/{asset_name}");
        let downloader = StubDownloader {
            routes: HashMap::new(),
        };

        let err = download_and_install_binary_from_archive(
            &downloader,
            &[],
            &BinaryArchiveInstallRequest {
                canonical_url: &canonical_url,
                destination: &destination,
                asset_name,
                binary_name: &binary_name,
                archive_binary_hint: None,
                expected_sha256: None,
                max_download_bytes: None,
            },
        )
        .await
        .expect_err("empty candidate lists must be rejected");

        assert!(err.candidate_failures().is_empty());
        assert!(
            err.to_string()
                .contains("requires at least one download candidate"),
            "unexpected message: {err}"
        );
        Ok(())
    }

    #[test]
    fn archive_binary_missing_target_surfaces_structured_detail() -> Result<(), Box<dyn Error>> {
        let archive = make_zip_archive(&[("demo/bin/other", b"good-binary", 0o755)])?;
        let temp = tempfile::tempdir()?;
        let destination = temp
            .path()
            .join(format!("demo{}", std::env::consts::EXE_SUFFIX));

        let err = install_binary_from_archive(
            "demo.zip",
            &archive,
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .expect("binary name"),
            &destination,
            None,
        )
        .expect_err("missing archive binary should fail");

        assert_eq!(
            err.detail(),
            Some(&ArtifactInstallErrorDetail::ArchiveBinaryNotFound {
                archive_format: omne_archive_primitives::BinaryArchiveFormat::Zip,
                binary_name: destination
                    .file_name()
                    .and_then(|name| name.to_str())
                    .expect("binary name")
                    .to_string(),
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn direct_binary_install_serializes_same_destination() -> Result<(), Box<dyn Error>> {
        let asset_name = format!("demo{}", std::env::consts::EXE_SUFFIX);
        let binary = b"good-binary".to_vec();
        let expected_sha256 = hash_sha256(&binary);

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let canonical_url = format!("http://{addr}/{asset_name}");

        let mut routes = HashMap::new();
        routes.insert(format!("/{asset_name}"), binary.clone());
        let handle = spawn_mock_http_server(listener, routes, 1);

        let temp = tempfile::tempdir()?;
        let destination = temp.path().join(&asset_name);
        let lock_root = destination.parent().expect("destination parent");
        let lock_file = binary_install_lock_file_name(&destination);
        let guard = lock_advisory_file_in_ambient_root(
            lock_root,
            "binary install lock root",
            &lock_file,
            "binary install lock file",
        )?;
        let client = reqwest::Client::builder().build()?;
        let mut install = tokio::spawn({
            let canonical_url = canonical_url.clone();
            let destination = destination.clone();
            let asset_name = asset_name.clone();
            async move {
                download_binary_to_destination(
                    &client,
                    &[ArtifactDownloadCandidate {
                        url: canonical_url.clone(),
                        kind: ArtifactDownloadCandidateKind::Canonical,
                    }],
                    &DownloadBinaryRequest {
                        canonical_url: &canonical_url,
                        destination: &destination,
                        asset_name: &asset_name,
                        expected_sha256: Some(&expected_sha256),
                        max_download_bytes: None,
                    },
                )
                .await
            }
        });

        assert!(
            timeout(Duration::from_millis(200), &mut install)
                .await
                .is_err(),
            "same-destination direct install should wait for the advisory lock"
        );

        drop(guard);

        install.await.expect("install task join")?;
        handle.join().expect("mock server thread join");
        assert_eq!(std::fs::read(&destination)?, binary);
        Ok(())
    }

    #[test]
    fn install_binary_from_archive_serializes_same_destination() -> Result<(), Box<dyn Error>> {
        let binary_name = format!("demo{}", std::env::consts::EXE_SUFFIX);
        let archive_path = format!("demo/bin/{binary_name}");
        let archive = make_zip_archive(&[(archive_path.as_str(), b"good-binary", 0o755)])?;
        let temp = tempfile::tempdir()?;
        let destination = temp.path().join(&binary_name);
        let lock_root = destination.parent().expect("destination parent");
        let lock_file = binary_install_lock_file_name(&destination);
        let guard = lock_advisory_file_in_ambient_root(
            lock_root,
            "binary install lock root",
            &lock_file,
            "binary install lock file",
        )?;
        let (tx, rx) = mpsc::channel();
        let destination_for_thread = destination.clone();
        let binary_name_for_thread = binary_name.clone();
        let handle = thread::spawn(move || {
            let result = install_binary_from_archive(
                "demo.zip",
                &archive,
                &binary_name_for_thread,
                &destination_for_thread,
                Some(&archive_path),
            );
            tx.send(result).expect("send install result");
        });

        assert!(
            matches!(
                rx.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "same-destination archive install should wait for the advisory lock"
        );

        drop(guard);

        rx.recv_timeout(Duration::from_secs(2))
            .expect("install should complete after lock release")?;
        handle.join().expect("install thread join");
        assert_eq!(std::fs::read(&destination)?, b"good-binary");
        Ok(())
    }
}
