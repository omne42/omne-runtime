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
use crate::install_lock::lock_install_destination;

const BINARY_INSTALL_LOCK_PREFIX: &str = ".binary-install-";

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

        let expected_sha256 = request.expected_sha256.cloned();
        let destination = request.destination.to_path_buf();
        let install_result = run_blocking_install(move || {
            let _install_lock = lock_binary_install_destination(&destination)?;
            verify_downloaded_candidate(staged.file_mut(), expected_sha256.as_ref()).and_then(
                |_| {
                    staged
                        .commit()
                        .map_err(|err| ArtifactInstallError::install(err.to_string()))
                },
            )
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

        let expected_sha256 = request.expected_sha256.cloned();
        let asset_name = request.asset_name.to_string();
        let binary_name = request.binary_name.to_string();
        let destination = request.destination.to_path_buf();
        let archive_binary_hint = request.archive_binary_hint.map(str::to_string);
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
    let mut staged = stage_file_atomically(destination, &binary_write_options())
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    let _install_lock = lock_binary_install_destination(destination)?;
    let matched = extract_binary_from_archive_reader_to_writer(
        asset_name,
        reader,
        &BinaryArchiveRequest {
            binary_name,
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

fn lock_binary_install_destination(
    destination: &Path,
) -> Result<omne_fs_primitives::AdvisoryLockGuard, ArtifactInstallError> {
    lock_install_destination(
        destination,
        BINARY_INSTALL_LOCK_PREFIX,
        "binary install lock root",
    )
}

#[cfg(test)]
fn binary_install_lock_file_name(destination: &Path) -> std::path::PathBuf {
    crate::install_lock::install_lock_file_name(destination, BINARY_INSTALL_LOCK_PREFIX)
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

async fn run_blocking_install<T, F>(work: F) -> Result<T, ArtifactInstallError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ArtifactInstallError> + Send + 'static,
{
    tokio::task::spawn_blocking(work).await.map_err(|err| {
        ArtifactInstallError::install(format!("blocking install task failed: {err}"))
    })?
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use omne_fs_primitives::lock_advisory_file_in_ambient_root;
    use omne_integrity_primitives::hash_sha256;

    use crate::artifact_download::{ArtifactDownloadCandidate, ArtifactInstallError};

    use super::{
        BinaryArchiveInstallRequest, DownloadBinaryRequest, binary_install_lock_file_name,
        download_and_install_binary_from_archive, download_binary_to_destination,
    };

    fn canonical_test_root(dir: &tempfile::TempDir) -> PathBuf {
        dir.path()
            .canonicalize()
            .unwrap_or_else(|_| dir.path().to_path_buf())
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
        let destination = canonical_test_root(&temp).join(&asset_name);
        let client = reqwest::Client::builder().build()?;
        let selected = download_binary_to_destination(
            &client,
            &[
                ArtifactDownloadCandidate {
                    url: canonical_url.clone(),
                    source_label: "canonical".to_string(),
                },
                ArtifactDownloadCandidate {
                    url: mirror_url,
                    source_label: "mirror".to_string(),
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

        assert_eq!(selected.source_label, "mirror");
        assert_eq!(std::fs::read(&destination)?, good_binary);

        handle.join().expect("mock server thread join");
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
        let destination = canonical_test_root(&temp).join(&binary_name);
        let client = reqwest::Client::builder().build()?;
        let installed = download_and_install_binary_from_archive(
            &client,
            &[
                ArtifactDownloadCandidate {
                    url: canonical_url.clone(),
                    source_label: "canonical".to_string(),
                },
                ArtifactDownloadCandidate {
                    url: mirror_url,
                    source_label: "mirror".to_string(),
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

        assert_eq!(installed.source.source_label, "mirror");
        assert_eq!(std::fs::read(&destination)?, b"good-binary");

        handle.join().expect("mock server thread join");
        Ok(())
    }

    #[tokio::test]
    async fn direct_binary_install_serializes_same_destination() -> Result<(), Box<dyn Error>> {
        let asset_name = format!("demo{}", std::env::consts::EXE_SUFFIX);
        let binary = b"demo-binary".to_vec();
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let canonical_url = format!("http://{addr}/{asset_name}");

        let mut routes = HashMap::new();
        routes.insert(format!("/{asset_name}"), binary.clone());
        let handle = spawn_mock_http_server(listener, routes, 1);

        let temp = tempfile::tempdir()?;
        let destination = canonical_test_root(&temp).join(&asset_name);
        let lock_root = destination.parent().expect("destination parent");
        let lock_file = binary_install_lock_file_name(&destination);
        let guard = lock_advisory_file_in_ambient_root(
            lock_root,
            "binary install lock root",
            &lock_file,
            "artifact install lock file",
        )?;
        let destination_for_thread = destination.clone();
        let canonical_url_for_thread = canonical_url.clone();
        let (tx, rx) = mpsc::channel();
        let install_thread = thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            let result = runtime.block_on(async move {
                let client = reqwest::Client::builder()
                    .build()
                    .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
                download_binary_to_destination(
                    &client,
                    &[ArtifactDownloadCandidate {
                        url: canonical_url_for_thread.clone(),
                        source_label: "canonical".to_string(),
                    }],
                    &DownloadBinaryRequest {
                        canonical_url: &canonical_url_for_thread,
                        destination: &destination_for_thread,
                        asset_name: &asset_name,
                        expected_sha256: None,
                        max_download_bytes: None,
                    },
                )
                .await
            });
            tx.send(result).expect("send install result");
        });

        assert!(
            matches!(
                rx.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "same-destination binary install should wait for the advisory lock"
        );

        drop(guard);

        rx.recv_timeout(Duration::from_secs(2))
            .expect("install should complete after lock release")?;
        install_thread.join().expect("install thread join");
        assert_eq!(std::fs::read(&destination)?, binary);

        handle.join().expect("mock server thread join");
        Ok(())
    }

    #[tokio::test]
    async fn archive_binary_install_serializes_same_destination() -> Result<(), Box<dyn Error>> {
        let asset_name = "demo.zip";
        let binary_name = format!("demo{}", std::env::consts::EXE_SUFFIX);
        let archive_path = format!("demo/bin/{binary_name}");
        let archive = make_zip_archive(&[(archive_path.as_str(), b"archive-binary", 0o755)])?;

        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        let canonical_url = format!("http://{addr}/{asset_name}");

        let mut routes = HashMap::new();
        routes.insert(format!("/{asset_name}"), archive);
        let handle = spawn_mock_http_server(listener, routes, 1);

        let temp = tempfile::tempdir()?;
        let destination = canonical_test_root(&temp).join(&binary_name);
        let lock_root = destination.parent().expect("destination parent");
        let lock_file = binary_install_lock_file_name(&destination);
        let guard = lock_advisory_file_in_ambient_root(
            lock_root,
            "binary install lock root",
            &lock_file,
            "artifact install lock file",
        )?;
        let destination_for_thread = destination.clone();
        let canonical_url_for_thread = canonical_url.clone();
        let binary_name_for_thread = binary_name.clone();
        let (tx, rx) = mpsc::channel();
        let install_thread = thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
            let result = runtime.block_on(async move {
                let client = reqwest::Client::builder()
                    .build()
                    .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
                download_and_install_binary_from_archive(
                    &client,
                    &[ArtifactDownloadCandidate {
                        url: canonical_url_for_thread.clone(),
                        source_label: "canonical".to_string(),
                    }],
                    &BinaryArchiveInstallRequest {
                        canonical_url: &canonical_url_for_thread,
                        destination: &destination_for_thread,
                        asset_name,
                        binary_name: &binary_name_for_thread,
                        archive_binary_hint: None,
                        expected_sha256: None,
                        max_download_bytes: None,
                    },
                )
                .await
            });
            tx.send(result).expect("send install result");
        });

        assert!(
            matches!(
                rx.recv_timeout(Duration::from_millis(200)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "same-destination archive-binary install should wait for the advisory lock"
        );

        drop(guard);

        rx.recv_timeout(Duration::from_secs(2))
            .expect("install should complete after lock release")?;
        install_thread.join().expect("install thread join");
        assert_eq!(std::fs::read(&destination)?, b"archive-binary");

        handle.join().expect("mock server thread join");
        Ok(())
    }
}
