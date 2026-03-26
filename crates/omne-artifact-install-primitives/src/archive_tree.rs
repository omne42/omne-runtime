use std::fs::{self, File};
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Component, Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use omne_fs_primitives::{AtomicWriteOptions, stage_file_atomically_with_name};
use omne_integrity_primitives::{Sha256Digest, verify_sha256_reader};
use tar::Archive as TarArchive;
use xz2::read::XzDecoder;
use zip::ZipArchive;

use crate::artifact_download::{
    ArtifactDownloadCandidate, ArtifactInstallError, candidate_failure_message,
    download_candidate_to_writer_with_options, failed_candidates_error,
};

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
    install_archive_tree_from_reader(asset_name, Cursor::new(archive_bytes), destination)
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
    let staging_dir = create_archive_tree_staging_dir(destination)?;
    let extract_result = if asset_name.ends_with(".zip") {
        extract_zip_tree(reader, &staging_dir)
    } else if asset_name.ends_with(".tar.gz") {
        extract_tar_tree(GzDecoder::new(reader), &staging_dir)
    } else if asset_name.ends_with(".tar.xz") {
        extract_tar_tree(XzDecoder::new(reader), &staging_dir)
    } else {
        Err(ArtifactInstallError::install(format!(
            "unsupported archive tree asset `{asset_name}`"
        )))
    };

    if let Err(err) = extract_result {
        remove_path_if_exists(&staging_dir);
        return Err(err);
    }

    replace_destination_with_staged_tree(destination, &staging_dir)
}

fn extract_zip_tree<R>(reader: R, destination: &Path) -> Result<(), ArtifactInstallError>
where
    R: Read + Seek,
{
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
        let output_path = destination.join(&enclosed);
        if entry.is_dir() {
            fs::create_dir_all(&output_path)
                .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
            continue;
        }
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
        }
        let mut file = File::create(&output_path)
            .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
        std::io::copy(&mut entry, &mut file)
            .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
        #[cfg(unix)]
        if let Some(mode) = entry.unix_mode() {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(&output_path, fs::Permissions::from_mode(mode))
                .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
        }
    }
    Ok(())
}

fn extract_tar_tree<R>(reader: R, destination: &Path) -> Result<(), ArtifactInstallError>
where
    R: Read,
{
    let mut archive = TarArchive::new(reader);
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
        let output_path = destination.join(sanitized);
        let entry_type = entry.header().entry_type();
        if entry_type.is_dir() {
            fs::create_dir_all(&output_path)
                .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
            continue;
        }
        if entry_type.is_file() {
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
            }
            entry
                .unpack(&output_path)
                .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
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
            create_tar_hard_link(&path, &output_path, &link_target, destination)?;
            continue;
        }
        return Err(ArtifactInstallError::install(format!(
            "unsupported tar entry type for {}",
            path.display()
        )));
    }
    Ok(())
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
    fs::create_dir_all(parent).map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    validate_archive_link_target(entry_path, parent, link_target, destination)?;

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

fn create_tar_hard_link(
    entry_path: &Path,
    output_path: &Path,
    link_target: &Path,
    destination: &Path,
) -> Result<(), ArtifactInstallError> {
    let parent = output_path.parent().ok_or_else(|| {
        ArtifactInstallError::install(format!(
            "cannot determine hard link parent for tar entry {}",
            entry_path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    let resolved_target =
        validate_archive_link_target(entry_path, parent, link_target, destination)?;
    if !resolved_target.exists() {
        return Err(ArtifactInstallError::install(format!(
            "hard link target does not exist for tar entry {}",
            entry_path.display()
        )));
    }
    fs::hard_link(&resolved_target, output_path)
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
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

fn create_archive_tree_staging_dir(destination: &Path) -> Result<PathBuf, ArtifactInstallError> {
    let parent = destination_parent(destination);
    fs::create_dir_all(parent).map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    let staging_dir = unique_sibling_path(destination, "staging")?;
    fs::create_dir_all(&staging_dir)
        .map_err(|err| ArtifactInstallError::install(err.to_string()))?;
    Ok(staging_dir)
}

fn replace_destination_with_staged_tree(
    destination: &Path,
    staging_dir: &Path,
) -> Result<(), ArtifactInstallError> {
    let backup_path = if destination.exists() {
        let backup_path = unique_sibling_path(destination, "backup")?;
        fs::rename(destination, &backup_path).map_err(|err| {
            ArtifactInstallError::install(format!(
                "move existing archive tree destination `{}` aside failed: {err}",
                destination.display()
            ))
        })?;
        Some(backup_path)
    } else {
        None
    };

    if let Err(err) = fs::rename(staging_dir, destination) {
        let restore_error = backup_path.as_ref().and_then(|backup_path| {
            fs::rename(backup_path, destination).err().map(|restore_err| {
                format!(
                    "restore existing archive tree destination `{}` from `{}` failed: {restore_err}",
                    destination.display(),
                    backup_path.display()
                )
            })
        });
        remove_path_if_exists(staging_dir);
        let mut message = format!(
            "replace archive tree destination `{}` failed: {err}",
            destination.display()
        );
        if let Some(restore_error) = restore_error {
            message.push_str("; ");
            message.push_str(&restore_error);
        }
        return Err(ArtifactInstallError::install(message));
    }

    if let Some(backup_path) = backup_path {
        remove_path_if_exists(&backup_path);
    }
    Ok(())
}

fn destination_parent(destination: &Path) -> &Path {
    match destination.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn unique_sibling_path(destination: &Path, kind: &str) -> Result<PathBuf, ArtifactInstallError> {
    let parent = destination_parent(destination);
    let file_name = destination.file_name().ok_or_else(|| {
        ArtifactInstallError::install(format!(
            "archive tree destination `{}` must include a final path component",
            destination.display()
        ))
    })?;
    let file_name = file_name.to_string_lossy();
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for attempt in 0..1024_u32 {
        let candidate = parent.join(format!(
            ".{file_name}.omne-artifact-install-{kind}-{}-{seed}-{attempt}",
            process::id()
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(ArtifactInstallError::install(format!(
        "cannot allocate {kind} path next to archive tree destination `{}`",
        destination.display()
    )))
}

fn remove_path_if_exists(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    let result = if metadata.file_type().is_dir() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    let _ = result;
}

fn archive_download_stage_options() -> AtomicWriteOptions {
    AtomicWriteOptions {
        create_parent_directories: true,
        ..AtomicWriteOptions::default()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use crate::artifact_download::{ArtifactDownloadCandidate, ArtifactDownloadCandidateKind};

    use super::{ArchiveTreeInstallRequest, download_and_install_archive_tree};

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
}
