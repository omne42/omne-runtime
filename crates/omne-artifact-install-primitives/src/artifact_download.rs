use std::fmt;
use std::future::Future;
use std::io::Write;

use http_kit::write_response_body_limited;
use omne_archive_primitives::{BinaryArchiveFormat, ExtractBinaryFromArchiveError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDownloadCandidate {
    pub url: String,
    pub source_label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactInstallErrorKind {
    Download,
    Install,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactInstallErrorDetail {
    UnsupportedArchiveType {
        asset_name: String,
    },
    ArchiveRead {
        archive_format: BinaryArchiveFormat,
        stage: &'static str,
        detail: String,
    },
    ArchiveBinaryNotFound {
        archive_format: BinaryArchiveFormat,
        binary_name: String,
    },
    ArchiveMatchedEntryNotRegularFile {
        archive_format: BinaryArchiveFormat,
        archive_path: String,
    },
    ArchiveExtractionBudgetExceeded {
        archive_format: BinaryArchiveFormat,
        archive_path: String,
        limit_bytes: u64,
    },
    ArchiveScanBudgetExceeded {
        archive_format: BinaryArchiveFormat,
        limit_entries: u64,
    },
}

impl ArtifactInstallErrorDetail {
    pub(crate) fn from_extract_binary_error(error: ExtractBinaryFromArchiveError) -> Self {
        match error {
            ExtractBinaryFromArchiveError::UnsupportedArchiveType { asset_name } => {
                Self::UnsupportedArchiveType { asset_name }
            }
            ExtractBinaryFromArchiveError::ArchiveRead {
                archive_format,
                stage,
                detail,
            } => Self::ArchiveRead {
                archive_format,
                stage,
                detail,
            },
            ExtractBinaryFromArchiveError::BinaryNotFound {
                archive_format,
                binary_name,
            } => Self::ArchiveBinaryNotFound {
                archive_format,
                binary_name,
            },
            ExtractBinaryFromArchiveError::MatchedEntryNotRegularFile {
                archive_format,
                archive_path,
            } => Self::ArchiveMatchedEntryNotRegularFile {
                archive_format,
                archive_path,
            },
            ExtractBinaryFromArchiveError::ExtractionBudgetExceeded {
                archive_format,
                archive_path,
                limit_bytes,
            } => Self::ArchiveExtractionBudgetExceeded {
                archive_format,
                archive_path,
                limit_bytes,
            },
            ExtractBinaryFromArchiveError::ArchiveScanBudgetExceeded {
                archive_format,
                limit_entries,
            } => Self::ArchiveScanBudgetExceeded {
                archive_format,
                limit_entries,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactCandidateFailure {
    kind: ArtifactInstallErrorKind,
    source_label: String,
    redacted_url: String,
    message: String,
    detail: Option<ArtifactInstallErrorDetail>,
}

impl ArtifactCandidateFailure {
    #[must_use]
    pub const fn kind(&self) -> ArtifactInstallErrorKind {
        self.kind
    }

    #[must_use]
    pub fn source_label(&self) -> &str {
        &self.source_label
    }

    #[must_use]
    pub fn redacted_url(&self) -> &str {
        &self.redacted_url
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub const fn detail(&self) -> Option<&ArtifactInstallErrorDetail> {
        self.detail.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactInstallError {
    kind: ArtifactInstallErrorKind,
    message: String,
    detail: Option<ArtifactInstallErrorDetail>,
    candidate_failures: Vec<ArtifactCandidateFailure>,
}

/// Narrow async download adapter for artifact-install entrypoints.
///
/// Callers can satisfy this contract with their own HTTP/runtime stack; the public primitive
/// boundary does not require a concrete client type. `reqwest::Client` remains supported through
/// the built-in adapter impl below.
pub trait ArtifactDownloader {
    fn download_to_writer<W>(
        &self,
        url: &str,
        writer: &mut W,
        max_bytes: Option<u64>,
    ) -> impl Future<Output = Result<(), ArtifactInstallError>> + Send
    where
        W: Write + ?Sized + Send;
}

impl ArtifactInstallError {
    pub fn download(message: impl Into<String>) -> Self {
        Self {
            kind: ArtifactInstallErrorKind::Download,
            message: message.into(),
            detail: None,
            candidate_failures: Vec::new(),
        }
    }

    pub fn install(message: impl Into<String>) -> Self {
        Self {
            kind: ArtifactInstallErrorKind::Install,
            message: message.into(),
            detail: None,
            candidate_failures: Vec::new(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ArtifactInstallErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn detail(&self) -> Option<&ArtifactInstallErrorDetail> {
        self.detail.as_ref()
    }

    #[must_use]
    pub fn candidate_failures(&self) -> &[ArtifactCandidateFailure] {
        &self.candidate_failures
    }

    pub(crate) fn install_with_detail(
        message: impl Into<String>,
        detail: ArtifactInstallErrorDetail,
    ) -> Self {
        Self {
            kind: ArtifactInstallErrorKind::Install,
            message: message.into(),
            detail: Some(detail),
            candidate_failures: Vec::new(),
        }
    }
}

impl fmt::Display for ArtifactInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ArtifactInstallError {}

impl ArtifactDownloader for reqwest::Client {
    async fn download_to_writer<W>(
        &self,
        url: &str,
        writer: &mut W,
        max_bytes: Option<u64>,
    ) -> Result<(), ArtifactInstallError>
    where
        W: Write + ?Sized,
    {
        let response = self
            .get(url)
            .send()
            .await
            .map_err(|err| ArtifactInstallError::download(err.to_string()))?;
        if !response.status().is_success() {
            return Err(ArtifactInstallError::download(format!(
                "HTTP {}",
                response.status()
            )));
        }
        write_response_body_limited(response, writer, max_bytes)
            .await
            .map_err(|err| ArtifactInstallError::download(err.to_string()))
    }
}

pub(crate) async fn download_candidate_to_writer_with_options<D, W>(
    downloader: &D,
    candidate: &ArtifactDownloadCandidate,
    writer: &mut W,
    max_bytes: Option<u64>,
) -> Result<(), ArtifactInstallError>
where
    D: ArtifactDownloader + ?Sized,
    W: Write + ?Sized + Send,
{
    downloader
        .download_to_writer(&candidate.url, writer, max_bytes)
        .await
}

pub(crate) async fn run_blocking_install<T, F>(operation: F) -> Result<T, ArtifactInstallError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ArtifactInstallError> + Send + 'static,
{
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|err| {
            ArtifactInstallError::install(format!("blocking install task failed: {err}"))
        })?
}

pub(crate) fn candidate_failure_message(
    candidate: &ArtifactDownloadCandidate,
    err: &ArtifactInstallError,
) -> ArtifactCandidateFailure {
    ArtifactCandidateFailure {
        kind: err.kind(),
        source_label: candidate.source_label.clone(),
        redacted_url: redact_url_for_error(&candidate.url),
        message: format!(
            "{}:{} -> {err}",
            candidate.source_label,
            redact_url_for_error(&candidate.url)
        ),
        detail: err.detail().cloned(),
    }
}

pub(crate) fn require_download_candidates(
    candidates: &[ArtifactDownloadCandidate],
    canonical_url: &str,
) -> Result<(), ArtifactInstallError> {
    if candidates.is_empty() {
        return Err(ArtifactInstallError::install(format!(
            "artifact install requires at least one download candidate for {}",
            redact_url_for_error(canonical_url)
        )));
    }

    Ok(())
}

pub(crate) fn failed_candidates_error(
    canonical_url: &str,
    errors: Vec<ArtifactCandidateFailure>,
) -> ArtifactInstallError {
    let kind = aggregate_failure_kind(&errors);
    let details = errors
        .iter()
        .map(|error| error.message.clone())
        .collect::<Vec<_>>()
        .join(" | ");
    let detail = (errors.len() == 1)
        .then(|| errors[0].detail.clone())
        .flatten();
    let canonical_url = redact_url_for_error(canonical_url);
    let message = match kind {
        ArtifactInstallErrorKind::Download => {
            format!("all artifact download candidates failed for {canonical_url}: {details}")
        }
        ArtifactInstallErrorKind::Install => format!(
            "all artifact candidates failed for {canonical_url}; at least one candidate reached install phase: {details}"
        ),
    };
    ArtifactInstallError {
        kind,
        message,
        detail,
        candidate_failures: errors,
    }
}

fn redact_url_for_error(raw: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(raw) else {
        return "<invalid-url>".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn aggregate_failure_kind(errors: &[ArtifactCandidateFailure]) -> ArtifactInstallErrorKind {
    if errors
        .iter()
        .any(|error| error.kind == ArtifactInstallErrorKind::Install)
    {
        ArtifactInstallErrorKind::Install
    } else {
        ArtifactInstallErrorKind::Download
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::{
        ArtifactCandidateFailure, ArtifactDownloadCandidate, ArtifactDownloader,
        ArtifactInstallError, ArtifactInstallErrorDetail, ArtifactInstallErrorKind,
        candidate_failure_message, download_candidate_to_writer_with_options,
        failed_candidates_error, require_download_candidates, run_blocking_install,
    };

    struct RecordingDownloader {
        visited_urls: Mutex<Vec<String>>,
        body: Vec<u8>,
    }

    impl RecordingDownloader {
        fn new(body: &[u8]) -> Self {
            Self {
                visited_urls: Mutex::new(Vec::new()),
                body: body.to_vec(),
            }
        }
    }

    impl ArtifactDownloader for RecordingDownloader {
        async fn download_to_writer<W>(
            &self,
            url: &str,
            writer: &mut W,
            _max_bytes: Option<u64>,
        ) -> Result<(), ArtifactInstallError>
        where
            W: Write + ?Sized,
        {
            self.visited_urls
                .lock()
                .expect("record visited urls")
                .push(url.to_string());
            writer
                .write_all(&self.body)
                .map_err(|err| ArtifactInstallError::download(err.to_string()))
        }
    }

    #[test]
    fn failed_candidates_error_stays_download_when_all_candidates_failed_to_download() {
        let candidate = ArtifactDownloadCandidate {
            url: "https://example.invalid/demo.zip".to_string(),
            source_label: "primary".to_string(),
        };

        let err = failed_candidates_error(
            "https://example.invalid/demo.zip",
            vec![candidate_failure_message(
                &candidate,
                &ArtifactInstallError::download("HTTP 404"),
            )],
        );

        assert_eq!(err.kind(), ArtifactInstallErrorKind::Download);
        assert!(
            err.to_string()
                .contains("all artifact download candidates failed"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn require_download_candidates_rejects_empty_candidate_lists() {
        let err = require_download_candidates(&[], "https://example.invalid/demo.zip")
            .expect_err("empty candidate lists must be rejected");

        assert_eq!(err.kind(), ArtifactInstallErrorKind::Install);
        assert!(err.candidate_failures().is_empty());
        assert!(
            err.to_string()
                .contains("requires at least one download candidate"),
            "unexpected message: {err}"
        );
    }

    #[test]
    fn failed_candidates_preserve_caller_defined_source_labels() {
        let mirror = ArtifactDownloadCandidate {
            url: "https://mirror.example.invalid/demo.zip".to_string(),
            source_label: "regional-mirror".to_string(),
        };
        let gateway = ArtifactDownloadCandidate {
            url: "https://gateway.example.invalid/demo.zip".to_string(),
            source_label: "signed gateway".to_string(),
        };

        let err = failed_candidates_error(
            "https://example.invalid/demo.zip",
            vec![
                candidate_failure_message(&mirror, &ArtifactInstallError::download("HTTP 404")),
                candidate_failure_message(
                    &gateway,
                    &ArtifactInstallError::install("archive extraction failed"),
                ),
            ],
        );

        let failures = err.candidate_failures();
        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].source_label(), "regional-mirror");
        assert_eq!(failures[1].source_label(), "signed gateway");
        assert!(failures[0].message().starts_with("regional-mirror:"));
        assert!(failures[1].message().starts_with("signed gateway:"));
    }

    #[test]
    fn failed_candidates_error_reports_install_when_any_candidate_reached_install_phase() {
        let candidate = ArtifactDownloadCandidate {
            url: "https://example.invalid/demo.zip".to_string(),
            source_label: "fallback".to_string(),
        };

        let err = failed_candidates_error(
            "https://example.invalid/demo.zip",
            vec![candidate_failure_message(
                &candidate,
                &ArtifactInstallError::install("archive extraction failed"),
            )],
        );

        assert_eq!(err.kind(), ArtifactInstallErrorKind::Install);
        assert!(
            err.to_string()
                .contains("at least one candidate reached install phase"),
            "unexpected message: {err}"
        );
        assert!(err.to_string().contains("archive extraction failed"));
    }

    #[test]
    fn install_phase_failure_message_does_not_claim_everything_failed_in_download_phase() {
        let download_candidate = ArtifactDownloadCandidate {
            url: "https://example.invalid/demo.zip".to_string(),
            source_label: "primary".to_string(),
        };
        let install_candidate = ArtifactDownloadCandidate {
            url: "https://mirror.example.invalid/demo.zip".to_string(),
            source_label: "fallback".to_string(),
        };

        let err = failed_candidates_error(
            "https://example.invalid/demo.zip",
            vec![
                candidate_failure_message(
                    &download_candidate,
                    &ArtifactInstallError::download("HTTP 404"),
                ),
                candidate_failure_message(
                    &install_candidate,
                    &ArtifactInstallError::install("archive extraction failed"),
                ),
            ],
        );

        assert_eq!(err.kind(), ArtifactInstallErrorKind::Install);
        assert!(
            !err.to_string().contains("all download candidates failed"),
            "unexpected message: {err}"
        );
        assert!(err.to_string().contains("archive extraction failed"));
    }

    #[test]
    fn failed_candidate_messages_redact_url_credentials_and_query() {
        let candidate = ArtifactDownloadCandidate {
            url: "https://token@example.invalid/demo.zip?sig=secret#frag".to_string(),
            source_label: "signed-mirror".to_string(),
        };

        let failure =
            candidate_failure_message(&candidate, &ArtifactInstallError::download("HTTP 403"));
        assert_eq!(failure.kind, ArtifactInstallErrorKind::Download);
        assert!(failure.message.contains("https://example.invalid/demo.zip"));
        assert!(!failure.message.contains("token@"));
        assert!(!failure.message.contains("sig=secret"));
        assert!(!failure.message.contains("#frag"));
    }

    #[test]
    fn failed_candidates_error_preserves_single_structured_detail() {
        let error = failed_candidates_error(
            "https://example.invalid/demo.zip",
            vec![ArtifactCandidateFailure {
                kind: ArtifactInstallErrorKind::Install,
                source_label: "primary".to_string(),
                redacted_url: "https://example.invalid/demo.zip".to_string(),
                message: "primary:https://example.invalid/demo.zip -> archive missing".to_string(),
                detail: Some(ArtifactInstallErrorDetail::ArchiveBinaryNotFound {
                    archive_format: omne_archive_primitives::BinaryArchiveFormat::Zip,
                    binary_name: "demo".to_string(),
                }),
            }],
        );

        assert_eq!(
            error.detail(),
            Some(&ArtifactInstallErrorDetail::ArchiveBinaryNotFound {
                archive_format: omne_archive_primitives::BinaryArchiveFormat::Zip,
                binary_name: "demo".to_string(),
            })
        );
        assert_eq!(error.candidate_failures().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn custom_downloader_can_stream_candidate_without_reqwest_client_surface() {
        let candidate = ArtifactDownloadCandidate {
            url: "https://example.invalid/demo.zip".to_string(),
            source_label: "primary".to_string(),
        };
        let downloader = RecordingDownloader::new(b"artifact-bytes");
        let mut buffer = Vec::new();

        download_candidate_to_writer_with_options(&downloader, &candidate, &mut buffer, None)
            .await
            .expect("download with custom downloader");

        assert_eq!(buffer, b"artifact-bytes");
        assert_eq!(
            downloader
                .visited_urls
                .into_inner()
                .expect("extract visited urls"),
            vec!["https://example.invalid/demo.zip".to_string()]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn run_blocking_install_does_not_block_async_runtime() {
        let started = Instant::now();
        let sleeper = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            started.elapsed()
        });

        run_blocking_install(|| {
            std::thread::sleep(Duration::from_millis(100));
            Ok::<_, ArtifactInstallError>(())
        })
        .await
        .expect("blocking install");

        let sleeper_elapsed = sleeper.await.expect("join sleeper");
        assert!(
            sleeper_elapsed < Duration::from_millis(80),
            "async runtime should keep making progress while install work is offloaded"
        );
    }
}
