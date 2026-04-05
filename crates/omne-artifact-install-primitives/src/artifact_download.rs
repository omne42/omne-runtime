use std::fmt;
use std::future::Future;
use std::io::Write;

use http_kit::write_response_body_limited;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactDownloadCandidateKind {
    Gateway,
    Canonical,
    Mirror,
}

impl ArtifactDownloadCandidateKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Gateway => "gateway",
            Self::Canonical => "canonical",
            Self::Mirror => "mirror",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDownloadCandidate {
    pub url: String,
    pub kind: ArtifactDownloadCandidateKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactInstallErrorKind {
    Download,
    Install,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidateFailure {
    pub(crate) kind: ArtifactInstallErrorKind,
    pub(crate) message: String,
}

#[derive(Debug, Clone)]
pub struct ArtifactInstallError {
    kind: ArtifactInstallErrorKind,
    message: String,
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
        }
    }

    pub fn install(message: impl Into<String>) -> Self {
        Self {
            kind: ArtifactInstallErrorKind::Install,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ArtifactInstallErrorKind {
        self.kind
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
) -> CandidateFailure {
    CandidateFailure {
        kind: err.kind(),
        message: format!(
            "{}:{} -> {err}",
            candidate.kind.label(),
            redact_url_for_error(&candidate.url)
        ),
    }
}

pub(crate) fn failed_candidates_error(
    canonical_url: &str,
    errors: Vec<CandidateFailure>,
) -> ArtifactInstallError {
    let kind = aggregate_failure_kind(&errors);
    let details = errors
        .into_iter()
        .map(|error| error.message)
        .collect::<Vec<_>>()
        .join(" | ");
    let canonical_url = redact_url_for_error(canonical_url);
    match kind {
        ArtifactInstallErrorKind::Download => ArtifactInstallError::download(format!(
            "all artifact download candidates failed for {canonical_url}: {details}"
        )),
        ArtifactInstallErrorKind::Install => ArtifactInstallError::install(format!(
            "all artifact candidates failed for {canonical_url}; at least one candidate reached install phase: {details}"
        )),
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

fn aggregate_failure_kind(errors: &[CandidateFailure]) -> ArtifactInstallErrorKind {
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
    use std::future::Future;
    use std::io::Write;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use super::{
        ArtifactDownloadCandidate, ArtifactDownloadCandidateKind, ArtifactDownloader,
        ArtifactInstallError, ArtifactInstallErrorKind, candidate_failure_message,
        download_candidate_to_writer_with_options, failed_candidates_error, run_blocking_install,
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
        fn download_to_writer<W>(
            &self,
            url: &str,
            writer: &mut W,
            _max_bytes: Option<u64>,
        ) -> impl Future<Output = Result<(), ArtifactInstallError>>
        where
            W: Write + ?Sized,
        {
            async move {
                self.visited_urls
                    .lock()
                    .expect("record visited urls")
                    .push(url.to_string());
                writer
                    .write_all(&self.body)
                    .map_err(|err| ArtifactInstallError::download(err.to_string()))
            }
        }
    }

    #[test]
    fn failed_candidates_error_stays_download_when_all_candidates_failed_to_download() {
        let candidate = ArtifactDownloadCandidate {
            url: "https://example.invalid/demo.zip".to_string(),
            kind: ArtifactDownloadCandidateKind::Canonical,
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
    fn failed_candidates_error_reports_install_when_any_candidate_reached_install_phase() {
        let candidate = ArtifactDownloadCandidate {
            url: "https://example.invalid/demo.zip".to_string(),
            kind: ArtifactDownloadCandidateKind::Mirror,
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
            kind: ArtifactDownloadCandidateKind::Canonical,
        };
        let install_candidate = ArtifactDownloadCandidate {
            url: "https://mirror.example.invalid/demo.zip".to_string(),
            kind: ArtifactDownloadCandidateKind::Mirror,
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
            kind: ArtifactDownloadCandidateKind::Canonical,
        };

        let failure =
            candidate_failure_message(&candidate, &ArtifactInstallError::download("HTTP 403"));
        assert_eq!(failure.kind, ArtifactInstallErrorKind::Download);
        assert!(failure.message.contains("https://example.invalid/demo.zip"));
        assert!(!failure.message.contains("token@"));
        assert!(!failure.message.contains("sig=secret"));
        assert!(!failure.message.contains("#frag"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn custom_downloader_can_stream_candidate_without_reqwest_client_surface() {
        let candidate = ArtifactDownloadCandidate {
            url: "https://example.invalid/demo.zip".to_string(),
            kind: ArtifactDownloadCandidateKind::Canonical,
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
