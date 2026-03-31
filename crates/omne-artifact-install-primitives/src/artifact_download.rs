use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::io::Write;
use std::pin::Pin;

use http_kit::write_response_body_limited;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDownloadCandidate {
    pub url: String,
    pub source_label: String,
}

impl ArtifactDownloadCandidate {
    fn display_source_label(&self) -> Cow<'_, str> {
        if self.source_label.trim().is_empty() {
            Cow::Borrowed("candidate")
        } else {
            Cow::Borrowed(self.source_label.as_str())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactInstallErrorKind {
    Download,
    Install,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactInstallErrorDetail {
    ArchiveBinaryNotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CandidateFailure {
    pub(crate) kind: ArtifactInstallErrorKind,
    pub(crate) detail: Option<ArtifactInstallErrorDetail>,
    pub(crate) message: String,
}

#[derive(Debug, Clone)]
pub struct ArtifactInstallError {
    kind: ArtifactInstallErrorKind,
    detail: Option<ArtifactInstallErrorDetail>,
    message: String,
}

impl ArtifactInstallError {
    pub fn download(message: impl Into<String>) -> Self {
        Self {
            kind: ArtifactInstallErrorKind::Download,
            detail: None,
            message: message.into(),
        }
    }

    pub fn install(message: impl Into<String>) -> Self {
        Self {
            kind: ArtifactInstallErrorKind::Install,
            detail: None,
            message: message.into(),
        }
    }

    pub fn install_with_detail(
        detail: ArtifactInstallErrorDetail,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind: ArtifactInstallErrorKind::Install,
            detail: Some(detail),
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ArtifactInstallErrorKind {
        self.kind
    }

    #[must_use]
    pub const fn detail(&self) -> Option<ArtifactInstallErrorDetail> {
        self.detail
    }
}

impl fmt::Display for ArtifactInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ArtifactInstallError {}

pub type ArtifactDownloadFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), ArtifactInstallError>> + Send + 'a>>;

pub trait ArtifactDownloader {
    fn download_to_writer<'a, W>(
        &'a self,
        candidate: &'a ArtifactDownloadCandidate,
        writer: &'a mut W,
        max_bytes: Option<u64>,
    ) -> ArtifactDownloadFuture<'a>
    where
        W: Write + Send + ?Sized + 'a;
}

impl ArtifactDownloader for reqwest::Client {
    fn download_to_writer<'a, W>(
        &'a self,
        candidate: &'a ArtifactDownloadCandidate,
        writer: &'a mut W,
        max_bytes: Option<u64>,
    ) -> ArtifactDownloadFuture<'a>
    where
        W: Write + Send + ?Sized + 'a,
    {
        Box::pin(async move {
            let response = self
                .get(&candidate.url)
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
        })
    }
}

impl ArtifactDownloader for http_kit::HttpClientProfile {
    fn download_to_writer<'a, W>(
        &'a self,
        candidate: &'a ArtifactDownloadCandidate,
        writer: &'a mut W,
        max_bytes: Option<u64>,
    ) -> ArtifactDownloadFuture<'a>
    where
        W: Write + Send + ?Sized + 'a,
    {
        ArtifactDownloader::download_to_writer(self.client(), candidate, writer, max_bytes)
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
    W: Write + Send + ?Sized,
{
    downloader
        .download_to_writer(candidate, writer, max_bytes)
        .await
}

pub(crate) fn candidate_failure_message(
    candidate: &ArtifactDownloadCandidate,
    err: &ArtifactInstallError,
) -> CandidateFailure {
    CandidateFailure {
        kind: err.kind(),
        detail: err.detail(),
        message: format!(
            "{}:{} -> {err}",
            candidate.display_source_label(),
            redact_url_for_error(&candidate.url)
        ),
    }
}

pub(crate) fn failed_candidates_error(
    canonical_url: &str,
    errors: Vec<CandidateFailure>,
) -> ArtifactInstallError {
    let kind = aggregate_failure_kind(&errors);
    let detail = aggregate_failure_detail(&errors);
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
        ArtifactInstallErrorKind::Install => {
            let message = format!(
                "all artifact candidates failed for {canonical_url}; at least one candidate reached install phase: {details}"
            );
            if let Some(detail) = detail {
                ArtifactInstallError::install_with_detail(detail, message)
            } else {
                ArtifactInstallError::install(message)
            }
        }
    }
}

pub(crate) fn no_candidates_error(canonical_url: &str) -> ArtifactInstallError {
    ArtifactInstallError::download(format!(
        "artifact install requires at least one download candidate for {}",
        redact_url_for_error(canonical_url)
    ))
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

fn aggregate_failure_detail(errors: &[CandidateFailure]) -> Option<ArtifactInstallErrorDetail> {
    let mut install_failures = errors
        .iter()
        .filter(|error| error.kind == ArtifactInstallErrorKind::Install);
    let first_detail = install_failures.next()?.detail?;
    install_failures
        .all(|error| error.detail == Some(first_detail))
        .then_some(first_detail)
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactDownloadCandidate, ArtifactInstallError, ArtifactInstallErrorDetail,
        ArtifactInstallErrorKind, candidate_failure_message, failed_candidates_error,
        no_candidates_error,
    };

    #[test]
    fn failed_candidates_error_stays_download_when_all_candidates_failed_to_download() {
        let candidate = ArtifactDownloadCandidate {
            url: "https://example.invalid/demo.zip".to_string(),
            source_label: "canonical".to_string(),
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
            source_label: "mirror".to_string(),
        };

        let err = failed_candidates_error(
            "https://example.invalid/demo.zip",
            vec![candidate_failure_message(
                &candidate,
                &ArtifactInstallError::install("archive extraction failed"),
            )],
        );

        assert_eq!(err.kind(), ArtifactInstallErrorKind::Install);
        assert_eq!(err.detail(), None);
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
            source_label: "canonical".to_string(),
        };
        let install_candidate = ArtifactDownloadCandidate {
            url: "https://mirror.example.invalid/demo.zip".to_string(),
            source_label: "mirror".to_string(),
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
        assert_eq!(err.detail(), None);
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
            source_label: "canonical".to_string(),
        };

        let failure =
            candidate_failure_message(&candidate, &ArtifactInstallError::download("HTTP 403"));
        assert_eq!(failure.kind, ArtifactInstallErrorKind::Download);
        assert_eq!(failure.detail, None);
        assert!(failure.message.contains("https://example.invalid/demo.zip"));
        assert!(!failure.message.contains("token@"));
        assert!(!failure.message.contains("sig=secret"));
        assert!(!failure.message.contains("#frag"));
    }

    #[test]
    fn failed_candidate_messages_fallback_when_source_label_is_blank() {
        let candidate = ArtifactDownloadCandidate {
            url: "https://example.invalid/demo.zip".to_string(),
            source_label: "   ".to_string(),
        };

        let failure =
            candidate_failure_message(&candidate, &ArtifactInstallError::download("HTTP 404"));
        assert_eq!(failure.detail, None);
        assert!(
            failure
                .message
                .starts_with("candidate:https://example.invalid/demo.zip")
        );
    }

    #[test]
    fn failed_candidates_error_preserves_shared_install_detail() {
        let candidate = ArtifactDownloadCandidate {
            url: "https://example.invalid/demo.zip".to_string(),
            source_label: "canonical".to_string(),
        };

        let err = failed_candidates_error(
            "https://example.invalid/demo.zip",
            vec![candidate_failure_message(
                &candidate,
                &ArtifactInstallError::install_with_detail(
                    ArtifactInstallErrorDetail::ArchiveBinaryNotFound,
                    "binary `demo` not found in zip archive",
                ),
            )],
        );

        assert_eq!(err.kind(), ArtifactInstallErrorKind::Install);
        assert_eq!(
            err.detail(),
            Some(ArtifactInstallErrorDetail::ArchiveBinaryNotFound)
        );
    }

    #[test]
    fn failed_candidates_error_drops_install_detail_when_install_failures_disagree() {
        let mirror = ArtifactDownloadCandidate {
            url: "https://mirror.example.invalid/demo.zip".to_string(),
            source_label: "mirror".to_string(),
        };
        let gateway = ArtifactDownloadCandidate {
            url: "https://gateway.example.invalid/demo.zip".to_string(),
            source_label: "gateway".to_string(),
        };

        let err = failed_candidates_error(
            "https://example.invalid/demo.zip",
            vec![
                candidate_failure_message(
                    &mirror,
                    &ArtifactInstallError::install_with_detail(
                        ArtifactInstallErrorDetail::ArchiveBinaryNotFound,
                        "binary `demo` not found in zip archive",
                    ),
                ),
                candidate_failure_message(
                    &gateway,
                    &ArtifactInstallError::install("permission denied"),
                ),
            ],
        );

        assert_eq!(err.kind(), ArtifactInstallErrorKind::Install);
        assert_eq!(err.detail(), None);
    }

    #[test]
    fn no_candidates_error_reports_missing_candidate_list() {
        let err = no_candidates_error("https://token@example.invalid/demo.zip?sig=secret");

        assert_eq!(err.kind(), ArtifactInstallErrorKind::Download);
        assert!(
            err.to_string()
                .contains("requires at least one download candidate"),
            "unexpected message: {err}"
        );
        assert!(err.to_string().contains("https://example.invalid/demo.zip"));
        assert!(!err.to_string().contains("token@"));
        assert!(!err.to_string().contains("sig=secret"));
    }
}
