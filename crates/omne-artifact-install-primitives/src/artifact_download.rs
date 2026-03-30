use std::borrow::Cow;
use std::fmt;
use std::io::Write;

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

pub(crate) async fn download_candidate_to_writer_with_options<W>(
    client: &reqwest::Client,
    candidate: &ArtifactDownloadCandidate,
    writer: &mut W,
    max_bytes: Option<u64>,
) -> Result<(), ArtifactInstallError>
where
    W: Write + ?Sized,
{
    let response = client
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
}

pub(crate) fn candidate_failure_message(
    candidate: &ArtifactDownloadCandidate,
    err: &ArtifactInstallError,
) -> CandidateFailure {
    CandidateFailure {
        kind: err.kind(),
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
    use super::{
        ArtifactDownloadCandidate, ArtifactInstallError, ArtifactInstallErrorKind,
        candidate_failure_message, failed_candidates_error,
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
        assert!(
            failure
                .message
                .starts_with("candidate:https://example.invalid/demo.zip")
        );
    }
}
