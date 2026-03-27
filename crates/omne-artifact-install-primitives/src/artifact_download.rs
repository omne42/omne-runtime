use std::fmt;
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
        message: format!("{}:{} -> {err}", candidate.kind.label(), candidate.url),
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
    match kind {
        ArtifactInstallErrorKind::Download => ArtifactInstallError::download(format!(
            "all download candidates failed for {canonical_url}: {details}"
        )),
        ArtifactInstallErrorKind::Install => ArtifactInstallError::install(format!(
            "all download candidates failed for {canonical_url}: {details}"
        )),
    }
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
        ArtifactDownloadCandidate, ArtifactDownloadCandidateKind, ArtifactInstallError,
        ArtifactInstallErrorKind, candidate_failure_message, failed_candidates_error,
    };

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
        assert!(err.to_string().contains("archive extraction failed"));
    }
}
