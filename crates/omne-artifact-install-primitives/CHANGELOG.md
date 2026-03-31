# Changelog

## [Unreleased]

- preserve a structured install-error detail when every archive-binary candidate fails for the same runtime reason, so callers can retry without parsing error strings
- cap ZIP symlink target reads so archive-tree extraction no longer buffers arbitrarily large link payloads into memory before validation
- clarify aggregated candidate failures so install-phase errors no longer report themselves as pure download failures
- serialize archive tree installs per destination with an advisory lock so concurrent installers cannot race staged directory replacement
- serialize direct binary installs and archive-binary installs per destination with the same advisory-lock model used by archive-tree replacement
- remove the unused archive-install `tool_name` request field so product-specific binary selection only flows through exact `archive_binary_hint`
- replace the hard-coded `ArtifactDownloadCandidateKind` enum with caller-defined `source_label` strings so candidate provenance stays product-agnostic
- move checksum verification, archive extraction, and staged commit work onto Tokio blocking threads so the async install APIs stop monopolizing runtime workers during heavy local install phases
