# Changelog

## [Unreleased]

- route archive-tree entry materialization through capability-backed staging-directory handles
  instead of ambient path-based `create_dir` / `File::create` / `hard_link`, so symlink ancestor
  checks stay bound to the staged tree boundary during extraction
- move archive-tree tar/zip/xz traversal onto `omne-archive-primitives`, so this crate keeps only staged-directory materialization and destination-boundary enforcement
- reject empty artifact candidate lists with an explicit caller-input error instead of claiming that all downloads failed
- preserve a structured install-error detail when every archive-binary candidate fails for the same runtime reason, so callers can retry without parsing error strings
- cap ZIP symlink target reads so archive-tree extraction no longer buffers arbitrarily large link payloads into memory before validation
- clarify aggregated candidate failures so install-phase errors no longer report themselves as pure download failures
- serialize archive tree installs per destination with an advisory lock so concurrent installers cannot race staged directory replacement
- serialize direct binary installs and archive-binary installs per destination with the same advisory-lock model used by archive-tree replacement
- bind artifact install advisory-lock roots to the same no-follow destination parent validation as staged writes, so lock namespaces cannot drift through symlinked ancestors
- remove the unused archive-install `tool_name` request field so product-specific binary selection only flows through exact `archive_binary_hint`
- replace public `reqwest::Client` parameters with a narrow `ArtifactDownloader` contract, while keeping built-in integrations for `reqwest::Client` and `http-kit::HttpClientProfile`
- replace the hard-coded `ArtifactDownloadCandidateKind` enum with caller-defined `source_label` strings so candidate provenance stays product-agnostic
- move checksum verification, archive extraction, and staged commit work onto Tokio blocking threads so the async install APIs stop monopolizing runtime workers during heavy local install phases
- add regression coverage that product-specific archive layouts only install via exact `archive_binary_hint`, so archive selection cannot drift back to extra product fields or hidden fallbacks
