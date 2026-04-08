# Changelog

## [Unreleased]

- cap ZIP symlink target reads so archive-tree extraction no longer buffers arbitrarily large link payloads into memory before validation
- clarify aggregated candidate failures so install-phase errors no longer report themselves as pure download failures
- serialize direct binary installs per destination with the same advisory-lock contract already used by archive-tree installs
- offload checksum verification, archive extraction, and atomic commit work from async worker threads onto blocking install tasks
- serialize archive tree installs per destination with an advisory lock so concurrent installers cannot race staged directory replacement
