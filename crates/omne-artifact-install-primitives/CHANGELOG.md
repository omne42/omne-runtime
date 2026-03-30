# Changelog

## [Unreleased]

- cap ZIP symlink target reads so archive-tree extraction no longer buffers arbitrarily large link payloads into memory before validation
- clarify aggregated candidate failures so install-phase errors no longer report themselves as pure download failures
- serialize archive tree installs per destination with an advisory lock so concurrent installers cannot race staged directory replacement
- remove the unused archive-install `tool_name` request field so product-specific binary selection only flows through exact `archive_binary_hint`
- move checksum verification, archive extraction, and staged commit work onto Tokio blocking threads so the async install APIs stop monopolizing runtime workers during heavy local install phases
