# Changelog

## [Unreleased]

- cap ZIP symlink target reads so archive-tree extraction no longer buffers arbitrarily large link payloads into memory before validation
- clarify aggregated candidate failures so install-phase errors no longer report themselves as pure download failures
- serialize archive tree installs per destination with an advisory lock so concurrent installers cannot race staged directory replacement
- serialize direct binary and binary-from-archive installs per destination during the install phase so concurrent installers cannot race file replacement
- drop the unused `tool_name` field from `BinaryArchiveInstallRequest` and the matching `install_binary_from_archive` parameter
- route archive-tree regular-file, symlink, and hard-link writes through `omne-fs-primitives` capability directories so staged extraction no longer does leaf `remove_file`/`create`/`hard_link` by ambient paths
- keep archive-tree staged-root traversal fail-closed while still allowing pre-existing ambient symlink ancestors such as macOS `/var -> /private/var`
