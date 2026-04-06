# Changelog

## [Unreleased]

- reject empty artifact candidate lists up front so public install/download entrypoints report caller input errors instead of the misleading "all candidates failed" aggregate
- make the public download/install entrypoints generic over a narrow `ArtifactDownloader` trait,
  so callers are no longer forced to expose `reqwest::Client` at the primitive boundary while the
  built-in `reqwest` adapter remains available for current integrations
- derive archive-tree install lock names from a normalized destination identity so root aliases and lexical path aliases cannot bypass per-target serialization
- cap ZIP symlink target reads so archive-tree extraction no longer buffers arbitrarily large link payloads into memory before validation
- clarify aggregated candidate failures so install-phase errors no longer report themselves as pure download failures
- serialize archive tree installs per destination with an advisory lock so concurrent installers cannot race staged directory replacement
- serialize direct binary and binary-from-archive installs per destination during the install phase so concurrent installers cannot race file replacement
- preserve structured archive install failure details and candidate-level failure lists on `ArtifactInstallError`, so callers can branch on cases like missing archive binaries without string parsing
- drop the unused `tool_name` field from `BinaryArchiveInstallRequest` and the matching `install_binary_from_archive` parameter
- route archive-tree regular-file, symlink, and hard-link writes through `omne-fs-primitives` capability directories so staged extraction no longer does leaf `remove_file`/`create`/`hard_link` by ambient paths
- keep archive-tree extraction and final directory replace bound to the validated staged directory / parent directory handles so parent-path swaps after staging fail closed instead of drifting into symlink targets
- keep archive-tree staged-root traversal fail-closed while still allowing pre-existing ambient symlink ancestors such as macOS `/var -> /private/var`
