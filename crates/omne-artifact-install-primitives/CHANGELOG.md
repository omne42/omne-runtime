# Changelog

## [Unreleased]

- redact download-layer URLs before they reach public artifact-install errors, and add regression
  coverage so credentials, query parameters, and fragments cannot leak back through reqwest or
  aggregated candidate failure messages
- replace the hard-coded `Gateway|Canonical|Mirror` candidate enum with caller-provided source
  labels, so the primitive keeps candidate error attribution without baking product source strategy
  into the public API
- classify SHA-256 mismatches as install-phase failures once artifact bytes have been fetched, so aggregate errors no longer misreport integrity failures as pure download issues
- reject empty artifact candidate lists up front so public install/download entrypoints report caller input errors instead of the misleading "all candidates failed" aggregate
- make the public download/install entrypoints generic over a narrow `ArtifactDownloader` trait,
  so callers are no longer forced to expose `reqwest::Client` at the primitive boundary while the
  built-in `reqwest` adapter remains available for current integrations
- derive archive-tree install lock names from a normalized destination identity so root aliases and lexical path aliases cannot bypass per-target serialization
- cap ZIP symlink target reads so archive-tree extraction no longer buffers arbitrarily large link payloads into memory before validation
- clarify aggregated candidate failures so install-phase errors no longer report themselves as pure download failures
- serialize archive tree installs per destination with an advisory lock so concurrent installers cannot race staged directory replacement
- serialize direct binary and binary-from-archive installs for the full per-destination install attempt, with lock names derived from normalized destination identity so concurrent installers cannot race the same target into nondeterministic last-writer-wins
- preserve structured archive install failure details and candidate-level failure lists on `ArtifactInstallError`, so callers can branch on cases like missing archive binaries without string parsing
- preserve the new ambiguous archive-binary extraction detail on `ArtifactInstallError`, so callers can distinguish "not found" from "multiple exact `bin/<binary>` candidates" without falling back to string parsing
- remove the deprecated `from_legacy_parts(..., tool_name, ...)` helper so archive-backed installs only expose `binary_name` plus optional exact `archive_binary_hint` at the primitive boundary
- route archive-tree regular-file, symlink, and hard-link writes through `omne-fs-primitives` capability directories so staged extraction no longer does leaf `remove_file`/`create`/`hard_link` by ambient paths
- keep archive-tree extraction and final directory replace bound to the validated staged directory / parent directory handles so parent-path swaps after staging fail closed instead of drifting into symlink targets
- keep archive-tree staged-root traversal fail-closed while still allowing pre-existing ambient symlink ancestors such as macOS `/var -> /private/var`
- add regression coverage that preserves caller-defined candidate `source_label` values in
  aggregated failure surfaces, so the primitive boundary cannot silently regress back to a fixed
  source enum
- route archive-tree archive parsing, path sanitization, link validation, and extraction-budget
  accounting back through `omne-archive-primitives`, so `artifact-install` stops maintaining a
  second copy of archive semantics outside the shared archive boundary
