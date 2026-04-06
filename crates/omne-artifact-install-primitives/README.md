# omne-artifact-install-primitives

Reusable artifact download and install primitives shared by higher-level callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- ordered artifact download candidate execution
- public download/install entrypoints that depend on the crate-local `ArtifactDownloader` boundary
  instead of hard-coding a concrete HTTP client type; `reqwest::Client` remains supported via the
  built-in adapter impl
- optional SHA-256 verification for downloaded artifacts
- structured install errors that preserve candidate-level failures and key archive extraction
  details such as `ArchiveBinaryNotFound`, so callers do not have to branch on display strings
- direct binary artifact atomic installation, serialized per destination during the install phase
- binary-from-archive installation with the exported `DEFAULT_MAX_EXTRACTED_BINARY_BYTES` budget and the same per-destination install lock
- archive-tree installation via `omne-fs-primitives` staged directory replacement plus exported extracted-byte and entry-count budgets
- archive-tree link extraction that fails closed if the staged destination root or any staged parent directory chain component is a symlink ancestor
- archive-tree regular-file, symlink, and hard-link materialization through `omne-fs-primitives` capability directories so staged extraction never trusts ambient leaf paths
- archive-tree staging now clones the bound staged directory handle directly into extraction, so parent-path swaps after staging cannot retarget unzip/untar writes or the final replace step
- Unix zip symlink materialization and tar forward hard-link resolution inside the staged tree

## Non-Goals

- GitHub release metadata or source-selection policy
- package/tool specific destination policy
- product-specific error codes or result DTOs
- CLI surfaces

## Verification

```bash
cargo test -p omne-artifact-install-primitives
../../scripts/check-docs-system.sh
```
