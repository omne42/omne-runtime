# omne-artifact-install-primitives

Reusable artifact download and install primitives shared by higher-level callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- ordered artifact download candidate execution
- empty candidate lists fail fast as caller-input errors instead of being misreported as download retries that all failed
- download entrypoints are generic over a caller-supplied `ArtifactDownloader`; this crate provides built-in integrations for `reqwest::Client` and `http-kit::HttpClientProfile` without leaking either transport type into the primitive contract
- optional SHA-256 verification for downloaded artifacts
- direct binary artifact atomic installation, serialized per destination during the install/commit phase
- binary-from-archive installation with the crate-local `DEFAULT_MAX_BINARY_ARCHIVE_EXTRACTED_BYTES` budget and crate-local archive-match metadata types, instead of re-exporting `omne-archive-primitives` symbols directly
- archive-tree installation via `omne-archive-primitives` shared walker plus `omne-fs-primitives` staged directory replacement and exported extracted-byte / entry-count budgets
- archive-tree entry materialization stays inside capability-backed handles opened on the staged directory, so regular files, symlinks, and hard links do not fall back to ambient path-based writes during extraction
- archive-tree link extraction that fails closed if a parent directory chain contains symlink ancestors
- Unix zip symlink materialization and tar forward hard-link resolution inside the staged tree
- exact archive-relative `archive_binary_hint` selection for product-specific binary layouts; no separate tool-name fallback remains
- install-phase errors keep a narrow structured detail when every attempted archive extraction failed for the same reason, so callers can make stable retry decisions without parsing error strings
- candidate provenance labels stay caller-defined via free-form `source_label`, instead of hard-coding product source enums into the primitive layer
- heavy local install phases such as checksum verification, archive extraction, and staged commit run on Tokio blocking threads instead of the async worker pool

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
