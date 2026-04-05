# omne-artifact-install-primitives

Reusable artifact download and install primitives shared by higher-level callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- ordered artifact download candidate execution
- optional SHA-256 verification for downloaded artifacts
- direct binary artifact atomic installation, serialized per destination during the install phase
- binary-from-archive installation with the exported `DEFAULT_MAX_EXTRACTED_BINARY_BYTES` budget and the same per-destination install lock
- archive-tree installation via `omne-fs-primitives` staged directory replacement plus exported extracted-byte and entry-count budgets
- archive-tree link extraction that fails closed if a parent directory chain contains symlink ancestors
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
