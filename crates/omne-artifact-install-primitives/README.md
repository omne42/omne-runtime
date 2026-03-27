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
- direct binary artifact atomic installation
- binary-from-archive installation with a default extracted-byte budget
- archive-tree staging and replace installation with default extracted-byte and entry-count budgets
- tar archive-tree link extraction that fails closed if a parent directory chain contains symlink ancestors

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
