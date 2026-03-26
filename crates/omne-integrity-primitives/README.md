# omne-integrity-primitives

Low-level integrity primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- `sha256:<hex>` parsing
- raw hex digest parsing
- SHA-256 hashing for bytes and readers
- structured checksum mismatch errors

## Non-Goals

- HTTP downloads
- release metadata fetching
- source selection
- installation orchestration

## Verification

```bash
cargo test -p omne-integrity-primitives
../../scripts/check-docs-system.sh
```
