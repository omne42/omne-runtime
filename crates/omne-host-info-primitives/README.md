# omne-host-info-primitives

Low-level host platform and target-triple primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- host OS and architecture detection
- canonical target-triple mapping, including Linux `gnu` vs `musl` detection from local ABI markers
- validated target override normalization for the crate's supported canonical triples, with checked
  APIs that return structured errors and compatibility helpers that fail closed
- home-directory resolution
- executable suffix inference for validated canonical target triples, with checked APIs plus
  fail-closed compatibility helpers

## Non-Goals

- product directory layout
- package-manager integration
- installation orchestration
- CLI behavior

## Verification

```bash
cargo test -p omne-host-info-primitives
../../scripts/check-docs-system.sh
```
