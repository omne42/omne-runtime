# omne-host-info-primitives

Low-level host platform and target-triple primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- host OS and architecture detection
- canonical target-triple mapping, including fail-closed Linux `gnu` vs `musl` detection before a
  default host triple is exposed; Linux runtime probes also fall back to standard absolute command
  paths so narrowed `PATH` environments do not erase host detection
- target override normalization with supported-triple validation
- home-directory resolution
- executable suffix inference from validated canonical target triples

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
