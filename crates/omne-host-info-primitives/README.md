# omne-host-info-primitives

Low-level host platform and target-triple primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- host OS and architecture detection
- canonical target-triple mapping, including Linux `gnu` vs `musl` detection from current-process
  loader/libc mappings with fail-closed loader-marker fallback only when direct runtime evidence
  is unavailable; current-process evidence stays authoritative even if unrelated musl loader files
  exist on disk, and coarse distro markers such as `/etc/alpine-release` are no longer treated as
  sufficient libc evidence; when Linux libc still cannot be determined, host detection returns no
  platform/triple instead of guessing `*-unknown-linux-gnu`
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
