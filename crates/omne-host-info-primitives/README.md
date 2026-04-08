# omne-host-info-primitives

Low-level host platform and target-triple primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- host OS and architecture detection
- canonical host-platform mapping, including Linux hosts whose libc stays explicitly unknown when
  direct runtime evidence and trusted absolute loader markers cannot distinguish `gnu` vs `musl`
- canonical target-triple mapping for host platforms with known Linux libc, with checked host
  APIs that surface `LinuxLibcUnknown` instead of collapsing unknown Linux hosts into
  `*-unknown-linux-gnu`
- Linux `gnu` vs `musl` detection from current-process loader/libc mappings with fail-closed
  loader-marker fallback only when direct runtime evidence is unavailable; current-process
  evidence stays authoritative even if unrelated musl loader files exist on disk, coarse distro
  markers such as `/etc/alpine-release` are not treated as sufficient libc evidence, and unknown
  Linux libc continues to fail closed
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
