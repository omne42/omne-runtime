# omne-system-package-primitives

Low-level system package primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- canonical package-manager recognition
- validated `SystemPackageName` parsing for package identifiers before recipe construction
- package-manager enum modeling
- install recipe construction from validated package names, plus `try_*` helpers for string callers
- default package-manager order per OS

## Non-Goals

- command execution
- package installation orchestration
- host detection
- plan methods or product tool/package mapping
- CLI behavior

## Verification

```bash
cargo test -p omne-system-package-primitives
../../scripts/check-docs-system.sh
```
