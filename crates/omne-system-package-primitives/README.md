# omne-system-package-primitives

Low-level system package primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- exact canonical package-manager recognition; non-canonical case changes or surrounding
  whitespace are rejected instead of being normalized implicitly
- validated `SystemPackageName` parsing for package identifiers before recipe construction,
  preserving platform path-separator semantics instead of treating Unix `\\` as a separator
- package-manager enum modeling
- install recipe construction from validated package names using only the canonical install verb and
  package token; prompt suppression, cache policy, and similar workflow flags stay with callers
- operating-system parsing that distinguishes known OS values from unknown OS strings
- default package-manager order for recipe-capable OS values, with explicit unsupported-platform
  errors instead of silently returning an empty recipe list when a known OS like `windows` has no
  default system-package recipe fallback

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
