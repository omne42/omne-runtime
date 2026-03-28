# omne-system-package-primitives

Low-level system package primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- canonical package-manager recognition
- package-manager enum modeling
- validated system-package-name modeling and install recipe construction
- default package-manager order per OS

## Non-Goals

- command execution
- package installation orchestration
- host detection
- plan methods or product tool/package mapping
- CLI behavior

`SystemPackageName` is intentionally narrower than an arbitrary string: callers must validate a
package identifier before turning it into argv so this crate does not silently normalize option-like
or whitespace-bearing input into install recipes.

## Verification

```bash
cargo test -p omne-system-package-primitives
../../scripts/check-docs-system.sh
```
