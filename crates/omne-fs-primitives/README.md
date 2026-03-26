# omne-fs-primitives

Low-level filesystem primitives shared by higher-level callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- capability-style root opening and directory traversal
- no-follow file opening and symlink/reparse classification
- bounded reads for text and byte streams
- staged atomic writes and advisory locking

## Non-Goals

- filesystem policy interpretation
- secret redaction or permission decisions
- CLI surfaces
- OS sandbox orchestration

## Verification

```bash
cargo test -p omne-fs-primitives
../../scripts/check-docs-system.sh
```
