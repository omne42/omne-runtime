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
- normalized-path no-follow regular-file reads and appendable regular-file validation/open helpers
- bounded reads for text and byte streams
- staged atomic file/directory replacement and advisory locking
- parent-directory materialization for atomic staging that rejects non-root symlink ancestors instead of following them ambiently, while normalizing only known platform root aliases such as macOS `/var` and `/tmp`
- handle-bound staged file/directory commit paths so parent-path swaps after validation cannot silently retarget atomic replace into a symlink destination

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
