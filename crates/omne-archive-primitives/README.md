# omne-archive-primitives

Low-level archive/compression primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- archive format detection for binary delivery assets
- archive entry traversal for `.tar.gz`, `.tar.xz`, and `.zip`
- target binary matching by binary name, tool name, and optional `archive_binary` hint
- extraction of the matched binary bytes from the archive

## Non-Goals

- downloading archives
- filesystem writes, chmod, or atomic replacement
- hash verification or source trust policy
- product-specific install error mapping

## Verification

```bash
cargo test -p omne-archive-primitives
../../scripts/check-docs-system.sh
```
