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
- target binary matching only by exact `archive_binary_hint` or conventional `bin/<binary>` layout; there is no remaining tool-name-based layout inference
- extraction of the matched binary bytes from the archive, limited by the exported `DEFAULT_MAX_EXTRACTED_BINARY_BYTES` budget sized for large official single-binary releases
- matched target validation that only accepts regular-file archive entries before reading content
- archive-tree walking with shared entry-count / extracted-byte budgets and normalized path or link targets, so higher layers do not need to duplicate tar/zip traversal hardening

If a caller needs to target a layout such as `PortableGit/cmd/git.exe`, it must pass that exact
archive-relative path through `archive_binary_hint`.

`BinaryArchiveRequest::new(binary_name)` plus `with_archive_binary_hint(...)` is the full public
construction path.

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
