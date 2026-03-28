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
- target binary matching by exact `archive_binary` hint or conventional `bin/<binary>` layout, with `tool_name` reserved for archive-format-specific fallbacks such as Git for Windows
- extraction of the matched binary bytes from the archive, limited by the exported `DEFAULT_MAX_EXTRACTED_BINARY_BYTES` budget sized for large official single-binary releases
- matched target validation that only accepts regular-file archive entries before reading content

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
