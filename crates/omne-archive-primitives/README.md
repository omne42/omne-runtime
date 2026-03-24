# omne-archive-primitives

Low-level archive/compression primitives shared across callers.

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
