# Changelog

## [Unreleased]

- add a shared archive-tree walker with normalized path/link handling and extraction budgets, so higher-level callers stop duplicating tar/zip traversal hardening
- remove the unused `BinaryArchiveRequest::tool_name` field and explicitly collapse the contract to `binary_name` plus optional exact `archive_binary_hint`; keep a deprecated `from_legacy_parts(..., tool_name, ...)` helper for migration, but product-specific layouts are no longer inferred from tool identity
- cap archive-wide entry scanning during binary extraction so malicious tar/zip files cannot force unbounded linear scans before the requested binary is found
- require `archive_binary` to resolve to an exact archive-relative path instead of matching by suffix traversal order
- export the default extracted-binary budget
