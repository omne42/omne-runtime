# Changelog

## [Unreleased]

- add a shared archive-tree walker with normalized path/link handling and extraction budgets, so higher-level callers stop duplicating tar/zip traversal hardening
- remove the deprecated `from_legacy_parts(..., tool_name, ...)` helper so the public contract is only `binary_name` plus optional exact `archive_binary_hint`, with no remaining tool-identity affordance at the primitive boundary
- cap archive-wide entry scanning during binary extraction so malicious tar/zip files cannot force unbounded linear scans before the requested binary is found
- require `archive_binary` to resolve to an exact archive-relative path instead of matching by suffix traversal order
- export the default extracted-binary budget
