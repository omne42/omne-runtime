# Changelog

## [Unreleased]

- support `.tar.bz2` for shared binary archive extraction and archive-tree walking, so callers do not need to hand-roll bzip2 tar traversal
- add a shared archive-tree walker with normalized path/link handling and extraction budgets, so higher-level callers stop duplicating tar/zip traversal hardening
- remove the deprecated legacy constructor so the public contract is only `binary_name` plus optional exact `archive_binary_hint`, with no remaining tool-identity affordance at the primitive boundary
- cap archive-wide entry scanning during binary extraction so malicious tar/zip files cannot force unbounded linear scans before the requested binary is found
- require `archive_binary` to resolve to an exact archive-relative path instead of matching by suffix traversal order
- fail closed when multiple `bin/<binary>` candidates exist without an exact hint, instead of picking the first match by archive traversal order
- accept a top-level `bin/<binary>` archive layout during hintless auto-match, while still failing closed if that introduces ambiguity
- export the default extracted-binary budget
