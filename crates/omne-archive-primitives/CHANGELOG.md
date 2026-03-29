# Changelog

## [Unreleased]

- stop interpreting `BinaryArchiveRequest::tool_name` inside the primitive and require callers to use exact `archive_binary` hints for product-specific archive layouts
- cap archive-wide entry scanning during binary extraction so malicious tar/zip files cannot force unbounded linear scans before the requested binary is found
- require `archive_binary` to resolve to an exact archive-relative path instead of matching by suffix traversal order
- export the default extracted-binary budget and document that `tool_name` is retained only for compatibility
