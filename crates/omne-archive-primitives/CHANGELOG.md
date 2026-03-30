# Changelog

## [Unreleased]

- remove the unused `BinaryArchiveRequest::tool_name` field; product-specific archive layouts must now be selected only by exact `archive_binary_hint`
- cap archive-wide entry scanning during binary extraction so malicious tar/zip files cannot force unbounded linear scans before the requested binary is found
- require `archive_binary` to resolve to an exact archive-relative path instead of matching by suffix traversal order
- export the default extracted-binary budget
