# Changelog

## [Unreleased]

- reject non-root symlink ancestors while materializing parent directories for staged atomic file/directory writes, while normalizing platform root aliases such as macOS `/var`
- add reusable ambient-root no-follow helpers for bounded regular-file reads and appendable regular-file validation/open, so callers stop duplicating descriptor-backed path-guard logic
