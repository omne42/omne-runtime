# Changelog

## [Unreleased]

- reject non-root symlink ancestors while materializing parent directories for staged atomic file/directory writes, while normalizing platform root aliases such as macOS `/var`
- add normalized-path no-follow helpers for bounded UTF-8 regular-file reads and appendable regular-file validation/open
