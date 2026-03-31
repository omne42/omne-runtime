# Changelog

## [Unreleased]

- narrow macOS root-alias normalization to the known `/var` and `/tmp` aliases instead of trusting any first-component symlink under `/`
- reject non-root symlink ancestors while materializing parent directories for staged atomic file/directory writes, while normalizing platform root aliases such as macOS `/var`
- add normalized-path no-follow helpers for bounded UTF-8 regular-file reads and appendable regular-file validation/open
- add a strict advisory-lock helper that creates lock files under `open_root` no-follow validation instead of ambient existing-ancestor traversal
