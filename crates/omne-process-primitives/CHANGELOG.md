# Changelog

## [Unreleased]

- stop formatting full host recipe `stdout`/`stderr` into `HostRecipeError::Display`; surface only exit status and captured byte counts while preserving raw `Output` for callers
