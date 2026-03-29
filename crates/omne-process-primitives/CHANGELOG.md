# Changelog

## [Unreleased]

- stop formatting full host recipe `stdout`/`stderr` into `HostRecipeError::Display`; surface only exit status and captured byte counts while preserving raw `Output` for callers
- stop draining oversized stdout/stderr streams after the capture limit is reached; fail the capture path immediately instead
