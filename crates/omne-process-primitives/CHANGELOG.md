# Changelog

## [Unreleased]

- stop formatting full host recipe `stdout`/`stderr` into `HostRecipeError::Display`; surface only exit status and captured byte counts while preserving raw `Output` for callers
- stop draining oversized stdout/stderr streams after the capture limit is reached, while still allowing outputs that end exactly on the capture limit
- resolve privileged helper binaries such as `sudo` and `env` from trusted standard locations instead of the request's effective `PATH`
- restore fail-closed Linux process-group cleanup when leader identity capture or revalidation is incomplete
