# Changelog

## [Unreleased]

- restrict `IfNonRootSystemCommand` escalation to supported system package managers resolved from trusted standard locations, so request-scoped `PATH` shadowing cannot inject fake `sudo` or fake package-manager binaries across the elevation boundary
- stop formatting full host recipe `stdout`/`stderr` into `HostRecipeError::Display`; surface only exit status and captured byte counts while preserving raw `Output` for callers
- stop draining oversized stdout/stderr streams after the capture limit is reached, while still allowing outputs that end exactly on the capture limit
