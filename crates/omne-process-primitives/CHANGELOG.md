# Changelog

## [Unreleased]

- stop formatting full host recipe `stdout`/`stderr` into `HostRecipeError::Display`; surface only exit status and captured byte counts while preserving raw `Output` for callers
- keep draining oversized stdout/stderr streams until EOF before returning the capture-limit error, so bounded capture cannot deadlock on a full pipe
- resolve explicit relative program paths against the caller process cwd instead of reinterpreting them through `working_directory`, keeping command probes and execution consistent
- make `command_exists_for_request` / `command_available_for_request` use the same caller-cwd semantics for explicit relative program paths as `run_host_command`, while still honoring request-scoped `PATH` overrides for bare direct commands
- stop trusting request `PATH` overrides to locate `sudo` or the elevated bare command target; resolve both from the host environment and pass the elevated target as a concrete path
- require explicit `sudo` system-command paths to resolve into a trusted system directory after canonicalization, so lexical escapes and symlink aliases cannot cross the privilege boundary
- capture Linux process-group leader identity from a single `/proc/<pid>/stat` snapshot so cleanup never combines `start_ticks` and `session_id` from different process lifetimes
