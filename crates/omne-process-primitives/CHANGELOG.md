# Changelog

## [Unreleased]

- resolve bare direct commands to a concrete executable path before spawn, so request-scoped `PATH`
  probing, execution, and `CommandNotFound` classification stay consistent and missing
  interpreters/loaders are not mislabeled as missing commands
- make Linux process-tree cleanup fail closed when the captured leader PID has already been
  reused by another live process, instead of killing the old PGID based only on surviving group
  members
- make Unix host-command tests resolve an available shell and prebuilt payload files instead of
  assuming `/bin/sh` and `python3`, so `cargo test -p omne-process-primitives` stays portable
- stop formatting full host recipe `stdout`/`stderr` into `HostRecipeError::Display`; surface only exit status and captured byte counts while preserving raw `Output` for callers
- make `command_available` / `command_available_os` / `command_available_for_request` require spawnable commands instead of treating any regular file as available
- keep draining oversized stdout/stderr streams until EOF before returning the capture-limit error, so bounded capture cannot deadlock on a full pipe
- resolve explicit relative program paths against the caller process cwd instead of reinterpreting them through `working_directory`, keeping command probes and execution consistent
- make `command_exists_for_request` / `command_available_for_request` use the same caller-cwd semantics for explicit relative program paths as `run_host_command`, while still honoring request-scoped `PATH` overrides for bare direct commands
- stop trusting request `PATH` overrides to locate `sudo` or the elevated bare command target; resolve both from the host environment and pass the elevated target as a concrete path
- require explicit `sudo` system-package-manager paths to match the same canonical binary the host resolves for that manager name, so lexical aliases cannot smuggle a different executable across the privilege boundary
- drop request `PATH` overrides at the sudo boundary itself so auto-elevated system commands do not reintroduce caller-controlled search paths under root
- restrict auto-sudo to canonical system package manager commands from `omne-system-package-primitives`, instead of treating arbitrary bare commands or user-local prefixes as implicit system commands
- classify direct explicit-path `ENOENT` as `CommandNotFound` only when the resolved target path is actually missing; if the file still exists, preserve the spawn failure so missing interpreters/loaders are not mislabeled
- capture direct child stdout/stderr through temporary files so daemonized descendants that inherit those handles cannot keep `run_host_command` / `run_host_recipe` blocked after the direct child exits
- add regression coverage that locks sudo bare-command resolution to trusted host paths and proves daemonized descendants holding `stderr` cannot keep `run_host_command` blocked
- capture Linux process-group leader identity from a single `/proc/<pid>/stat` snapshot so cleanup never combines `start_ticks` and `session_id` from different process lifetimes
