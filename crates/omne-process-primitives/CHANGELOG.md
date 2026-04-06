# Changelog

## [Unreleased]

### Fixed

- resolve request-scoped relative `PATH` entries against the same effective `working_directory`
  used for direct spawn, including relative `working_directory` inputs, so command probing,
  missing-program classification, and execution stay aligned

- treat Windows drive-relative program paths such as `C:tool.exe` as explicit relative paths
  instead of bare commands, so request-scoped probes and execution stop falling back to `PATH`
- fail closed on Linux once process-tree cleanup can no longer revalidate the original leader
  after exit, instead of trusting surviving same-session group members behind a reused historical
  process-group id
- terminate still-running direct children as soon as captured stdout/stderr exceeds the bounded
  per-stream limit, so oversized output fails fast instead of waiting for the command to exit
- stop `resolve_command_path*` helpers from reinterpreting explicit relative paths through `PATH`;
  commands such as `./tool` and `subdir/tool` now resolve only as explicit paths, matching
  shell/`exec` semantics and keeping probe APIs aligned with execution
- add request-scoped host-command controls for env removal and hard timeouts without changing the default `run_host_command` / `run_host_recipe` surface; timeout failures now return bounded captured stdout/stderr instead of forcing callers to reimplement subprocess supervision
- drop all request env at the sudo privilege boundary instead of reapplying non-`PATH` entries inside the elevated target process; direct execution still preserves request env semantics, but privileged package-manager runs no longer inherit caller-controlled loader/runtime variables under root
- classify post-spawn stdout/stderr collection failures as `HostCommandError::CaptureFailed` instead of `SpawnFailed`, so callers can distinguish startup failures from output-capture failures
- make Linux process-tree cleanup fail closed when the group leader exits before cleanup can bind a `/proc` identity, instead of arming `killpg` from a bare historical PGID
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
- reject explicit relative request program paths unless callers also provide `working_directory`, so request-scoped probes and execution no longer fall back to the host process cwd behind the API boundary
- stop trusting request `PATH` overrides to locate `sudo` or the elevated bare command target; resolve both from the host environment and pass the elevated target as a concrete path
- require explicit `sudo` system-package-manager paths to match the same canonical binary the host resolves for that manager name, so lexical aliases cannot smuggle a different executable across the privilege boundary
- add regression coverage proving lexical prefix escapes such as `/usr/bin/../tmp/evil` do not regain `IfNonRootSystemCommand` treatment through explicit package-manager paths
- drop request `PATH` overrides at the sudo boundary itself so auto-elevated system commands do not reintroduce caller-controlled search paths under root
- restrict auto-sudo to canonical system package manager commands from `omne-system-package-primitives`, instead of treating arbitrary bare commands or user-local prefixes as implicit system commands
- classify direct explicit-path `ENOENT` as `CommandNotFound` only when the resolved target path is actually missing; if the file still exists, preserve the spawn failure so missing interpreters/loaders are not mislabeled
- capture direct child stdout/stderr through temporary files so daemonized descendants that inherit those handles cannot keep `run_host_command` / `run_host_recipe` blocked after the direct child exits
- add regression coverage that locks sudo bare-command resolution to trusted host paths and proves daemonized descendants holding `stderr` cannot keep `run_host_command` blocked
- capture the Linux process-group id and leader identity from a single `/proc/<pid>/stat` snapshot so cleanup never combines `pgid`, `start_ticks`, or `session_id` from different process lifetimes
- stop trusting ambient `PATH` for `sudo`, `env`, and auto-sudo package-manager target resolution; control-plane binaries now bind only to trusted standard install locations while direct bare commands still honor request-scoped `PATH`
- make non-Linux Unix process-group cleanup fail closed by skipping `killpg` when the crate
  cannot revalidate the original leader lifetime with Linux-style evidence
