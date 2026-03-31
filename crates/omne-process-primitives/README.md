# omne-process-primitives

Low-level host-command and process-tree primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- host command discovery, including `OsStr`-friendly probe/resolve helpers
- request-scoped command probes that honor request `PATH` overrides for bare direct commands without changing caller-cwd semantics for explicit relative program paths
- `command_available*` probes that keep the same spawnable contract as execution and do not report non-executable files as available
- host command execution with captured output that returns after the direct child exits even if daemonized descendants keep inherited stdout/stderr open
- host recipe execution with `OsString` argv/env, env/cwd support, and non-zero-exit errors
- non-zero-exit `HostRecipeError::Display` summaries that report exit status and captured byte counts without dumping full stdout/stderr into logs
- explicit relative program paths that keep caller-cwd semantics even when the child process runs under a different `working_directory`
- sudo-style escalation that applies explicit request env inside the elevated target command via `env -- KEY=VALUE ...`, except for request `PATH` overrides that are dropped at the sudo boundary instead of being reintroduced under root
- fail-closed `CommandNotFound` classification before invoking `sudo` when the requested bare target cannot be resolved from the host environment as a canonical system package manager command
- direct explicit-path spawns only collapse `ENOENT` into `CommandNotFound` when the resolved target path itself is gone; if the file still exists, interpreter/loader failures remain structured spawn errors
- sudo resolution that ignores request-scoped `PATH` overrides when choosing the `sudo` binary or the elevated bare-command target, and only auto-escalates canonical system package manager commands whose explicit paths match the same binary identity the host resolves for that manager name
- default sudo-mode selection driven by the canonical `omne-system-package-primitives` manager catalog
- optional `sudo -n` probing on Unix
- process-tree cleanup setup and best-effort termination
- fail-closed process-tree capture on Unix unless the child was spawned into its own dedicated process group via `configure_command_for_process_tree`
- Windows `taskkill` cleanup that waits for command success before skipping descendant fallback
- Unix process-group cleanup that still fails closed on leader-PID reuse, while Linux can keep reaping same-session orphaned descendants both when the leader already exited before cleanup capture finished and when it exits shortly after capture

## Non-Goals

- product allowlists
- timeout policy
- environment filtering, lossy UTF-8 coercion, or output-log leakage policy
- sandbox selection

## Verification

```bash
cargo test -p omne-process-primitives
../../scripts/check-docs-system.sh
```
