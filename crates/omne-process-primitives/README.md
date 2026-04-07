# omne-process-primitives

Low-level host-command and process-tree primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- host command discovery, including `OsStr`-friendly probe/resolve helpers
- host command execution with captured output
- host recipe execution with `OsString` argv/env, env/cwd support, and non-zero-exit errors
- non-zero-exit `HostRecipeError::Display` summaries that report exit status and captured byte counts without dumping full stdout/stderr into logs
- sudo-style escalation that applies explicit request env inside the elevated target command via `env -- KEY=VALUE ...`, instead of depending on host `sudoers` env propagation
- fail-closed `CommandNotFound` classification before invoking `sudo` when the requested bare target cannot be resolved in the effective `PATH`
- default sudo-mode selection for common system-package commands
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
