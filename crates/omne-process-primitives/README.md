# omne-process-primitives

Low-level host-command and process-tree primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- host command discovery
- host command execution with captured output
- host recipe execution with env/cwd support and non-zero-exit errors
- sudo-style escalation that preserves explicit request env via `sudo --preserve-env=...`
- default sudo-mode selection for common system-package commands
- optional `sudo -n` probing on Unix
- process-tree cleanup setup and best-effort termination
- Windows `taskkill` cleanup that waits for command success before skipping descendant fallback
- fail-closed orphan process-group cleanup on non-Linux Unix once the original leader exits

## Non-Goals

- product allowlists
- timeout policy
- environment filtering policy
- sandbox selection

## Verification

```bash
cargo test -p omne-process-primitives
../../scripts/check-docs-system.sh
```
