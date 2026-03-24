# Process Primitives Boundary ADR

## Status

Accepted and implemented.

## Decision

We add a dedicated low-level crate, `omne-process-primitives`, inside the umbrella workspace.

This crate is a sibling of `omne-fs-primitives`, not part of the `omne-fs` policy/tooling
crate.

## Ownership

### Lives in `omne-process-primitives`

- host command probing helpers such as `command_exists` / `command_available`
- captured host command execution helpers, including Unix `sudo -n` trial for bare system commands
- `tokio::process::Command` setup needed for process-tree cleanup
- Linux process-group identity capture
- Linux `/proc`-based validation for stale process-group reuse checks
- best-effort process-tree kill on Linux
- Windows Job Object assignment and kill-on-close cleanup

### Stays in domain/runtime callers

- timeout policy
- cancellation policy
- stderr/stdout secrecy decisions
- product-specific error mapping
- command allowlists and environment filtering

## Why

Process/runtime command execution is not filesystem policy.

The previous alternatives were both bad:

- leaving the low-level platform code duplicated in each domain crate
- forcing process/runtime code into `omne-fs` just because it uses `cfg(unix)` /
  `cfg(windows)`

The correct separation is:

- filesystem primitives -> `omne-fs-primitives`
- process/runtime primitives -> `omne-process-primitives`
- policy/tooling -> `omne-fs`
- domain semantics -> caller crates

## Consequences

- `secret` now depends on `omne-process-primitives` for low-level process-tree cleanup.
- Future runtime/process consumers should use this crate instead of copying host command probing,
  Unix `sudo -n` trial logic, Linux process-group code, or Windows Job Object logic again.
- `omne-fs` remains focused on filesystem policy and must not absorb process-control APIs.
