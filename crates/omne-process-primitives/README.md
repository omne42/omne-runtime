# omne-process-primitives

Low-level host-command and process-tree primitives shared across callers.

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `../../docs/workspace-crate-boundaries.md`

## Scope

- host command discovery, including `OsStr`-friendly probe/resolve helpers
- explicit-path command discovery that treats `./tool` and `subdir/tool` as explicit paths instead
  of continuing to search `PATH`, matching shell/`exec` semantics for probe helpers; Windows
  drive-relative paths such as `C:tool.exe` are treated as explicit relative paths too
- request-scoped command probes that honor request `PATH` overrides for bare direct commands while failing closed on explicit relative program paths that omit `working_directory`
- `command_available*` probes that keep the same spawnable contract as execution and do not report non-executable files as available
- host command execution with captured output that returns after the direct child exits even if daemonized descendants keep inherited stdout/stderr open
- host command capture-limit enforcement that best-effort terminates an overproducing direct child
  and reaps it asynchronously, so continuously writing commands return a structured capture error
  instead of hanging in the overflow path
- optional request-scoped env removals and hard timeouts for host command / recipe execution, while leaving timeout selection to the caller
- caller-controlled per-stream capture limits for host command / recipe execution, including an explicit escape hatch to disable the default 8 MiB bound when the caller owns the higher-level policy
- distinct host-command capture errors for post-spawn stdout/stderr read failures, so callers can distinguish execution-start failures from output-collection failures
- distinct timeout errors that preserve bounded captured stdout/stderr for callers that need to render or classify partial output
- host recipe execution with `OsString` argv/env, env/cwd support, and non-zero-exit errors
- non-zero-exit `HostRecipeError::Display` summaries that report exit status and captured byte counts without dumping full stdout/stderr into logs
- explicit relative program paths that resolve only against an explicit `working_directory`, instead of silently inheriting the caller process cwd
- sudo-style escalation that resolves the privileged target from trusted host locations and drops all request env at the sudo boundary, so elevated commands never reintroduce caller-controlled `PATH` or other request-scoped environment into the root-side target process
- fail-closed `CommandNotFound` classification before invoking `sudo` when the requested bare target cannot be resolved from trusted standard install locations as a canonical system package manager command
- fail-closed local validation for explicit `IfNonRootSystemCommand` paths before invoking
  `sudo`, so missing, non-executable, or untrusted package-manager paths cannot escape into
  elevated child-process errors
- direct explicit-path spawns only collapse `ENOENT` into `CommandNotFound` when the resolved target path itself is gone; if the file still exists, interpreter/loader failures remain structured spawn errors
- sudo resolution that ignores both request-scoped and ambient `PATH` pollution when choosing the `sudo` binary or the elevated bare-command target, and only auto-escalates canonical system package manager commands whose explicit paths match the same binary identity trusted standard locations resolve for that manager name
- default sudo-mode selection driven by the canonical `omne-system-package-primitives` manager catalog
- optional `sudo -n` probing on Unix
- process-tree cleanup setup and best-effort termination
- fail-closed process-tree capture on Unix unless the child was spawned into its own dedicated process group via `configure_command_for_process_tree`
- Windows `taskkill` cleanup that waits for command success before skipping descendant fallback
- Unix process-group cleanup that fails closed once the captured leader PID has been reused by a
  different live process, and on Linux also fails closed when the leader exits before cleanup can
  still revalidate the original `/proc` identity; non-Linux Unix skips `killpg` entirely because
  the crate cannot revalidate leader lifetime with Linux-strength evidence there, and the captured
  process-group id, `start_ticks`, and `session_id` must keep matching the exact captured
  `/proc/<pid>/stat` leader snapshot, so cleanup never mixes fields from different process
  lifetimes or degrades into trusting a bare surviving PGID

## Non-Goals

- product allowlists
- default timeout policy
- general direct-execution environment filtering, lossy UTF-8 coercion, or output-log leakage policy
- sandbox selection

## Verification

```bash
cargo test -p omne-process-primitives
../../scripts/check-docs-system.sh
```
