# Audit Events

The gateway exposes `ExecEvent` to describe decision outcomes.

## Event Fields

| Field | Description |
| --- | --- |
| `decision` | `run` or `deny`. |
| `requested_isolation` | Isolation requested by caller. |
| `requested_policy_meta` | Canonical `policy-meta` projection of the requested isolation. Currently emitted as `{ "version": 1, "execution_isolation": ... }`. |
| `supported_isolation` | Host-supported isolation detected by gateway. |
| `program` | Program name. UTF-8 values stay strings; non-UTF-8 OS strings emit a lossless object with `display` plus platform raw bytes/code units. |
| `cwd` | Effective working directory. Canonicalized when validation succeeds. |
| `workspace_root` | Effective workspace boundary root. Canonicalized when validation succeeds. |
| `declared_mutation` | Raw caller-declared mutation intent. |
| `reason` | Optional denial reason. |
| `sandbox_runtime` | Optional runtime sandbox observation. Present for execution paths that can report realized enforcement state. |

## API Entry Points

- `evaluate(&request)` for dry-run decision check.
- `execute(&request)` for decision plus execution result.
- `execute(&request).into_parts()` when tuple destructuring is preferred.
- `prepare_command(&request, command)` for callers that need a spawn-only `PreparedCommand`; the gateway rejects the call if `command` program/args diverge from `request`, and `PreparedCommand::spawn()` revalidates bound `cwd` / `workspace_root` identities right before spawn.

## JSONL Audit Sink

When `audit_log_path` is set, the gateway appends JSONL records with:

- `ts_unix_ms`
- `request_resolution` so the exact canonical argv and isolation provenance remain available in the audit sink
- full `event`
- `event.requested_policy_meta` for cross-repo canonical policy metadata
- `result.status` (`prepared`, `prepare_error`, `exited`, or `spawn_error`)
- `result.error` (if present)
- `result.exit_code` / `result.success` for completed processes
- `result.signal` when a process terminated via signal

Current shipped platforms do not emit `event.sandbox_runtime`, because native `best_effort` /
`strict` sandbox backends are not enabled.

The field remains part of the event schema so future native backends can report realized runtime
enforcement state without changing the audit contract.

The audit sink itself is fail-closed: the gateway rejects symlinked audit files, special files,
and paths that traverse existing symlinked parent directories.

For JSON consumers, `request_resolution.program`, `request_resolution.args`, and `event.program`
serialize as plain strings for UTF-8 values. When an OS string is not valid UTF-8, the gateway
emits an object like `{ "display": "...", "unix_bytes_hex": "..." }` on Unix or
`{ "display": "...", "windows_wide_hex": "..." }` on Windows so audit readers can recover the
exact command bytes/code units instead of relying on lossy replacement text.
