# Audit Events

The gateway exposes `ExecEvent` to describe decision outcomes.

## Event Fields

| Field | Description |
| --- | --- |
| `decision` | `run` or `deny`. |
| `requested_isolation` | Isolation requested by caller. |
| `requested_policy_meta` | Canonical `policy-meta` projection of the requested isolation. Currently emitted as `{ "version": 1, "execution_isolation": ... }`. |
| `supported_isolation` | Host-supported isolation detected by gateway. |
| `program` | Program name in readable lossy form. |
| `args` | Full argv in readable lossy form. |
| `program_exact` | Exact JSON encoding of `program`. UTF-8 values emit `{ "encoding": "utf8", "value": ... }`; non-UTF-8 Unix values emit `{ "encoding": "unix_bytes_hex", "value": ... }`. |
| `args_exact` | Exact JSON encoding of each argv entry, parallel to `args`. |
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
- full `event`
- exact `event.program_exact` / `event.args_exact` alongside the readable lossy `event.program` / `event.args`
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
