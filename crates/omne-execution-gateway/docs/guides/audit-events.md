# Audit Events

The gateway exposes `ExecEvent` to describe decision outcomes.

## Event Fields

| Field | Description |
| --- | --- |
| `decision` | `run` or `deny`. |
| `requested_isolation` | Isolation requested by caller. |
| `requested_policy_meta` | Canonical `policy-meta` projection of the requested isolation. Currently emitted as `{ "version": 1, "execution_isolation": ... }`. |
| `supported_isolation` | Host-supported isolation detected by gateway. |
| `program` | Program name (serialized lossily for OS strings). |
| `cwd` | Effective working directory. Canonicalized when validation succeeds. |
| `workspace_root` | Effective workspace boundary root. Canonicalized when validation succeeds. |
| `declared_mutation` | Raw caller-declared mutation intent. |
| `reason` | Optional denial reason. |
| `sandbox_runtime` | Optional runtime sandbox observation. Present for execution paths that can report realized enforcement state. |

## API Entry Points

- `evaluate(&request)` for dry-run decision check.
- `execute(&request)` for decision plus execution result.
- `execute_status_with_event(&request)` for tuple-style compatibility.
- `prepare_command(&request, &mut command)` for callers that need the gateway to apply validated `cwd` and sandbox configuration to a `Command` before spawning manually; the gateway rejects the call if `command` program/args diverge from `request`.

## JSONL Audit Sink

When `audit_log_path` is set, the gateway appends JSONL records with:

- `ts_unix_ms`
- full `event`
- `event.requested_policy_meta` for cross-repo canonical policy metadata
- `result.status` (`prepared`, `prepare_error`, `exited`, or `spawn_error`)
- `result.error` (if present)
- `result.exit_code` / `result.success` for completed processes
- `result.signal` when a process terminated via signal

On Linux `best_effort`, `event.sandbox_runtime` records the observed Landlock outcome as one of:

- `fully_enforced`
- `partially_enforced`
- `not_enforced`
- `error`
