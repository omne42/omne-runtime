# CLI Usage

Use `omne-execution` as a policy-enforcing CLI adapter.

## Command

```bash
cargo run --bin omne-execution -- --policy ./policy.json --request ./request.json
```

## policy.json

```json
{
  "allow_isolation_none": true,
  "enforce_allowlisted_program_for_mutation": true,
  "mutating_program_allowlist": ["/usr/local/bin/omne-fs"],
  "non_mutating_program_allowlist": ["/usr/bin/echo"],
  "default_isolation": "none",
  "audit_log_path": "/tmp/omne_exec_audit.jsonl"
}
```

## request.json

```json
{
  "program": "/usr/bin/echo",
  "args": ["hello-from-omne-execution"],
  "cwd": ".",
  "workspace_root": ".",
  "required_isolation": "none",
  "declared_mutation": false
}
```

`required_isolation` is optional; when omitted, the CLI builds an `ExecRequest` with
`requested_isolation_source = policy_default` and `required_isolation = policy.default_isolation`.
`declared_mutation` is required in `request.json`; the CLI no longer defaults it to `false`.
Unknown request fields are rejected fail-closed instead of being ignored.
`request.json` must be a bounded regular file; symlink, special-file, and oversized inputs are rejected fail-closed.
`audit_log_path` must be absolute; relative paths are denied during preflight.
`program`, each entry in `args`, and explicit `env.name` / `env.value` accept either a normal JSON string or the exact OS-string object form used in gateway output, for example `{ "encoding": "unix_bytes_hex", "value": "666f80" }` on Unix.
When `program` matches `mutating_program_allowlist`, the gateway requires
`declared_mutation = true`; declared mutations still must use an allowlisted explicit path.
When `declared_mutation = false`, the request must likewise use an explicit path from
`non_mutating_program_allowlist`; unknown tools can no longer self-label as read-only and bypass
the mutation boundary.
Bare program names are denied fail-closed for mutation authorization, even if a same-name string
appears in either allowlist.
For ordinary execution, bare program names are resolved to an absolute executable path during
preflight; if lookup cannot be bound to a concrete executable, the request fails closed instead of
passing an unresolved name through to `spawn()`.
Allowlisted explicit paths are compared by resolved executable identity, so a symlink alias is only
authorized while it still points at the same executable file.
Shell-like and multiplexing opaque frontends such as `sh`, `cmd`, `powershell`, `pwsh`,
`python3.12`, `pip3.12`, and `nodejs` are denied even if their full executable paths appear in an
allowlist. The gateway does not parse `omne-fs` subcommands, shell scripts, package-manager
operations, or interpreter payloads to infer mutation intent.
The gateway likewise does not infer arbitrary read-only vs mutating behavior from executable
basenames. If you want to authorize a read-only direct executable such as `git status` or
`cargo metadata`, place that exact resolved executable in `non_mutating_program_allowlist`;
multiplexing launcher/frontend families stay fail-closed because executable identity alone does
not prove a read-only subcommand.
`request_resolution`, `event`, and the pure evaluation methods stay side-effect free; the gateway
only creates the audit parent chain during `execute()` / `prepare_command()`.

## Output Schema

One JSON line with:

- `request_resolution` (authoritative normalized request plus isolation provenance)
- `event` (authoritative full `ExecEvent` payload, including argv)
- `exit_code`
- `signal`
- `error`

Example output fragment:

```json
{
  "request_resolution": {
    "program": "/usr/bin/echo",
    "args": ["hello-from-omne-execution"],
    "program_exact": {
      "encoding": "utf8",
      "value": "/usr/bin/echo"
    },
    "args_exact": [
      {
        "encoding": "utf8",
        "value": "hello-from-omne-execution"
      }
    ],
    "cwd": "/abs/workspace",
    "workspace_root": "/abs/workspace",
    "declared_mutation": false,
    "requested_isolation": "none",
    "requested_isolation_source": "request",
    "requested_policy_meta": {
      "version": 1,
      "execution_isolation": "none"
    },
    "policy_default_isolation": "none"
  },
  "event": {
    "decision": "run",
    "requested_isolation": "none",
    "requested_policy_meta": {
      "version": 1,
      "execution_isolation": "none"
    },
    "supported_isolation": "none",
    "program": "/usr/bin/echo",
    "args": ["hello-from-omne-execution"],
    "program_exact": {
      "encoding": "utf8",
      "value": "/usr/bin/echo"
    },
    "args_exact": [
      {
        "encoding": "utf8",
        "value": "hello-from-omne-execution"
      }
    ],
    "cwd": "/abs/workspace",
    "workspace_root": "/abs/workspace",
    "declared_mutation": false,
    "reason": null
  },
  "exit_code": 0,
  "signal": null,
  "error": null
}
```

`request_resolution` is the gateway-generated canonical pre-execution request view, derived from
the same authoritative execution/preflight event snapshot emitted in `event`. It makes defaulted
isolation decisions explicit through `input_required_isolation`, `requested_isolation_source`, and
`policy_default_isolation`.
`event` is the canonical execution/audit shape and includes canonicalized `cwd`,
canonicalized `workspace_root`, declared mutation intent, and the authoritative argv seen by the
gateway. When the request used a bare command name, `program` reflects the resolved absolute
executable path that the gateway bound during preflight.
Both `request_resolution` and `event` keep readable lossy `program` / `args` fields and also emit
`program_exact` / `args_exact` so non-UTF-8 OS strings remain reconstructable in machine-facing
output.
If `cwd` is missing, inaccessible, or not a directory, the CLI surfaces `cwd_invalid` instead of
mislabeling the input as `cwd_outside_workspace`.
`requested_isolation_source` explains whether the effective isolation came from the request payload
or from `policy.default_isolation`.
Current hosts report `supported_isolation = none`; `best_effort` and `strict` requests fail closed
until a native sandbox backend is reintroduced safely.

## Exit Behavior

- exit `0` only when command exits `0`.
- non-zero for deny/failure/non-zero child exit.
