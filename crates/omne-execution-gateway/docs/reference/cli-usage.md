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
  "default_isolation": "best_effort",
  "audit_log_path": "/tmp/omne_exec_audit.jsonl"
}
```

## request.json

```json
{
  "program": "echo",
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
When `program` matches `mutating_program_allowlist`, the gateway requires
`declared_mutation = true`; declared mutations still must use an allowlisted explicit path.
Bare program names are denied fail-closed for mutation authorization, even if a same-name string
appears in `mutating_program_allowlist`.
Allowlisted explicit paths are compared by resolved executable identity, so a symlink alias is only
authorized while it still points at the same executable file.
Shell-like opaque launchers such as `sh`, `cmd`, `powershell`, and `pwsh` are denied unless
their full executable paths are explicitly allowlisted. The gateway does not parse `omne-fs` subcommands to infer
mutation intent.
Known mutating tool families such as `git`, `make`, package managers, and core file-mutating
utilities are also denied when callers set `"declared_mutation": false`; to run them, callers must
declare mutation and use an explicitly allowlisted executable path.

## Output Schema

One JSON line with:

- `request_resolution` (authoritative normalized request plus isolation provenance)
- `event` (authoritative full `ExecEvent` payload)
- `exit_code`
- `signal`
- `error`

Example output fragment:

```json
{
  "request_resolution": {
    "program": "echo",
    "args": ["hello-from-omne-execution"],
    "cwd": "/abs/workspace",
    "workspace_root": "/abs/workspace",
    "declared_mutation": false,
    "requested_isolation": "none",
    "requested_isolation_source": "request",
    "requested_policy_meta": {
      "version": 1,
      "execution_isolation": "none"
    },
    "policy_default_isolation": "best_effort"
  },
  "event": {
    "decision": "run",
    "requested_isolation": "none",
    "requested_policy_meta": {
      "version": 1,
      "execution_isolation": "none"
    },
    "supported_isolation": "none",
    "program": "echo",
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

`request_resolution` is the gateway-generated canonical pre-execution request view. It makes
defaulted isolation decisions explicit through `input_required_isolation`,
`requested_isolation_source`, and `policy_default_isolation`.
Its `program` / `args` fields stay JSON strings for UTF-8 values, but switch to a lossless object
with `display` plus platform raw bytes/code units when an OS string is not valid UTF-8.
`event` is the canonical execution/audit shape and includes canonicalized `cwd`,
canonicalized `workspace_root`, and declared mutation intent.
`event.program` follows the same lossless non-UTF-8 encoding rule.
If `cwd` is missing, inaccessible, or not a directory, the CLI surfaces `cwd_invalid` instead of
mislabeling the input as `cwd_outside_workspace`.
`requested_isolation_source` explains whether the effective isolation came from the request payload
or from `policy.default_isolation`.
Current hosts report `supported_isolation = none`; `best_effort` and `strict` requests fail closed
until a native sandbox backend is reintroduced safely.
When audit logging is enabled, the JSONL sink also includes the same `request_resolution` payload,
so downstream parsers do not need to reconstruct argv from the shorter `event` view.

## Exit Behavior

- exit `0` only when command exits `0`.
- non-zero for deny/failure/non-zero child exit.
