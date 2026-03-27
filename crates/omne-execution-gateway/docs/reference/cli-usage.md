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
When `program` matches `mutating_program_allowlist`, the gateway requires
`declared_mutation = true`; declared mutations still must use an allowlisted explicit path.
Bare program names are denied fail-closed for mutation authorization, even if a same-name string
appears in `mutating_program_allowlist`.
Shell-like opaque launchers such as `sh`, `cmd`, `powershell`, and `pwsh` are denied unless
their full executable paths are explicitly allowlisted. The gateway does not parse `omne-fs` subcommands to infer
mutation intent.

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
    "cwd": ".",
    "workspace_root": ".",
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

`request_resolution` is the gateway-generated canonical pre-execution request view. It preserves the
request payload shape (`program`, `args`, `cwd`, `workspace_root`, `declared_mutation`) and makes
defaulted isolation decisions explicit through `input_required_isolation`,
`requested_isolation_source`, and `policy_default_isolation`.
`event` is the canonical execution/audit shape and includes canonicalized `cwd`,
canonicalized `workspace_root`, and declared mutation intent.
`requested_isolation_source` explains whether the effective isolation came from the request payload
or from `policy.default_isolation`.
Current hosts report `supported_isolation = none`; `best_effort` and `strict` requests fail closed
until a native sandbox backend is reintroduced safely.

## Exit Behavior

- exit `0` only when command exits `0`.
- non-zero for deny/failure/non-zero child exit.
