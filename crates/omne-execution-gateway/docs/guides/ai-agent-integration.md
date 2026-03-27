# AI and Agent Integration

Use `omne-execution-gateway` as the command execution boundary in agent loops.

## Recommended Flow

```text
agent plan
-> build ExecRequest
-> use with_policy_default_isolation(...) only when intentionally delegating to policy.default_isolation
-> set declared_mutation explicitly
-> evaluate (optional)
-> execute
-> store event + process result
-> feed summarized result back to planner
```

## Integration Rules

- Either supply an explicit isolation enum or use `ExecRequest::with_policy_default_isolation(...)`.
- Always set `declared_mutation` intentionally for generic external commands.
- Keep `workspace_root` explicit and stable.
- Treat denial reasons as actionable control signals.
- Persist `execution.event.requested_policy_meta` when you need a canonical cross-repo record of the requested isolation contract.
- Avoid shell-style launchers such as `sh`, `cmd`, `powershell`, and `pwsh` unless policy explicitly allowlists them.
- Current hosts only report `none` support. Treat `best_effort` / `strict` requests as deliberate fail-closed guards until a native sandbox backend is restored.

## Repair Mapping

| Reason | Typical remediation |
| --- | --- |
| `isolation_not_supported` | Lower isolation only with explicit approval. |
| `policy_default_isolation_mismatch` | Rebuild the request against the current gateway policy default. |
| `cwd_outside_workspace` | Correct path under workspace root. |
| `mutation_requires_allowlisted_program` | Route via a policy-allowlisted mutating program such as `omne-fs`. |
| `opaque_command_requires_allowlisted_program` | Replace shell-style launcher usage with a direct executable or explicitly allowlist that launcher. |
| `isolation_none_forbidden` | Explicitly allow `none`, or defer execution until a supported native isolation backend exists. |

## Safe Defaults for Autonomous Runs

- `allow_isolation_none=false`
- `enforce_allowlisted_program_for_mutation=true`
- request `best_effort` by default only when you want unsupported hosts to fail closed
- if unsandboxed execution is intentionally allowed, set `allow_isolation_none=true` and request `none` explicitly
- keep audit logging enabled
