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
- On Linux `best_effort`, inspect `execution.event.sandbox_runtime` before treating the run as sandboxed.

## Repair Mapping

| Reason | Typical remediation |
| --- | --- |
| `isolation_not_supported` | Lower isolation only with explicit approval. |
| `policy_default_isolation_mismatch` | Rebuild the request against the current gateway policy default. |
| `cwd_outside_workspace` | Correct path under workspace root. |
| `mutation_requires_fs_tool` | Route via `omne-fs`. |
| `isolation_none_forbidden` | Use `best_effort` or `strict`. |

## Safe Defaults for Autonomous Runs

- `allow_isolation_none=false`
- `enforce_fs_tool_for_mutation=true`
- request `best_effort` by default
- keep audit logging enabled
