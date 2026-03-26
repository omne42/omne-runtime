# Policy Model

`GatewayPolicy` defines execution controls.

## Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_isolation_none` | `bool` | `false` | Allows `policy_meta::ExecutionIsolation::None` when true. |
| `enforce_allowlisted_program_for_mutation` | `bool` | `true` | Requires caller-declared mutating requests to use allowlisted programs. |
| `mutating_program_allowlist` | `Vec<String>` | `omne-fs`, `omne-fs-cli` | Allowed program names or explicit paths for declared mutation. Basename matching is accepted for explicit paths. |
| `default_isolation` | `policy_meta::ExecutionIsolation` | `BestEffort` | Fallback isolation for CLI requests when not provided. |
| `audit_log_path` | `Option<PathBuf>` | `None` | Optional JSONL audit file path. |

## Default Policy JSON

```json
{
  "allow_isolation_none": false,
  "enforce_allowlisted_program_for_mutation": true,
  "mutating_program_allowlist": ["omne-fs", "omne-fs-cli"],
  "default_isolation": "best_effort",
  "audit_log_path": "/tmp/omne_exec_audit.jsonl"
}
```

## Enforcement Order

1. Deny requests that claim `requested_isolation_source = policy_default` when their stored isolation no longer matches `policy.default_isolation`.
2. Deny `none` isolation if forbidden.
3. Enforce mutation allowlist for caller-declared mutating requests.
4. Deny if requested isolation exceeds host capability.
5. Deny invalid `workspace_root`.
6. Deny `cwd` outside workspace.
7. Apply sandbox and execute.

## Notes

- mutation enforcement relies on caller declaration; the gateway does not parse tool-specific CLI syntax or infer arbitrary shell intent.
- allowlist matching is name/path based; it is not binary provenance verification.
- macOS 和 Windows 当前只报告 `None` 为受支持能力；如果 policy/default/request 仍要求 `best_effort` 或 `strict`，gateway 会按 `isolation_not_supported` fail-closed。

## Denial Reasons

- `policy_default_isolation_mismatch`
- `isolation_none_forbidden`
- `mutation_requires_allowlisted_program`
- `isolation_not_supported`
- `workspace_root_invalid`
- `cwd_outside_workspace`
