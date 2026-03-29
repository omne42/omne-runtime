# Policy Model

`GatewayPolicy` defines execution controls.

## Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_isolation_none` | `bool` | `false` | Allows `policy_meta::ExecutionIsolation::None` when true. |
| `enforce_allowlisted_program_for_mutation` | `bool` | `true` | Requires every request to declare mutation intent explicitly, requires declared mutations to use allowlisted programs, requires allowlisted mutating programs to set `declared_mutation = true`, and fail-closes shell-like opaque launchers plus known mutating tool families unless they are explicitly allowlisted. |
| `mutating_program_allowlist` | `Vec<String>` | empty | Explicit program paths whose resolved executable identity may authorize declared mutation. Bare program names are not trusted for mutation authorization. |
| `default_isolation` | `policy_meta::ExecutionIsolation` | `BestEffort` | Fallback isolation for CLI requests when not provided. |
| `audit_log_path` | `Option<PathBuf>` | `None` | Optional JSONL audit file path. |

## Default Policy JSON

```json
{
  "allow_isolation_none": false,
  "enforce_allowlisted_program_for_mutation": true,
  "mutating_program_allowlist": ["/usr/local/bin/omne-fs"],
  "default_isolation": "best_effort",
  "audit_log_path": "/tmp/omne_exec_audit.jsonl"
}
```

## Enforcement Order

1. Deny requests that claim `requested_isolation_source = policy_default` when their stored isolation no longer matches `policy.default_isolation`.
2. Deny `none` isolation if forbidden.
3. Enforce explicit mutation declaration, allowlisted mutating programs, built-in obvious mutator guardrails, and opaque launcher rules.
4. Deny if requested isolation exceeds host capability.
5. Deny invalid `workspace_root`.
6. Deny invalid `cwd`, then deny `cwd` outside workspace.
7. Apply sandbox and execute.

## Notes

- mutation enforcement is two-way for allowlisted programs: declared mutations must use an allowlisted explicit program path, and allowlisted mutating programs must explicitly declare mutation.
- when mutation enforcement is enabled, even read-only requests must call `with_declared_mutation(false)` or set `"declared_mutation": false` explicitly; silent constructor defaults are denied as `mutation_declaration_required`.
- bare program names do not grant mutation rights, even if a same-name entry appears in the allowlist. If a caller wants to mutate via `omne-fs`, the request must use an explicit path such as `/path/to/omne-fs`.
- allowlist matching binds to the resolved executable identity behind an explicit path, so stable aliases such as symlinks may match only when they still resolve to the same executable file.
- shell-like opaque launchers such as `sh`, `cmd`, `powershell`, and `pwsh` are denied unless they are explicitly allowlisted, because the gateway cannot trust `declared_mutation = false` for an interpreter boundary.
- known mutating tool families such as `git`, `make`, package managers, and core file-mutating utilities are denied when they claim `declared_mutation = false`, because the gateway should not trust `declared_mutation = false` for obvious host-mutating entry points; callers must treat them as mutating and pair them with an allowlisted explicit path.
- the gateway still does not parse arbitrary tool-specific CLI syntax or infer arbitrary binary semantics for unknown non-allowlisted direct executables; the built-in mutator list is only a narrow fail-closed guardrail for obvious host-mutating entry points.
- allowlist matching is executable-identity based for explicit paths; it is not binary provenance verification.
- Linux、macOS 和 Windows 当前都只报告 `None` 为受支持能力；如果 policy/default/request 仍要求 `best_effort` 或 `strict`，gateway 会按 `isolation_not_supported` fail-closed。

## Denial Reasons

- `policy_default_isolation_mismatch`
- `isolation_none_forbidden`
- `mutation_requires_allowlisted_program`
- `allowlisted_program_requires_declared_mutation`
- `opaque_command_requires_allowlisted_program`
- `known_mutating_program_requires_declared_mutation`
- `isolation_not_supported`
- `mutation_declaration_required`
- `workspace_root_invalid`
- `cwd_invalid`
- `cwd_outside_workspace`
