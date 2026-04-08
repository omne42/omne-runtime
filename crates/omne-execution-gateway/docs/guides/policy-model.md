# Policy Model

`GatewayPolicy` defines execution controls.

## Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_isolation_none` | `bool` | `true` | Allows `policy_meta::ExecutionIsolation::None` when true. |
| `enforce_allowlisted_program_for_mutation` | `bool` | `true` | Requires every request to declare mutation intent explicitly, requires declared mutations to use allowlisted programs, requires declared non-mutating requests to use explicitly allowlisted executables, and rejects shell-like, interpreter, and multiplexing frontend launchers outright. |
| `mutating_program_allowlist` | `Vec<String>` | empty | Explicit program paths whose resolved executable identity may authorize declared mutation. Bare program names are not trusted for mutation authorization. |
| `non_mutating_program_allowlist` | `Vec<String>` | empty | Explicit program paths whose resolved executable identity may authorize a declared non-mutating request. Bare program names are not trusted for non-mutating authorization either. |
| `default_isolation` | `policy_meta::ExecutionIsolation` | `None` | Fallback isolation for CLI requests when not provided. |
| `audit_log_path` | `Option<PathBuf>` | `None` | Optional JSONL audit file path. Must be absolute. |

## Default Policy JSON

```json
{
  "allow_isolation_none": true,
  "enforce_allowlisted_program_for_mutation": true,
  "mutating_program_allowlist": ["/usr/local/bin/omne-fs"],
  "non_mutating_program_allowlist": ["/usr/bin/git"],
  "default_isolation": "none",
  "audit_log_path": "/tmp/omne_exec_audit.jsonl"
}
```

## Enforcement Order

1. Deny requests that claim `requested_isolation_source = policy_default` when their stored isolation no longer matches `policy.default_isolation`.
2. Deny `none` isolation if forbidden.
3. Deny if requested isolation exceeds host capability.
4. Deny invalid relative `audit_log_path` values.
5. Bind and validate `workspace_root`, `cwd`, and the executable path.
6. Enforce explicit mutation declaration, startup-sensitive env denial, allowlisted mutating/non-mutating executable identities, and opaque launcher rules.
7. Apply sandbox and execute.

## Notes

- mutation enforcement is two-way for allowlisted programs: declared mutations must use an allowlisted explicit program path, and allowlisted mutating programs must explicitly declare mutation.
- when mutation enforcement is enabled, even read-only requests must call `with_declared_mutation(false)` or set `"declared_mutation": false` explicitly; silent constructor defaults are denied as `mutation_declaration_required`.
- bare program names do not grant mutation rights, even if a same-name entry appears in the allowlist. If a caller wants to mutate via `omne-fs`, the request must use an explicit path such as `/path/to/omne-fs`.
- allowlist matching binds to the resolved executable identity behind an explicit path, so stable aliases such as symlinks may match only when they still resolve to the same executable file.
- shell-like and multiplexing opaque launchers such as `sh`, `cmd`, `powershell`, `pwsh`, `python3.12`, `pip3.12`, and `nodejs` are denied even when their executable paths appear in an allowlist, because the gateway cannot bind arbitrary script/subcommand semantics to a stable executable identity.
- the gateway does not parse arbitrary tool-specific CLI syntax or infer arbitrary binary semantics from executable basenames. If a caller wants to authorize read-only direct executables such as `git` or `cargo`, that decision must be expressed through an explicit `non_mutating_program_allowlist` entry for the resolved executable path; multiplexing launcher/frontend families stay fail-closed because executable identity alone does not prove a read-only subcommand.
- allowlist matching is executable-identity based for explicit paths; it is not binary provenance verification.
- `execute()` still owns the simplest full-lifecycle path, but prepared execution is no longer audit-blind: `prepare_command()` records the preflight `prepared` / `prepare_error` state, and `PreparedChild::wait()` / `try_wait()` / drop finalization append the terminal execution record.
- `GatewayPolicy::default()` keeps host-compatible isolation defaults for current shipped hosts, but it still enables mutation enforcement with empty allowlists. Use `GatewayPolicy::default_for_supported_isolation(...)` or `ExecGateway::new()` when you want the executable constructor baseline, and set `default_isolation` to `best_effort` or `strict` explicitly when you want fail-closed sandbox preference.
- `GatewayPolicy::default_for_supported_isolation(...)`, and therefore `ExecGateway::new()` / `with_supported_isolation(...)`, use the same host-compatible isolation baseline but also disable mutation enforcement so default construction stays executable instead of behaving like an empty-allowlist deny-all policy. Re-enable `enforce_allowlisted_program_for_mutation` explicitly when you want that tighter gate.
- `CapabilityReport` reports the configured `policy_default_isolation` and also
  `policy_default_isolation_permitted`. The configured value remains host-compatible for
  `ExecGateway::new()` / `with_supported_isolation(...)`; for caller-supplied policies, check the
  boolean before building `ExecRequest::with_policy_default_isolation(...)` because the configured
  default may still be rejected by the current host/policy isolation gates.
- Linux、macOS 和 Windows 当前都只报告 `None` 为受支持能力；如果 policy/default/request 仍要求 `best_effort` 或 `strict`，gateway 会按 `isolation_not_supported` fail-closed。

## Denial Reasons

- `policy_default_isolation_mismatch`
- `isolation_none_forbidden`
- `relative_program_path_forbidden`
- `program_path_invalid`
- `mutation_requires_allowlisted_program`
- `allowlisted_program_requires_declared_mutation`
- `non_mutating_requires_allowlisted_program`
- `startup_sensitive_env_forbidden`
- `opaque_command_forbidden`
- `isolation_not_supported`
- `mutation_declaration_required`
- `workspace_root_invalid`
- `cwd_invalid`
- `cwd_outside_workspace`
- `audit_log_path_invalid`
- `audit_log_unavailable`
