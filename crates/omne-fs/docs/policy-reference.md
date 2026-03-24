# Policy Reference

`SandboxPolicy` is the source of truth for operation authorization and budgets.
It can also carry optional shared metadata under `metadata.policy_meta`, but that section is
descriptive only in `omne-fs` and is not consulted for enforcement.

## Full Schema

```toml
[[roots]]
id = "workspace"
path = "/abs/path"
write_scope = "read_only" # or "workspace_write"

[permissions]
read = true
glob = true
grep = true
list_dir = true
stat = true
edit = false
patch = false
delete = false
mkdir = false
write = false
move = false
copy_file = false

[paths]
allow_absolute = false

[limits]
max_read_bytes = 1048576
# max_patch_bytes = 1048576
max_write_bytes = 1048576
max_results = 2000
max_walk_entries = 500000
max_walk_files = 200000
# max_walk_ms = 1000
max_line_bytes = 4096
preserve_unix_xattrs = true

[secrets]
deny_globs = [".git/**", "**/.git/**"]
redact_regexes = []
replacement = "***REDACTED***"

[traversal]
stable_sort = true
skip_globs = ["node_modules/**", "target/**"]

[metadata.policy_meta]
version = 1
risk_profile = "standard"
write_scope = "workspace_write"
execution_isolation = "best_effort"
decision = "prompt"
```

## `roots`

- `id`: unique, `[A-Za-z0-9._-]`, max length 64, no surrounding whitespace.
- `path`: absolute path (structural validation); existence and directory checks happen in `Context::new`.
- `write_scope`:
  - `read_only`
  - `workspace_write`
  - `full_access`

## `permissions`

Boolean flags controlling operation entrypoints:

- `read`, `glob`, `grep`, `list_dir`, `stat`, `edit`, `patch`, `delete`, `mkdir`, `write`, `move`, `copy_file`.

Note: TOML key is `move`, mapped to Rust `move_path`.

## `paths`

- `allow_absolute` (default `false`):
  - `false`: request paths must be root-relative.
  - `true`: absolute paths accepted, but must still resolve inside selected root.

## `limits`

Defaults:

- `max_read_bytes = 1_048_576`
- `max_patch_bytes = None` (uses `max_read_bytes`)
- `max_write_bytes = 1_048_576`
- `max_results = 2_000`
- `max_walk_entries = 500_000`
- `max_walk_files = 200_000`
- `max_walk_ms = None`
- `max_line_bytes = 4_096`
- `preserve_unix_xattrs = true`

Constraints:

- Most limits must be `> 0`.
- `max_walk_files <= max_walk_entries`.
- Hard caps are enforced by validation to prevent pathological policy values.
- `max_line_bytes` also scales the default response-byte estimate budget
  (`max_results * max_line_bytes`) used by `glob`/`grep`/`list_dir`.
  `grep` response accounting includes path bytes per match, so very long relative paths can
  trigger `scan_limit_reason=response_bytes` before `max_results` is reached.
- `preserve_unix_xattrs` only affects Linux/Android overwrite writes. Disabling can reduce
  syscall overhead but stops xattr preservation.

## `secrets`

- `deny_globs`: root-relative glob patterns denied by path checks.
- `redact_regexes`: regex list applied to returned text.
- `replacement`: replacement string for redaction.

Defaults include `.git` and `.env` deny patterns.

## `traversal`

- `skip_globs`: traversal performance filter for `glob`/`grep` only.
- `stable_sort` (default `true`): sort directory entries before traversal to keep deterministic order.
  Set `false` in large-directory workloads when deterministic order is not required.
- Does not deny direct file operations.

## `metadata`

- `policy_meta`: optional shared metadata fragment parsed as `policy_meta::PolicyMetaV1`.
- Supported keys: `version`, `risk_profile`, `write_scope`, `execution_isolation`, `decision`.
- Descriptive only in `omne-fs`: it does not grant access, tighten access, or change limits.
- `metadata.policy_meta.write_scope` does not override `[[roots]].write_scope`; root enforcement still comes from `roots`.

## Validation Stages

1. `SandboxPolicy::validate()`:
   - structural validation only,
   - no filesystem I/O.
   - `metadata.policy_meta` is validated only for serde shape/value correctness; it is not interpreted as an enforcement rule.

2. `Context::new(policy)`:
   - filesystem checks (root exists, directory, canonicalization),
   - matcher compilation (deny/skip/redaction patterns).

## Recommended Profiles

### Local dev (balanced)

- `allow_absolute = false`
- moderate defaults
- explicit deny globs

### Untrusted integration (strict)

- small `max_*` limits
- `allow_absolute = false`
- `--error-format json --redact-paths-strict` in CLI wrappers
- run inside OS sandbox/container

## High-Risk Boundary

`SandboxPolicy` controls filesystem access and resource budgets only. It does not decide:

- business/legal legitimacy of file contents,
- human approval workflow for sensitive actions,
- organization-level identity/trust-chain requirements.

For high-risk scenarios, wrappers should add:

- explicit user confirmation for mutating operations,
- external approval/audit workflow,
- stronger runtime isolation (container/VM/OS sandbox).

## Out of Scope for Policy Schema

The policy schema intentionally excludes:

- content moderation and copyright governance logic,
- network/proxy governance logic unrelated to local filesystem operations,
- OS-level confinement semantics.

## See Also

- [`../policy.example.toml`](../policy.example.toml)
- [`security-guide.md`](security-guide.md)
- [`../SECURITY.md`](../SECURITY.md)
