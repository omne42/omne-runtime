# Isolation Semantics

The gateway uses three isolation levels from `policy-meta`.

| Level | Meaning |
| --- | --- |
| `none` | No isolation guarantee. |
| `best_effort` | Gateway validation plus platform-specific best effort setup; not a strong sandbox guarantee. |
| `strict` | Strongest native mode the gateway can provide on the host, with fail-closed support checks. |

## Platform Support (v0.1.0)

| Platform | Detected Support | Notes |
| --- | --- | --- |
| Linux | `none` | Native Linux sandbox support is temporarily disabled until a safe replacement for the previous Landlock `pre_exec` path is available. Requests above `none` fail closed. |
| macOS | `none` | Native `best_effort` / `strict` are not implemented, so requests above `none` fail closed. |
| Windows | `none` | Native `best_effort` / `strict` are not implemented, so requests above `none` fail closed. |

## Fail-Closed Behavior

When `required_isolation > supported_isolation`, execution is denied.

No silent downgrade is performed.

## Linux Native Sandbox Status

The previous Linux-native Landlock path is intentionally disabled.

Reason:

- the old implementation depended on Rust work inside `pre_exec`,
- that post-`fork` boundary is not safe to treat as a supported native sandbox contract,
- fail-closing to `none` support is preferable to advertising `best_effort` / `strict` semantics that do not hold.

Until a replacement exists, Linux behaves like the other current platforms:

- `none` is supported,
- `best_effort` and `strict` are denied as `isolation_not_supported`.
