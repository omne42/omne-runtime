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
| Linux | `strict` when Landlock is available, else `best_effort` | Strict path requires Landlock full enforcement. `best_effort` opportunistically installs a Landlock ruleset and silently degrades when the host cannot enforce it. |
| macOS | `best_effort` | Native strict not available. Current `best_effort` does not provide OS-enforced filesystem isolation. |
| Windows | `best_effort` | Native strict not available. Current `best_effort` does not provide OS-enforced filesystem isolation. |

## Fail-Closed Behavior

When `required_isolation > supported_isolation`, execution is denied.

No silent downgrade is performed.

## Linux Strict Path

In strict mode on Linux:

- ruleset is installed in child `pre_exec`,
- root read/execute + workspace full access are configured,
- run is rejected if ruleset is not fully enforced.

This means `strict` currently protects writes outside the workspace more strongly than reads.

It should not be modeled as host-wide secret isolation.

## Linux Best-Effort Path

In best-effort mode on Linux:

- the gateway attempts to install the same Landlock shape as strict mode,
- unsupported or partially enforced features do not fail the spawn,
- realized execution events report whether Landlock ended up `fully_enforced`, `partially_enforced`, `not_enforced`, or errored,
- callers should treat the result as opportunistic hardening rather than a contractual sandbox.
