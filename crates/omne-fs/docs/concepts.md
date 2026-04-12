# Concepts

This page explains the core model and invariants behind `omne-fs`.

## Core Model

Every operation is evaluated against:

- `roots`: named filesystem anchors.
- `permissions`: per-operation allow/deny switches.
- `limits`: byte/result/traversal budgets.
- `secrets`: deny and redaction rules.
- `paths`: absolute-path acceptance policy.
- `traversal`: performance-oriented skip patterns for `glob`/`grep`.

## Root-Bounded Access

Requests are scoped by `root_id` and a `path`.

- Relative paths resolve under the selected root.
- Absolute paths are allowed only when `paths.allow_absolute=true`.
- Canonicalization and boundary checks enforce best-effort root confinement.

Important: this is policy-layer enforcement, not a kernel sandbox.

## Request Path vs Resolved Path

Many responses include:

- `requested_path`: normalized user request path.
- `path`: effective root-relative path after resolution.

These can differ when symlinks or absolute input normalization are involved.

## Permission Gates

Each operation has a permission flag. For example:

- `read` requires `permissions.read=true`
- `write` requires `permissions.write=true`
- `move` requires `permissions.move=true`

Mutating operations also require root `write_scope = workspace_write` or `full_access`.

## Deny and Redaction

Two distinct mechanisms:

- `secrets.deny_globs`: blocks access to matching paths.
- `secrets.redact_regexes`: rewrites returned text (e.g., `read`, `grep`).

`traversal.skip_globs` is different: it skips traversal candidates for performance but does not deny direct access.

## Bounded Work

`limits` prevent unbounded scans and large payloads:

- `max_read_bytes`, `max_write_bytes`, `max_patch_bytes`
- `max_results`, `max_walk_entries`, `max_walk_files`, `max_walk_ms`
- `max_line_bytes` (for `grep` line text clipping)

`glob`/`grep` expose diagnostics when limits are hit.

## Feature Gating

Cargo features (`glob`, `grep`, `patch`, `policy-io`) control implementation availability.

Design choice:

- API remains stable even when features are off.
- `Context` methods and free functions remain callable and return deterministic
  `Error::NotPermitted` when disabled.

## Error Model

`Error::code()` provides stable classification strings (e.g. `invalid_path`, `outside_root`, `file_too_large`).

This is preferred over matching error text.

## Security Boundary

`omne-fs` does not claim TOCTOU-hard confinement against adversarial concurrent local processes.

For hostile environments:

- run in OS/container sandbox,
- keep policies strict,
- use small limits,
- redact error output.

See `SECURITY.md` and `docs/security-guide.md`.
