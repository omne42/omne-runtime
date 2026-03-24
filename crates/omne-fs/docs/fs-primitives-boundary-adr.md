# FS Primitives Boundary ADR

## Status

Accepted and implemented.

## Decision

We consolidate low-level no-follow filesystem primitives into a dedicated crate,
`omne-fs-primitives`, inside the `omne-fs` workspace.

We do **not** express this boundary with crate features on `omne-fs` itself.
The boundary is structural:

- `omne-fs-primitives`
  - owns descriptor/handle-oriented filesystem primitives
  - owns platform-specific no-follow open helpers and symlink/reparse classification
  - owns policy-free bounded read helpers that multiple filesystem consumers share
  - is allowed to expose raw-ish `Dir`/`File` style building blocks
- `omne-fs`
  - owns `SandboxPolicy`, permissions, limits, secrets, redaction, CLI, and high-level ops
  - may call `omne-fs-primitives`
  - must not reintroduce duplicated low-level no-follow primitives locally

## Why

Feature flags are a bad way to encode architecture. They hide boundaries instead of enforcing
them. We need one source of truth for the low-level filesystem pieces, but we also need the
policy/tool layer to stay separate.

## Non-Goals

This ADR does not merge `omne-fs` path-policy logic into the primitives crate.

In particular, these remain in `omne-fs`:

- alias-root semantics based on both declared and canonical roots
- lexical policy validation and policy-owned path resolution
- secret-path rejection, redaction, limits, and operation permissions

Those semantics are not low-level primitives; they are policy behavior.

Cross-platform code by itself is also not enough to justify placement in the fs crates.
Runtime process cleanup, job objects, process groups, `/proc` inspection, and application data-root
selection are separate concerns even when they need `cfg(unix)` / `cfg(windows)` handling.
Those behaviors belong in a dedicated runtime/process crate, not in `omne-fs`.

## Final Boundary

### Lives in `omne-fs-primitives`

- `materialize_root`
- `open_root`
- `open_directory_component`
- `create_directory_component`
- `open_regular_file_at`
- `create_regular_file_at`
- `remove_file_or_symlink_at`
- `entry_kind_at`
- `read_directory_names`
- `read_utf8_limited`
- `open_readonly_nofollow`
- `open_writeonly_nofollow`
- `open_regular_readonly_nofollow`
- `open_regular_writeonly_nofollow`
- symlink/reparse open-error classification
- shared default trusted-text byte limits
- shared bounded-read helper for descriptor-backed text consumers

### Lives in `omne-fs`

- `SandboxPolicy`
- `Context`
- alias-root handling
- request/response types for read/list/glob/grep/stat/edit/patch/write/move/copy/delete
- TOCTOU-aware higher-level operation logic
- redaction, deny rules, permissions, limits
- CLI and policy I/O

## Consequences

- Downstream crates should depend on `omne-fs-primitives` directly for low-level access.
- We do not preserve the legacy `cap_fs` crate name as a compatibility layer.
- Future low-level helpers shared across multiple consumers should be moved into
  `omne-fs-primitives`, not added independently to each caller.
- Cross-platform runtime/process abstractions should not be added to `omne-fs` just because
  they are portable; the boundary is filesystem primitives vs policy/runtime behavior, not
  `cfg(...)` usage.

## Downstream Adapters That Stay Local

- `runtime-assets-kit::secure_fs`
  - stays local because it owns resource-specific path validation, UTF-8 naming rules, backslash
    rejection, bootstrap/write semantics, and resource error messages
- `i18n::dynamic::secure_fs`
  - stays local because it owns catalog-specific traversal, `.json` filtering, source-count/byte
    limits, and `DynamicCatalogError` mapping
- `omne-process-primitives`
  - owns low-level process-tree spawn/cleanup primitives such as process-group setup, Linux
    process-group identity checks, `/proc` validation, and Windows Job Object teardown
  - stays separate from `omne-fs` because it is process/runtime infrastructure, not
    filesystem policy/tooling
- `secret` helper-process lifecycle semantics
  - stay local because timeout/cancellation policy, stderr secrecy, and secret-specific error
    mapping are still product behavior layered on top of `omne-process-primitives`
- `secret://file` open semantics
  - now consume `omne-fs-primitives::open_regular_readonly_nofollow` for the low-level open
  - still keep secret-specific error mapping and size/UTF-8 handling local to `secret`
