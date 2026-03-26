# FS Boundary Follow-Up

This note captures the post-consolidation review of the remaining filesystem/platform code in
`omne_foundation`.

## Core Rule

Do not group code by "it has platform branches". Group it by abstraction ownership.

- `omne-fs-primitives` owns low-level, policy-free building blocks.
- `omne-fs` owns filesystem policy/tooling.
- Domain crates keep adapters that encode domain naming rules, error taxonomies, lifecycle, and
  product semantics.

## Decisions

### Keep `text-assets-kit::secure_fs` In `omne_foundation`

Reason:
- It is not a raw filesystem primitive.
- It owns resource-path parsing, UTF-8/backslash rules, bootstrap/write behavior, rollback, and
  resource-specific errors.

What it should consume:
- `omne-fs-primitives::{open_root, open_directory_component, open_regular_file_at, read_utf8_limited, ...}`

### Keep `i18n-runtime-kit` Directory Loader In `omne_foundation`

Reason:
- It is a catalog adapter, not generic filesystem tooling.
- It owns `.json` filtering, locale-source counting, catalog-size enforcement, and
  `DynamicCatalogError` mapping.

What it should consume:
- The same low-level primitives from `omne-fs-primitives`.

### Split `secret` Process Cleanup At The Right Boundary

Reason:
- The low-level process-tree primitive is generic and now belongs in `omne-process-primitives`.
- The secret-specific timeout/cancellation semantics and stderr handling are still domain behavior.

What lives where now:
- `omne-process-primitives` owns command process-group setup, Linux process-group identity checks,
  best-effort `/proc` validation, and Windows Job Object cleanup.
- `secret` owns timeout policy, auth-command error mapping, stderr secrecy, and resolver
  lifecycle behavior.

### Split `secret://file` Ownership At The Right Boundary

Reason:
- The low-level open primitive is generic and now belongs in `omne-fs-primitives`.
- The secret-specific error mapping and post-open async read behavior are still domain behavior.

What lives where now:
- `omne-fs-primitives` owns the atomic no-follow regular-file open.
- `secret` owns `secret://file` error taxonomy, size limits, UTF-8 conversion, and resolver
  behavior.

## Decision Test

Before moving code into `omne-fs`, ask:

1. Is it low-level and policy-free?
2. Does it have at least two consumers?
3. Is it not carrying domain-specific error mapping or lifecycle semantics?

If any answer is "no", keep it local.
