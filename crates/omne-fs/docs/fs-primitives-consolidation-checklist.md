# FS Primitives Consolidation Checklist

## Goal

Zero duplicated low-level filesystem primitives, with a clear crate boundary between primitives
and policy/tooling.

## Completed

- [x] Added `omne-fs-primitives` as a dedicated low-level crate under the `omne-fs` workspace.
- [x] Moved the former `cap_fs` capability-style filesystem API into `omne-fs-primitives`.
- [x] Moved platform no-follow open/error-classification helpers into `omne-fs-primitives`.
- [x] Switched `omne-fs::platform_open` to re-export the shared primitives implementation.
- [x] Switched `omne-fs::ops::io` regular-file no-follow open paths to call `omne-fs-primitives`.
- [x] Switched `omne_foundation/crates/text-assets-kit` to depend on `omne-fs-primitives` directly.
- [x] Switched `omne_foundation/crates/i18n` to depend on `omne-fs-primitives` directly.
- [x] Switched `omne_foundation/crates/secret` file-open path to the shared no-follow regular-file
      primitive in `omne-fs-primitives`.
- [x] Moved the duplicated bounded-read primitive used by `resources` and `i18n` into
      `omne-fs-primitives`.
- [x] Removed the `cap_fs` crate from the `omne_foundation` workspace.
- [x] Removed the legacy `cap_fs` crate files instead of keeping a compatibility alias.

## Guardrails For Future Changes

- [ ] Do not add new low-level no-follow open helpers to `omne-fs/src`.
- [ ] Do not add a replacement compatibility crate under the old `cap_fs` name.
- [ ] If a helper is policy-free and filesystem-primitive in nature, add it to `omne-fs-primitives`.
- [ ] If a helper depends on permissions, limits, redaction, or alias-root semantics, keep it in
      `omne-fs`.
- [ ] If a helper is cross-platform but tied to one product/domain lifecycle, keep it in the owning
      domain crate instead of dumping it into `omne-fs`.

## Evaluated Follow-Ups

- [x] Evaluated whether generic identity/staged-temp helpers in `omne-fs::ops::io` now have
      multiple consumers. They do not; keep them local to `omne-fs` until a second
      non-policy consumer appears.
- [x] Evaluated remaining `omne_foundation` fs/platform code:
      `text-assets-kit::secure_fs` and the `i18n-runtime-kit` directory loader stay as domain adapters,
      `resources::data_root` stays as application root-resolution policy, and
      `secret` process cleanup / platform process control stay outside the fs crates.
- [x] Added a short public docs index entry for the post-consolidation boundary follow-up note.
- [x] Tightened `crates/secret` file-open semantics to require no-follow regular-file opens for
      `secret://file`, while keeping secret-specific error mapping local to `secret`.
- [x] Extracted shared process-tree setup/cleanup primitives into the dedicated sibling crate
      `omne-process-primitives` instead of growing `omne-fs` beyond filesystem concerns.
