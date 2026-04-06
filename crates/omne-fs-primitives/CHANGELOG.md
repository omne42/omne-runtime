# Changelog

## [Unreleased]

- make `open_regular_file_at` use non-blocking no-follow opens so FIFOs and other special files fail closed instead of hanging callers before regular-file validation
- report staged directory replace backup cleanup failures as post-commit errors so callers can tell the destination already switched
- call `fs2::FileExt::unlock` with fully qualified syntax so future stdlib name-collision lints do not break `-D warnings` builds
- narrow macOS root-alias normalization to the known `/var` and `/tmp` aliases instead of trusting any first-component symlink under `/`
- reject non-root symlink ancestors while materializing parent directories for staged atomic file/directory writes, while normalizing platform root aliases such as macOS `/var`
- move staged atomic file/directory temp creation and final replace onto bound parent-directory handles so parent-path swaps after validation fail closed instead of drifting into symlink targets
- add normalized-path no-follow helpers for bounded UTF-8 regular-file reads and appendable regular-file validation/open
- add a strict advisory-lock helper that creates lock files under `open_root` no-follow validation instead of ambient existing-ancestor traversal
