# omne-runtime

Umbrella repository and Cargo workspace for Omne host/runtime crates.

## Layout

- `crates/omne-archive-primitives`: low-level archive/compression primitives for binary extraction
- `crates/omne-fs`: policy-bounded filesystem runtime APIs and CLI
- `crates/omne-fs-primitives`: low-level filesystem primitives shared across adapters
- `crates/omne-integrity-primitives`: low-level digest parsing and integrity verification primitives
- `crates/omne-process-primitives`: low-level host-command and process-tree primitives
- `crates/omne-execution-gateway`: execution gateway and sandbox-facing orchestration

Naming follows `omne-<capability>` so each crate name carries both product scope and boundary role at
a glance. Public crate names avoid redundant prefixes and unclear jargon; established abbreviations
such as `fs` are acceptable when they are shorter and still immediately recognizable. Suffixes
such as `-primitives` and `-gateway` communicate depth and responsibility, and workspace directory
names mirror package names directly.

## Repository Conventions

- Shared CI and release automation live at the repository root under `.github/`.
- Shared Cargo resolution is rooted at this workspace `Cargo.toml`.
- Generated build outputs are ignored via the root `.gitignore`; member crates do not carry
  their own repository-level ignore or workflow configuration.
- We do not create a catch-all `platform` crate. Boundaries are capability-based:
  archive primitives, filesystem primitives, integrity primitives, process primitives, and
  sandbox/execution orchestration stay separate.
- `unsafe` is governed structurally:
  binaries and leaf crates that do not own syscall/FFI boundaries forbid it, while crates that
  own narrow `platform/*` or `sandbox/*` syscall boundaries deny it by default and locally allow
  it only inside those modules.
