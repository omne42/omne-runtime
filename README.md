# omne-runtime

Umbrella repository and Cargo workspace for Omne host/runtime crates. This workspace resolves
cross-repository foundation dependencies through canonical git source pins to
`omne42/omne_foundation`.

## Layout

- `crates/omne-artifact-install-primitives`: reusable artifact download, verification, and install pipeline primitives
- `crates/omne-archive-primitives`: low-level archive/compression primitives for binary extraction
- `crates/omne-fs`: policy-bounded filesystem runtime APIs and CLI
- `crates/omne-fs/cli`: nested `omne-fs-cli` workspace package that exposes the `omne-fs` binary while staying inside the `omne-fs` boundary
- `crates/omne-fs-primitives`: low-level filesystem primitives shared across adapters
- `crates/omne-host-info-primitives`: low-level host/platform identity and target-triple primitives
- `crates/omne-integrity-primitives`: low-level digest parsing and integrity verification primitives
- `crates/omne-process-primitives`: low-level host-command, host-recipe, and process-tree primitives
- `crates/omne-system-package-primitives`: low-level canonical package-manager and install-recipe primitives
- `crates/omne-execution-gateway`: execution gateway and sandbox-facing orchestration

## Documentation System

This repository follows an agent-first documentation model:

- `AGENTS.md`: short map only
- `docs/README.md`: workspace docs entrypoint
- `docs/docs-system-map.md`: workspace documentation entrypoint
- `docs/workspace-crate-boundaries.md`: workspace boundary reference
- `docs/source-layout.md`: workspace layout map
- `docs/quality-and-doc-maintenance.md`: documentation maintenance rules

Each crate under `crates/` owns the same minimum documentation skeleton:

- `README.md`
- `AGENTS.md`
- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`

Run `./scripts/check-docs-system.sh` to verify the workspace documentation skeletons against the
actual `Cargo.toml` member list. The nested workspace package `crates/omne-fs/cli` stays
documented through `crates/omne-fs/*`; it is a package inside the `omne-fs` boundary, not a tenth
top-level capability crate.

Naming follows `omne-<capability>` so each crate name carries both product scope and boundary role at
a glance. Public crate names avoid redundant prefixes and unclear jargon; established abbreviations
such as `fs` are acceptable when they are shorter and still immediately recognizable. Suffixes
such as `-primitives` and `-gateway` communicate depth and responsibility, and workspace directory
names mirror package names directly.

## Repository Conventions

- Shared CI and release automation live at the repository root under `.github/`.
- Shared Cargo resolution is rooted at this workspace `Cargo.toml`.
- Build/test commands fetch `http-kit` and `policy-meta` from the canonical
  `omne42/omne_foundation` git source pin declared in member manifests; no sibling checkout is
  required, including CI and release workflows.
- Generated build outputs are ignored via the root `.gitignore`; member crates do not carry
  their own repository-level ignore or workflow configuration.
- We do not create a catch-all `platform` crate. Boundaries are capability-based:
  artifact-install primitives, archive primitives, filesystem primitives, integrity primitives,
  process primitives, and sandbox/execution orchestration stay separate.
- `unsafe` is governed structurally:
  binaries and leaf crates that do not own syscall/FFI boundaries forbid it, while crates that
  own narrow `platform/*` or `sandbox/*` syscall boundaries deny it by default and locally allow
  it only inside those modules.

## Minimum Verification

```bash
./scripts/check-docs-system.sh
cargo test --workspace --all-features
```
