# omne-runtime AGENTS Map

This file is only a map. The version-controlled `docs/` tree is the system of record.

## Read First

- Workspace overview: `README.md`
- Docs entrypoint: `docs/README.md`
- Docs entrypoint: `docs/docs-system-map.md`
- Workspace crate boundaries: `docs/workspace-crate-boundaries.md`
- Workspace source layout: `docs/source-layout.md`
- Documentation maintenance rules: `docs/quality-and-doc-maintenance.md`
- Per-crate docs: `crates/*/docs/docs-system-map.md`

## Edit Rules

- Keep `AGENTS.md` short; do not move long-lived facts here.
- Boundary changes update `docs/workspace-crate-boundaries.md`.
- Workspace layout changes update `docs/source-layout.md`.
- Crate behavior or boundary changes update that crate's local docs in the same change.
- Generated outputs are not documentation sources of truth.

## Verify

- `./scripts/check-docs-system.sh`
- `cargo test --workspace`
