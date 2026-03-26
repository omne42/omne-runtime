# omne-execution-gateway AGENTS Map

This file is only a map. The local `docs/` tree is the system of record.

## Read First

- Overview: `README.md`
- Docs entrypoint: `docs/docs-system-map.md`
- Docs portal: `docs/index.md`
- Boundaries: `docs/architecture/system-boundaries.md`
- Source layout: `docs/architecture/source-layout.md`
- Workspace boundaries: `../../docs/workspace-crate-boundaries.md`

## Edit Rules

- Keep `AGENTS.md` short.
- Gateway or sandbox boundary changes update `system-boundaries.md`.
- Module/file responsibility changes update `source-layout.md`.
- `site/` is generated output, not the maintained record.

## Verify

- `cargo test -p omne-execution-gateway`
- `../../scripts/check-docs-system.sh`
