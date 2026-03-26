# omne-fs AGENTS Map

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
- Filesystem policy or boundary changes update `system-boundaries.md`.
- Source/module responsibility changes update `source-layout.md`.
- Existing guides and references under `docs/` remain the detailed record.

## Verify

- `cargo test -p omne-fs`
- `../../scripts/check-docs-system.sh`
