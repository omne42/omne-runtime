# Example Survey (Filesystem Tool Semantics)

Last reviewed: 2026-02-13

This document is a non-normative survey note used to record ecosystem observations.

The previous workspace-local `example/` snapshot is no longer part of this repository, so this
file intentionally avoids path-level claims that cannot be reproduced in-tree.

## Scope

- Keep short notes about common filesystem-tool tradeoffs in agent tooling.
- Capture why `omne-fs` keeps strict roots/limits/secrets boundaries.
- Avoid duplicating project policy rules.

## Authority

Normative rules live in:

- `README.md` (tool semantics and contracts)
- `SECURITY.md` (threat model and non-goals)

If this file disagrees with those documents, treat this file as stale and follow the authority docs.

## Observations

- Many tools treat policy/permissions as product-level controls, not OS-level sandboxing.
- Traversal semantics differ widely (`follow_links(true/false)`, gitignore coupling, skip rules).
- Search implementations often trade completeness for bounded work (time/files/results caps).
- Patch/edit APIs vary between operation-based and unified-diff models; both require explicit
  conflict and safety semantics.

## Notes For `omne-fs`

- Keep behavior explicit and policy-driven (`SandboxPolicy`, root bounds, secrets, limits).
- Keep traversal deterministic and bounded; expose diagnostics for partial results.
- Keep write/edit/patch semantics stable and predictable across library + CLI.

## Related

- [`index.md`](index.md)
- [`../README.md`](../README.md)
- [`../SECURITY.md`](../SECURITY.md)
