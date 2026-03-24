# Documentation Index

This is the primary documentation portal for `omne-fs`.

## Start Here

- [`getting-started.md`](getting-started.md): install, configure policy, run first commands.
- [`concepts.md`](concepts.md): safety model, path model, boundaries, limits.
- [`policy-reference.md`](policy-reference.md): complete policy schema and defaults.

## Reference

- [`operations-reference.md`](operations-reference.md): operation-by-operation contracts.
- [`cli-reference.md`](cli-reference.md): CLI commands, flags, and examples.
- [`library-reference.md`](library-reference.md): Rust integration and API patterns.

## Security and Operations

- [`../SECURITY.md`](../SECURITY.md): formal threat model and disclosure process.
- [`security-guide.md`](security-guide.md): practical security guidance for users/integrators.
- [`deployment-and-ops.md`](deployment-and-ops.md): CI, release, hooks, and maintenance workflows.
- [`secrets-gate.md`](secrets-gate.md): secrets scanning gate, baseline, and response policy.
- [`ops-runbook-secrets.md`](ops-runbook-secrets.md): secrets finding triage, escalation, and remediation runbook.

## Additional Design Notes

- [`db-vfs.md`](db-vfs.md): DB-backed VFS architecture decision and integration notes.
- [`fs-boundary-follow-up.md`](fs-boundary-follow-up.md): post-consolidation decisions for the
  remaining `omne_foundation` fs/platform adapters.
- [`process-primitives-boundary-adr.md`](process-primitives-boundary-adr.md): boundary for the
  shared low-level process-tree cleanup crate.
- [`example-survey.md`](example-survey.md): ecosystem survey notes (non-normative).
- [`release-notes-risk-boundary-2026h1.md`](release-notes-risk-boundary-2026h1.md): risk-boundary delivery summary.

## Versioning

- Current crate version: `0.2.0`.
- Changelog: [`../CHANGELOG.md`](../CHANGELOG.md).
