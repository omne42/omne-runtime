# Secrets Baseline

This directory is reserved for secrets scanning baseline artifacts.

Expected file:

- `gitleaks-baseline.json`

Usage:

- generate a baseline only after triaging findings,
- commit baseline updates in a dedicated reviewable PR,
- do not use baseline updates to hide unresolved active secrets.

Secondary scan:

- `.github/workflows/secrets-secondary.yml` runs weekly `trufflehog` verified scan,
- default behavior is warning-only (report + summary),
- set repository variable `SECRETS_SECONDARY_ENFORCE_ON_MAIN=true` to enforce failure on `main`,
- manual dispatch supports `enforce=true` for one-off blocking runs.
- optional tracking issue can be enabled by:
  - `SECRETS_SECONDARY_OPEN_ISSUE_ON_FINDINGS=true`, or
  - manual dispatch input `open_issue=true`.
- artifacts include:
  - `trufflehog-verified.jsonl`,
  - `secrets-secondary-summary.json`.

Reference:

- `docs/secrets-gate.md`
