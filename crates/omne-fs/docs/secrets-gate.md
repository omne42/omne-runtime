# Secrets Scan Gate

This document defines the repository secrets scanning gate for `omne-fs`.

## Scope

Goal: block credential/token leaks before merge, while keeping a manageable false-positive workflow.

Applies to:

- local commits (`pre-commit`),
- pull requests and `main` branch CI.

## Tooling Choice

Primary gate tool:

- `gitleaks` as blocking scanner for staged changes and CI diffs.

Secondary verifier:

- `trufflehog` as scheduled/secondary verification scanner (focus on verified findings).

Rationale:

- `gitleaks` has mature pre-commit/CI integration and baseline support.
- `trufflehog` adds detector diversity and verified-secret capability.

## Baseline Strategy

Store baseline under version control:

- `security/secrets/gitleaks-baseline.json`

Rules:

- baseline only for accepted historical findings,
- every baseline item requires a reason and owner in PR description,
- baseline updates are review-required and must not bypass scanner execution.

## CI Failure Policy

Blocking conditions:

- new `gitleaks` findings in PR scope (not covered by approved baseline),
- scanner execution failure (fail closed).

Non-blocking conditions:

- scheduled `trufflehog` job can be warning-only in phase 1,
- once false-positive rate is acceptable, promote to blocking for default branch checks.

## Rotation and Response

When a verified secret is found:

1. Revoke/rotate the credential immediately.
2. Remove the secret from source/history where feasible.
3. Add regression coverage if leak pattern is recurring.
4. Record incident summary in PR or incident tracker.

Ownership:

- repo maintainer on-duty coordinates rotation,
- secret owner confirms revocation completion.

## P1 Implementation Targets

- Integrate `gitleaks` into `githooks/pre-commit`.
- Add `gitleaks` scan step in `.github/workflows/ci.yml`.
- Add a scheduled `trufflehog` verification workflow (initially non-blocking).

## Current Implementation Notes

- `gitleaks` CI install in `.github/workflows/ci.yml` is version-pinned and tarball checksum-verified.
- Scheduled secondary scan is implemented in `.github/workflows/secrets-secondary.yml`:
  - trigger: weekly cron + manual dispatch,
  - scan mode: `trufflehog git ... --results=verified --fail`,
  - policy: default warning-only; can be enforced,
  - enforce switch (branch): set repository variable `SECRETS_SECONDARY_ENFORCE_ON_MAIN=true`,
  - enforce switch (manual): run `workflow_dispatch` with input `enforce=true`,
  - optional alert issue:
    - branch-level switch: `SECRETS_SECONDARY_OPEN_ISSUE_ON_FINDINGS=true`,
    - manual switch: `workflow_dispatch` input `open_issue=true`,
    - behavior: findings > 0 时自动创建/更新跟踪 issue（去重更新）。
  - output artifacts:
    - `trufflehog-verified.jsonl`,
    - `secrets-secondary-summary.json` (machine-readable run summary).

Operational response guide:

- [`ops-runbook-secrets.md`](ops-runbook-secrets.md)

## Non-Goals

- This gate does not replace runtime secret management.
- This gate does not provide org-wide governance workflow.
