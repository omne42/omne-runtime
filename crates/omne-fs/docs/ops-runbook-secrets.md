# Secrets Incident Runbook

This runbook defines the on-duty response for findings from the repository secrets gates.

## Inputs

- Primary gate: `gitleaks` result from `.github/workflows/ci.yml`
- Secondary gate: `trufflehog` artifacts from `.github/workflows/secrets-secondary.yml`
  - `trufflehog-verified.jsonl`
  - `secrets-secondary-summary.json`
- Optional tracking issue from `.github/workflows/secrets-secondary.yml`:
  - auto-open/update is controlled by `SECRETS_SECONDARY_OPEN_ISSUE_ON_FINDINGS` or manual `open_issue=true`.

## Triage SLA

- Initial triage: within 2 hours of alert.
- Rotation/revocation completion target: within 24 hours.

## Response Steps

1. Confirm finding details from CI logs/artifacts.
2. Classify severity:
   - `P0`: production credential/token with external access.
   - `P1`: non-production credential or limited-scope token.
   - `P2`: suspected false positive or already-revoked material.
3. Identify owner for the credential and system.
4. Revoke/rotate the credential.
5. Remove leaked material from repository history where feasible.
6. Open follow-up PR to harden detection/regression coverage.

## Containment Checklist

- Credential is revoked or rotated.
- Downstream systems are checked for misuse.
- Any required access policy updates are applied.
- Evidence and timestamps are recorded in incident notes.

## False Positive Handling

1. Capture evidence from `trufflehog-verified.jsonl` and scanner logs.
2. Verify token is invalid or non-sensitive test data.
3. If needed, update baseline/config with reviewer approval.
4. Keep scanner execution enabled; never disable the gate to suppress one finding.

## Escalation

- Escalate immediately to maintainer on duty when:
  - finding is `P0`,
  - credential owner is unknown,
  - revocation cannot complete within SLA.

## Post-Incident Record

Record in PR/incident tracker:

- finding source and detector type,
- affected repositories/systems,
- revoke/rotate completion time,
- prevention action (tests/rules/docs updates).
