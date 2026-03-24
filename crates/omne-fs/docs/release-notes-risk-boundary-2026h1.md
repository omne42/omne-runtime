# Release Notes (Risk Boundary 2026H1)

This note summarizes the risk-boundary delivery items completed in 2026H1.

## Added

- Secrets scan gate in local hooks and CI:
  - `githooks/pre-commit` runs `gitleaks` (with optional baseline path).
  - `.github/workflows/ci.yml` adds a dedicated `Secrets Scan` job.
  - `.github/workflows/secrets-secondary.yml` adds scheduled `trufflehog` verified scan (warning-only).
  - secondary scan supports configurable enforcement (`SECRETS_SECONDARY_ENFORCE_ON_MAIN` or manual input `enforce=true`).
  - secondary scan supports optional issue-based alerting (`SECRETS_SECONDARY_OPEN_ISSUE_ON_FINDINGS` or manual input `open_issue=true`).
  - secondary scan publishes structured artifact `secrets-secondary-summary.json`.
  - `gitleaks`/`trufflehog` workflow installs now verify tarball checksums.
- Explicit high-risk confirmation in CLI:
  - new global flag `--confirm-mutating-ops`,
  - mutating commands require this flag: `edit`, `patch`, `mkdir`, `write`, `delete`, `move`, `copy-file`.
- Error classification contract:
  - `reason_code`, `risk_tag`, `policy_rule` mapping in `src/error.rs`,
  - `DecisionTrace` in `src/ops/context.rs` for unified audit metadata.
- Adversarial regression tests:
  - encoded traversal token literal handling,
  - prompt-like path injection cases,
  - symlink + secret deny combined bypass regression.

## Changed

- Security and policy docs now explicitly state:
  - this project is not an OS sandbox,
  - deployment isolation baseline expectations,
  - non-goals and high-risk boundary ownership.
- Cross-platform regression gates are now green for Linux/Windows/macOS in the current matrix checks.
- Windows-target identity checks were migrated from unstable file-id APIs to stable metadata fingerprints
  (`file_attributes + creation_time + last_write_time + file_size`) to keep CI on stable Rust.

## Compatibility

- CLI mutating workflows are now stricter: wrappers must pass `--confirm-mutating-ops`.
- Existing read-only and non-mutating commands are unchanged.

## Not Included

- No OS-kernel sandbox implementation in this repository.
- No organization workflow/governance engine implementation.
