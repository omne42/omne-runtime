# Security Guide

This guide provides practical security usage guidance. Normative threat model details are in `SECURITY.md`.

## Security Posture Summary

`omne-fs` is a policy enforcement layer inside your process.

It is **not**:

- an OS sandbox,
- a complete TOCTOU-hard filesystem confinement model.

## Explicit Boundary (Non-Goals)

`omne-fs` does not provide:

- content legality/copyright judgment,
- organization approval workflow or human sign-off system,
- OS-kernel isolation guarantees.

If your scenario requires those controls, implement them in outer systems (platform governance, approval service, OS/container isolation), and use `omne-fs` as one policy layer.

## Recommended Deployment Modes

### Trusted local automation

- Moderate limits.
- `allow_absolute = false` preferred.
- Minimal required permissions.

### Semi-trusted integration (agent/server wrappers)

- Tight `limits` values.
- Strict deny globs.
- JSON errors + strict redaction.
- OS sandbox/container strongly recommended.

Example CLI wrapper flags:

```bash
--error-format json --redact-paths-strict
```

## Policy Hardening Checklist

- Use root-relative paths only (`allow_absolute = false`).
- Use dedicated roots per workspace.
- Keep `write_scope = read_only` unless mutation is truly required.
- Start from least privilege in `permissions`.
- Set conservative `max_*` limits for untrusted workloads.
- Add deny globs for secrets and SCM metadata.

## Input and Output Hardening

- Treat `--policy` and patch/content file arguments as trusted-wrapper inputs.
- Reject or sanitize untrusted path inputs before calling CLI.
- Avoid exposing raw stderr without redaction in multi-tenant environments.

## Side-Channel Considerations

Even with path checks, error/timing behavior may still leak information in adversarial scenarios.

Mitigation:

- run inside OS/container sandbox,
- reduce error detail exposure,
- constrain roots to minimal scope.

## Deployment Isolation Baseline

Minimum baseline for agent/server deployments:

- Run under a dedicated non-privileged OS user.
- Use a dedicated workspace root, never `/` or user home as root.
- Keep `allow_absolute = false` unless there is a strict operational need.
- Prefer container/VM isolation in semi-trusted and untrusted contexts.
- Restrict outbound network access for the wrapper process where possible.
- Keep CLI machine mode enabled: `--error-format json --redact-paths-strict`.

Environment baseline:

| Environment | Minimum controls |
|---|---|
| Local trusted dev | Dedicated project root + least-permission policy |
| CI shared runner | Ephemeral workspace + strict limits + JSON/redaction mode |
| Agent/service (semi-trusted) | Container/VM + dedicated user + strict policy + narrow mount scope |
| Multi-tenant/adversarial | OS isolation is mandatory; `omne-fs` alone is insufficient |

## Platform Notes

- Windows path behavior has dedicated validation (drive-relative and ADS checks).
- Unsupported platform paths fail closed in several identity-sensitive flows.

## Vulnerability Reporting

Use private advisory channel:

- `https://github.com/omne42/omne-fs/security/advisories/new`

Include:

- minimal reproduction,
- expected vs actual behavior,
- OS and Rust version.
