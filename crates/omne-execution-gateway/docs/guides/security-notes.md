# Security Notes

`omne-execution-gateway` improves execution safety, but it is one control layer in a broader security stack.

## What It Enforces

- request/policy-default isolation provenance consistency,
- isolation capability checks,
- workspace boundary checks,
- mutation declaration consistency for allowlisted mutating requests,
- non-interactive stdio detachment for gateway-managed spawns,
- fail-closed denial for non-allowlisted opaque launchers.

## What It Does Not Enforce Alone

- command intent semantics,
- network isolation,
- secret isolation across subprocesses,
- interactive terminal bridging or output capture,
- binary provenance verification,
- generic mutation detection for non-allowlisted direct executables.

## Operational Recommendations

- run under least-privilege OS accounts,
- keep workspace roots narrow,
- enable audit logging in production,
- pair with dedicated filesystem safety tooling,
- treat `none` isolation as exceptional.
