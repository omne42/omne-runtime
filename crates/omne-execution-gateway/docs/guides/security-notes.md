# Security Notes

`omne-execution-gateway` improves execution safety, but it is one control layer in a broader security stack.

## What It Enforces

- request/policy-default isolation provenance consistency,
- isolation capability checks,
- workspace boundary checks,
- mutation declaration consistency for allowlisted mutating requests,
- fail-closed denial for non-allowlisted opaque launchers.

On Linux, `best_effort` also attempts to apply a Landlock ruleset opportunistically.

## What It Does Not Enforce Alone

- command intent semantics,
- network isolation,
- secret isolation across subprocesses,
- binary provenance verification,
- generic mutation detection for non-allowlisted direct executables.

## Operational Recommendations

- run under least-privilege OS accounts,
- keep workspace roots narrow,
- enable audit logging in production,
- monitor runtime audit records for degraded Linux `best_effort` Landlock outcomes,
- pair with dedicated filesystem safety tooling,
- treat `none` isolation as exceptional.
