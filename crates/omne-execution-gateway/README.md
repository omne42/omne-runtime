# omne-execution-gateway

Cross-platform command execution gateway for agent runtimes and tooling, with explicit isolation semantics and fail-closed policy enforcement.

## Why This Exists

`omne-execution-gateway` provides one consistent execution boundary for `program + args + cwd` command calls.

It prevents fragmented per-caller safety logic and provides deterministic decisions with structured audit data.
Audit surfaces expose a canonical `policy-meta` projection for requested isolation.

## Core Guarantees

- capability model: `None | BestEffort | Strict`
- fail-closed if requested isolation exceeds host support
- fail-closed if a request marked as `policy_default` no longer matches the gateway's current policy default
- workspace boundary enforcement (`cwd` must be inside `workspace_root`, and execution uses the canonicalized working directory)
- two-way mutation declaration enforcement for allowlisted mutating programs
- fail-closed denial for opaque command launchers such as `sh`, `cmd`, and `pwsh` unless they are explicitly allowlisted
- structured decision events for audit/logging

## Important Scope Notes

- `BestEffort` is a compatibility tier, not a strong sandbox guarantee.
- On Linux, `BestEffort` now attempts a Landlock sandbox opportunistically, but it does not fail closed if the host cannot enforce it.
- Linux execution events now report the observed best-effort Landlock runtime outcome when the command is actually spawned.
- Linux `Strict` currently enforces a workspace write boundary, but still allows read/execute access outside the workspace.
- macOS and Windows currently do not implement a native `BestEffort` sandbox; they report only `None` support and fail closed if `BestEffort` or `Strict` is requested.
- allowlisted mutating programs must explicitly set `declared_mutation = true`, and declared mutations must still use an allowlisted bare program name or exact allowlisted path.
- shell-like opaque launchers are denied by default because the gateway cannot trust `declared_mutation = false` for an interpreter that can execute arbitrary subcommands.
- bare allowlist entries only match bare program names; explicit path entries only match that explicit path. This avoids granting mutation rights to arbitrary same-basename binaries in other directories.
- mutation checks remain name/path based; they do not prove binary provenance or infer arbitrary binary semantics.
- if `audit_log_path` is configured, preflight creates missing parent directories and rejects requests fail-closed when the audit log cannot be opened for append
- `prepare_command` rejects a `Command` when its program/args diverge from the validated `ExecRequest`.
- `execute()` is the primary integration surface because it preserves `ExecEvent` and runtime sandbox metadata.

## Platform Capability (v0.1.0)

- Linux: detects Landlock support at runtime; `Strict` when available, otherwise `BestEffort`
- macOS: `None`
- Windows: `None`

If `Strict` is requested but unsupported, execution is denied (no silent downgrade).
If `BestEffort` is requested on a host that reports only `None`, execution is also denied instead
of falling through to an unsandboxed spawn.

## Quick Usage

```rust
use omne_execution_gateway::{ExecGateway, ExecRequest};
use policy_meta::ExecutionIsolation;

let gateway = ExecGateway::new();
let req = ExecRequest::new(
    "echo",
    vec!["hello"],
    ".",
    ExecutionIsolation::BestEffort,
    ".",
);
let execution = gateway.execute(&req);
let status = execution.result?;
assert!(status.success());
assert_eq!(execution.event.decision, omne_execution_gateway::ExecDecision::Run);
# Ok::<(), omne_execution_gateway::ExecError>(())
```

## Capability Check

```bash
cargo run --bin omne-execution-capability
cargo run --bin omne-execution-capability -- --json
cargo run --bin omne-execution-capability -- --policy ./policy.json --json
```

`--json` emits the raw capability fields directly for machine consumption.
`--policy` lets capability reporting reflect a specific `GatewayPolicy` file instead of defaults.

## CLI Adapter

```bash
cargo run --bin omne-execution -- --policy ./policy.json --request ./request.json
```

## Documentation

- `docs/docs-system-map.md`
- `docs/architecture/system-boundaries.md`
- `docs/architecture/source-layout.md`
- `docs/index.md`
- `../../docs/workspace-crate-boundaries.md`

`docs/` is the source of truth. `site/` is generated output, not the maintained record.

GitHub Pages deployment is fully automated via GitHub Actions and includes version selection (powered by `mike`).
