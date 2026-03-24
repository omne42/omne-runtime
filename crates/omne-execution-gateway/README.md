# omne-execution-gateway

Cross-platform command execution gateway for agent runtimes and tooling, with explicit isolation semantics and fail-closed policy enforcement.

## Why This Exists

`omne-execution-gateway` provides one consistent execution boundary for `program + args + cwd` command calls.

It prevents fragmented per-caller safety logic and provides deterministic decisions with structured audit data.
Those audit and CLI surfaces also expose a canonical `policy-meta` projection for requested isolation.

## Core Guarantees

- capability model: `None | BestEffort | Strict`
- fail-closed if requested isolation exceeds host support
- fail-closed if a request marked as `policy_default` no longer matches the gateway's current policy default
- workspace boundary enforcement (`cwd` must be inside `workspace_root`, and execution uses the canonicalized working directory)
- declared-mutation enforcement via allowlisted filesystem tool programs
- structured decision events for audit/logging

## Important Scope Notes

- `BestEffort` is a compatibility tier, not a strong sandbox guarantee.
- On Linux, `BestEffort` now attempts a Landlock sandbox opportunistically, but it does not fail closed if the host cannot enforce it.
- Linux execution events now report the observed best-effort Landlock runtime outcome when the command is actually spawned.
- Linux `Strict` currently enforces a workspace write boundary, but still allows read/execute access outside the workspace.
- mutation allowlist checks rely on caller-declared mutation plus requested program/path form; they do not prove binary provenance.
- `prepare_command` rejects a `Command` when its program/args diverge from the validated `ExecRequest`.
- `execute()` is the primary integration surface because it preserves `ExecEvent` and runtime sandbox metadata.

## Platform Capability (v0.1.0)

- Linux: detects Landlock support at runtime; `Strict` when available, otherwise `BestEffort`
- macOS: `BestEffort`
- Windows: `BestEffort`

If `Strict` is requested but unsupported, execution is denied (no silent downgrade).

## Quick Usage

```rust
use omne_execution_gateway::{ExecGateway, ExecRequest, IsolationLevel};

let gateway = ExecGateway::new();
let req = ExecRequest::new(
    "sh",
    vec!["-lc", "echo hello"],
    ".",
    IsolationLevel::BestEffort,
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

`--json` emits both raw isolation fields and canonical `policy-meta` fragments for machine consumption.
`--policy` lets capability reporting reflect a specific `GatewayPolicy` file instead of defaults.

## CLI Adapter

```bash
cargo run --bin omne-execution -- --policy ./policy.json --request ./request.json
```

## Documentation

- docs source: `docs/`
- site config: `mkdocs.yml`
- auto deployment: `.github/workflows/docs-pages.yml`

GitHub Pages deployment is fully automated via GitHub Actions and includes version selection (powered by `mike`).
