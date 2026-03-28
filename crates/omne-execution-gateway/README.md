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
- fail-closed if `program` is neither a bare command name nor an absolute path
- explicit absolute `program` paths are bound as file identities and revalidated immediately before spawn
- workspace boundary enforcement (`cwd` must stay inside `workspace_root`, and execution binds canonicalized directory identities before spawn)
- two-way mutation declaration enforcement for allowlisted mutating programs
- fail-closed denial for opaque command launchers such as `sh`, `cmd`, and `pwsh` unless they are explicitly allowlisted
- gateway-managed spawns disconnect child stdio from the caller so `execute()` and prepared commands stay non-interactive by default
- structured decision events for audit/logging

## Important Scope Notes

- `BestEffort` is a compatibility tier, not a strong sandbox guarantee.
- Linux, macOS, and Windows currently do not expose a native `BestEffort` or `Strict` sandbox. Requests above `None` fail closed.
- Linux's previous native Landlock path is intentionally disabled until it can be reintroduced without relying on unsafe post-`fork` Rust execution.
- allowlisted mutating programs must explicitly set `declared_mutation = true`, and declared mutations must bind to an allowlisted executable identity via an explicit program path.
- shell-like opaque launchers are denied by default because the gateway cannot trust `declared_mutation = false` for an interpreter that can execute arbitrary subcommands.
- mutation authorization now requires explicit program paths in both the request and policy allowlist. Bare program names are denied fail-closed because they do not bind to a stable executable, and allowlist checks resolve by executable identity rather than basename text.
- relative executable paths such as `./tool` or `bin/tool` are denied fail-closed because their spawn semantics can drift with the gateway process context; callers must use a bare command name or absolute path.
- explicit program paths are revalidated as file identities before spawn, so even stable aliases such as symlinks cannot silently drift to a different executable after preflight succeeds.
- allowlist matching binds explicit paths to executable identity; it does not prove binary provenance or infer arbitrary binary semantics beyond the configured executable path.
- `GatewayPolicy::load_json()` only accepts no-follow regular files, so symlinks and other special files cannot silently stand in for trusted policy input.
- if `audit_log_path` is configured, preflight creates missing parent directories and rejects requests fail-closed when the audit log cannot be opened for append.
- if audit append succeeds during preflight but the final record write later fails, the execution result is surfaced as an explicit audit-log write failure instead of silently degrading to stderr-only reporting.
- `prepare_command` returns a spawn-only `PreparedCommand` wrapper instead of handing a mutable validated `Command` back to callers.
- `execute()` and `PreparedCommand::spawn()` both revalidate bound `cwd` / `workspace_root` identities immediately before spawn.
- `execute()` and `PreparedCommand::spawn()` bind `stdin/stdout/stderr` to null handles; callers that need interactive or captured stdio should use a different process primitive.
- `execute()` is the primary integration surface because it preserves `ExecEvent` and runtime sandbox metadata.

## Platform Capability (v0.1.0)

- Linux: `None`
- macOS: `None`
- Windows: `None`

If `Strict` is requested but unsupported, execution is denied (no silent downgrade).
If `BestEffort` is requested on a host that reports only `None`, execution is also denied instead
of falling through to an unsandboxed spawn.

## Quick Usage

```rust
use omne_execution_gateway::{ExecGateway, ExecRequest, GatewayPolicy};
use policy_meta::ExecutionIsolation;

let gateway = ExecGateway::with_policy(GatewayPolicy {
    allow_isolation_none: true,
    enforce_allowlisted_program_for_mutation: false,
    ..GatewayPolicy::default()
});
let req = ExecRequest::new(
    "echo",
    vec!["hello"],
    ".",
    ExecutionIsolation::None,
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
