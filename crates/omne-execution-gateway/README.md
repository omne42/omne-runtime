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
- explicit absolute `program` paths must already resolve to spawnable executables, are normalized to the canonical real executable path, and are revalidated immediately before spawn; this removes caller-controlled alias paths from the final `spawn` call and narrows the remaining OS-level race to the last check versus `exec`
- bare command names are resolved to a canonical absolute executable path during preflight, rebound as an executable identity, and rejected fail-closed if lookup cannot be bound
- workspace boundary enforcement (`cwd` must stay inside `workspace_root`; `cwd` / `workspace_root` reject symlink or reparse-point ancestors before canonical binding, except for macOS root aliases such as `/var` and `/tmp`, and execution revalidates the bound directory identities before spawn)
- explicit mutation declaration for every request when mutation enforcement is enabled
- fail-closed denial for shell-like or interpreter launchers such as `sh`, `cmd`, `pwsh`, `python`, and `node`; policy allowlists cannot authorize them because the gateway cannot bind arbitrary script or subcommand semantics to a stable executable identity
- gateway-managed spawns disconnect child stdio from the caller so `execute()` and prepared commands stay non-interactive by default
- structured decision events for audit/logging, including lossy display fields plus exact JSON encodings for `program` / `args` / explicit environment entries when OS strings are not valid UTF-8
- mutating and non-mutating allowlists plus opaque-launcher gates evaluate native `OsStr` / `Path` inputs directly instead of relying on lossy UTF-8 coercion

## Important Scope Notes

- `BestEffort` is a compatibility tier, not a strong sandbox guarantee.
- Linux, macOS, and Windows currently do not expose a native `BestEffort` or `Strict` sandbox. Requests above `None` fail closed.
- the in-memory `GatewayPolicy::default()` baseline now uses `allow_isolation_none = true` plus `default_isolation = none`, so a default `ExecGateway::new()` stays usable on today's `None`-only hosts; callers that want fail-closed sandbox preference must opt into `best_effort` or `strict` explicitly.
- `ExecGateway::new()` / `Default` are still deny-by-default on mutation policy: mutation enforcement remains on and both allowlists start empty, so callers that actually want commands to run must either provide allowlists or build a policy with `enforce_allowlisted_program_for_mutation = false`.
- Linux's previous native Landlock path is intentionally disabled until it can be reintroduced without relying on unsafe post-`fork` Rust execution.
- when `enforce_allowlisted_program_for_mutation = true`, callers must always set `with_declared_mutation(...)` intentionally instead of relying on the constructor default.
- declared mutations must bind to a `mutating_program_allowlist` executable identity via an explicit program path, and declared non-mutating requests must bind to a `non_mutating_program_allowlist` executable identity via an explicit program path.
- when mutation enforcement is enabled, allowlisted execution also rejects startup-sensitive request env such as `PATH`, `LD_*`, `DYLD_*`, `BASH_ENV`, `PYTHONPATH`, `RUBYOPT`, and `NODE_OPTIONS`, so audited program identity cannot be widened again through loader/interpreter hooks.
- shell-like and interpreter launchers are denied outright because the gateway cannot safely authorize runtimes that can execute arbitrary subcommands or scripts behind a single executable path.
- the gateway does not infer tool-specific read/write semantics from executable basenames. If a caller wants to authorize a read-only `git status` or `cargo metadata` path, that decision must live in the explicit `non_mutating_program_allowlist` policy instead of a built-in basename heuristic.
- mutation authorization now requires explicit program paths in both the request and the relevant policy allowlist. Bare program names are denied fail-closed because they do not bind to a stable executable, and allowlist checks resolve by executable identity rather than basename text.
- relative executable paths such as `./tool` or `bin/tool` are denied fail-closed because their spawn semantics can drift with the gateway process context; callers must use a bare command name or absolute path.
- bare command names remain allowed for `execute()`, but the gateway immediately resolves them to a concrete canonical executable path and audits that resolved path instead of the original bare token.
- explicit program paths are normalized to the canonical executable path that will actually be spawned, and that bound executable identity is revalidated before the spawn call; this closes caller-controlled symlink-alias drift but does not eliminate the final OS-level race between that last check and process creation.
- `prepare_command()` now requires the caller-supplied `Command` to already point at the same resolved executable path that the gateway bound during preflight; handing it an unresolved bare command name is rejected fail-closed as a prepared-command mismatch.
- `prepare_command()` also rejects caller-supplied explicit env or `current_dir` state when it does not match the audited request identity, so the validation input cannot silently describe a different execution context before the gateway rebuilds the final spawn command.
- allowlist matching binds explicit paths to executable identity; it does not prove binary provenance or infer arbitrary binary semantics beyond the configured executable path.
- JSON surfaces keep readable lossy `program` / `args` fields and also emit `program_exact` / `args_exact`, so audit consumers can reconstruct non-UTF-8 argv exactly instead of guessing from replacement characters.
- `GatewayPolicy::load_json()` only accepts no-follow regular files and fail-closed ancestor directory walks via `omne-fs-primitives`, so symlinks/reparse points cannot silently stand in for trusted policy input.
- `cwd` and `workspace_root` fail closed when their input path traverses a symlink or reparse-point ancestor, except for macOS system root aliases such as `/var` and `/tmp`, so request path validation does not silently re-authorize caller-controlled aliased directories during canonicalization.
- `ExecRequest` now carries explicit environment entries; `execute()` and `prepare_command()` clear inherited process state and apply only that audited environment before spawn.
- when `enforce_allowlisted_program_for_mutation = true`, request env is still audited, but startup-sensitive loader/interpreter/search-path overrides are denied fail-closed before preflight can authorize the execution.
- the CLI request adapter also rejects unknown JSON fields fail-closed, and `program` / `args` / explicit env entries now accept either plain UTF-8 strings or the exact OS-string JSON object encoding used in gateway output.
- if `audit_log_path` is configured, `evaluate()` / `resolve_request()` / `preflight()` stay side-effect free; audit parent creation and appendability checks move to `execute()` / `prepare_command()`, ancestor symlink/reparse point or non-directory blockers still fail closed before audited execution proceeds, and the final record write stays bound to the appendable file handle opened during preparation instead of reopening the path again after execution.
- allowlisted mutating and non-mutating programs bind both file identity and a preflight content fingerprint, and spawn revalidation rejects in-place executable rewrites before launch.
- if audit append succeeds during preflight but the final record write later fails, the execution result is surfaced as an explicit audit-log write failure instead of silently degrading to stderr-only reporting. When the command had already failed for another reason, the returned audit error now also includes that original execution error summary.
- `prepare_command` returns a spawn-only `PreparedCommand` wrapper instead of handing a mutable validated `Command` back to callers.
- `PreparedCommand::spawn()` returns a `PreparedChild` that carries the post-spawn sandbox observation alongside the owned child handle, so prepared spawns do not silently drop runtime sandbox metadata after preflight.
- `prepare_command` only emits the preflight `prepared`/`prepare_error` audit record. Final exit-status auditing still remains part of `execute()`, because handing back a spawn-only wrapper transfers child-lifecycle ownership to the caller.
- `execute()` and `PreparedCommand::spawn()` both revalidate bound `cwd` / `workspace_root` identities immediately before spawn.
- missing, inaccessible, or non-directory `cwd` values are reported as `cwd_invalid` instead of being mislabeled as workspace boundary violations.
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
)
.with_declared_mutation(false);
let execution = gateway.execute(&req);
let status = execution.result?;
assert!(status.success());
assert_eq!(execution.event.decision, omne_execution_gateway::ExecDecision::Run);
# Ok::<(), omne_execution_gateway::ExecError>(())
```

Use `ExecGateway::new()` only when you intentionally want that fail-closed default policy shape;
it will not authorize ordinary commands until you add allowlists or disable mutation enforcement.

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
