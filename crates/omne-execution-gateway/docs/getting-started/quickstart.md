# Quickstart

## 1. Add Dependency

```toml
[dependencies]
omne-execution-gateway = { path = "../omne-execution-gateway" }
policy-meta = { path = "../../omne_foundation/crates/policy-meta" }
```

## 2. Minimal Rust Example

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
    ["hello"],
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

## 3. Check Host Capability

```bash
cargo run --bin omne-execution-capability
cargo run --bin omne-execution-capability -- --json
cargo run --bin omne-execution-capability -- --policy ./policy.json --json
```

Example output:

```text
supported_isolation=None
```

JSON mode example:

```json
{
  "supported_isolation": "none",
  "policy_default_isolation": "none"
}
```

If you pass `--policy ./policy.json`, `policy_default_isolation` reflects that file instead of the
default in-memory policy.

## 4. Optional CLI Mode

```bash
cargo run --bin omne-execution -- --policy ./policy.json --request ./request.json
```

`omne-execution` prints one JSON result object with canonical nested `request_resolution` and `event`
objects and the exit outcome.
The request adapter rejects unknown JSON fields and requires an explicit `declared_mutation` field.

Example fragment:

```json
{
  "request_resolution": {
    "program": "echo",
    "args": ["hello-from-omne-execution"],
    "cwd": "/abs/workspace",
    "workspace_root": "/abs/workspace",
    "declared_mutation": false,
    "requested_isolation": "none",
    "requested_isolation_source": "request",
    "requested_policy_meta": {
      "version": 1,
      "execution_isolation": "none"
    },
    "policy_default_isolation": "none"
  },
  "event": {
    "decision": "run",
    "requested_isolation": "none",
    "requested_policy_meta": {
      "version": 1,
      "execution_isolation": "none"
    },
    "supported_isolation": "none",
    "program": "echo",
    "cwd": "/abs/workspace",
    "workspace_root": "/abs/workspace",
    "declared_mutation": false,
    "reason": null
  },
  "exit_code": 0,
  "signal": null,
  "error": null
}
```

## 5. Common Failure Cases

- `cwd` outside `workspace_root` -> denied.
- missing, inaccessible, or non-directory `cwd` -> denied as `cwd_invalid`.
- requested `best_effort` or `strict` on current hosts -> denied as `isolation_not_supported`.
- requested `strict` above host support -> denied.
- mutating request with non-allowlisted program -> denied (when policy enforcement is on).
- request omitted `with_declared_mutation(...)` / `declared_mutation` -> denied as `mutation_declaration_required` (when policy enforcement is on).
- shell-style launchers such as `sh`, `cmd`, and `pwsh` -> denied unless explicitly allowlisted.
- known mutating tools such as `git`, `make`, `cargo`, `go`, package managers (`npm`, `pip`, `apt`, `dnf`, `yum`, `pacman`, `brew`) and core file-mutating utilities like `rm`, `mv`, `mkdir`, `touch`, `chmod`, or `ln` -> denied when declared non-mutating; to run them, declare mutation and use an allowlisted explicit path.
- `request_resolution` now reports the same validated canonical `cwd` / `workspace_root` view that appears in `event` when preflight reaches path validation.
- `prepare_command` with a mismatched `Command` program/args -> denied.
