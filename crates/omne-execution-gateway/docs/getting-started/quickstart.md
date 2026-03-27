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
);

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
  "policy_default_isolation": "best_effort"
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

Example fragment:

```json
{
  "request_resolution": {
    "program": "echo",
    "args": ["hello-from-omne-execution"],
    "cwd": ".",
    "workspace_root": ".",
    "declared_mutation": false,
    "requested_isolation": "none",
    "requested_isolation_source": "request",
    "requested_policy_meta": {
      "version": 1,
      "execution_isolation": "none"
    },
    "policy_default_isolation": "best_effort"
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
- requested `best_effort` or `strict` on current hosts -> denied as `isolation_not_supported`.
- requested `strict` above host support -> denied.
- mutating request with non-allowlisted program -> denied (when policy enforcement is on).
- shell-style launchers such as `sh`, `cmd`, and `pwsh` -> denied unless explicitly allowlisted.
- `prepare_command` with a mismatched `Command` program/args -> denied.
