# Quickstart

## 1. Add Dependency

```toml
[dependencies]
omne-execution-gateway = { path = "../omne-execution-gateway" }
```

## 2. Minimal Rust Example

```rust
use omne_execution_gateway::{ExecGateway, ExecRequest, IsolationLevel};

let gateway = ExecGateway::new();
let req = ExecRequest::new(
    "sh",
    ["-lc", "echo hello"],
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

## 3. Check Host Capability

```bash
cargo run --bin omne-execution-capability
cargo run --bin omne-execution-capability -- --json
cargo run --bin omne-execution-capability -- --policy ./policy.json --json
```

Example output:

```text
supported_isolation=BestEffort
```

JSON mode example:

```json
{
  "supported_isolation": "best_effort",
  "supported_policy_meta": {
    "version": 1,
    "execution_isolation": "best_effort"
  },
  "policy_default_isolation": "best_effort",
  "policy_default_policy_meta": {
    "version": 1,
    "execution_isolation": "best_effort"
  }
}
```

If you pass `--policy ./policy.json`, `policy_default_isolation` and
`policy_default_policy_meta` reflect that file instead of the default in-memory policy.

## 4. Optional CLI Mode

```bash
cargo run --bin omne-execution -- --policy ./policy.json --request ./request.json
```

`omne-execution` prints one JSON result object with canonical nested `request_resolution` and `event`
objects, compatibility top-level projections, and exit outcome.

Example fragment:

```json
{
  "request_resolution": {
    "program": "sh",
    "args": ["-lc", "echo hello-from-omne-execution"],
    "cwd": ".",
    "workspace_root": ".",
    "declared_mutation": false,
    "requested_isolation": "best_effort",
    "requested_isolation_source": "policy_default",
    "requested_policy_meta": {
      "version": 1,
      "execution_isolation": "best_effort"
    },
    "policy_default_isolation": "best_effort"
  },
  "event": {
    "decision": "run",
    "requested_isolation": "best_effort",
    "requested_policy_meta": {
      "version": 1,
      "execution_isolation": "best_effort"
    },
    "supported_isolation": "best_effort",
    "program": "sh",
    "cwd": "/abs/workspace",
    "workspace_root": "/abs/workspace",
    "declared_mutation": false,
    "reason": null
  },
  "requested_isolation": "best_effort",
  "requested_isolation_source": "policy_default",
  "requested_policy_meta": {
    "version": 1,
    "execution_isolation": "best_effort"
  },
  "policy_default_isolation": "best_effort"
}
```

## 5. Common Failure Cases

- `cwd` outside `workspace_root` -> denied.
- requested `strict` above host support -> denied.
- mutating request with non-allowlisted program -> denied (when policy enforcement is on).
- `prepare_command` with a mismatched `Command` program/args -> denied.
