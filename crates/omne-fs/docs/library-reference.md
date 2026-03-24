# Library Reference

Crate: `omne-fs`

## Install

```toml
[dependencies]
omne-fs = { version = "0.2.0" }
```

With policy file loading helpers:

```toml
[dependencies]
omne-fs = { version = "0.2.0", features = ["policy-io"] }
```

## Top-Level API Surface

Re-exported key types:

- `Context`
- `SandboxPolicy`, `Root`, `Permissions`, `Limits`, `SecretRules`, `TraversalRules`, `PathRules`
- Request/response structs for all operations
- `Error`, `Result`

## Constructing Context

### Basic

```rust
use omne_fs::{Context, RootMode, SandboxPolicy};

let mut policy = SandboxPolicy::single_root("workspace", "/abs/workspace", RootMode::ReadOnly);
policy.permissions.read = true;

let ctx = Context::new(policy)?;
# Ok::<(), omne_fs::Error>(())
```

### Builder Entry Point

```rust
use omne_fs::{Context, RootMode, SandboxPolicy};

let policy = SandboxPolicy::single_root("workspace", "/abs/workspace", RootMode::ReadOnly);
let ctx = Context::builder(policy).build()?;
# Ok::<(), omne_fs::Error>(())
```

## Loading Policy From File (`policy-io`)

```rust
let policy = omne_fs::policy_io::load_policy("./policy.toml")?;
let ctx = omne_fs::Context::from_policy_path("./policy.toml")?;
# Ok::<(), omne_fs::Error>(())
```

## Calling Operations

You can call via free functions or context methods.

```rust
use omne_fs::{Context, ReadRequest, RootMode, SandboxPolicy};

let mut policy = SandboxPolicy::single_root("workspace", "/abs/workspace", RootMode::ReadOnly);
policy.permissions.read = true;
let ctx = Context::new(policy)?;

let response = ctx.read_file(ReadRequest {
    root_id: "workspace".to_string(),
    path: "README.md".into(),
    start_line: None,
    end_line: None,
})?;

assert!(!response.truncated);
# Ok::<(), omne_fs::Error>(())
```

## Error Handling

Use `Error::code()` for stable classification:

```rust
# use omne_fs::{Error, Result};
# fn classify(err: &Error) -> &'static str {
err.code()
# }
```

`Error` is `#[non_exhaustive]`; do not exhaustively match variants without a wildcard.

## Feature Flags

- `glob` (default)
- `grep` (default)
- `patch` (default)
- `policy-io` (optional)

When `glob`/`grep`/`patch` are disabled, the API remains callable and returns `Error::NotPermitted`.

## Integration Tips

- Reuse one `Context` across multiple calls when using one policy.
- Keep policy strict and explicit (minimal permissions).
- Prefer root-relative request paths (`allow_absolute = false`) for untrusted callers.

## Related

- [`policy-reference.md`](policy-reference.md)
- [`operations-reference.md`](operations-reference.md)
- [`security-guide.md`](security-guide.md)
