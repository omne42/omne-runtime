# omne-fs

`omne-fs` is a Rust library and CLI for policy-bounded filesystem operations.

It provides `read`, `list_dir`, `glob`, `grep`, `stat`, `edit`, `patch`, `mkdir`, `write`, `move`, `copy_file`, and `delete` with explicit root boundaries, permission gates, deny rules, and resource limits.

- Library operation names use `snake_case` (`list_dir`, `copy_file`).
- CLI subcommands use `kebab-case` (`list-dir`, `copy-file`).

MSRV: Rust `1.92.0`.

## Why This Exists

The core objective is explicit safety contracts for local file tooling:

- `SandboxPolicy`: what is allowed.
- `Root`: where access is anchored.
- `SecretRules`: what must be denied or redacted.
- `Limits`: how much work is allowed.
- `metadata.policy_meta`: optional shared/descriptive metadata, not an enforcement switch in `omne-fs`.

This project is not an OS sandbox. See `SECURITY.md` and `docs/security-guide.md`.

## Documentation

For full documentation, start here:

- [`docs/docs-system-map.md`](docs/docs-system-map.md) (documentation entrypoint)
- [`docs/architecture/system-boundaries.md`](docs/architecture/system-boundaries.md)
- [`docs/architecture/source-layout.md`](docs/architecture/source-layout.md)

- [`docs/index.md`](docs/index.md) (full portal)
- [`docs/getting-started.md`](docs/getting-started.md)
- [`docs/concepts.md`](docs/concepts.md)
- [`docs/policy-reference.md`](docs/policy-reference.md)
- [`docs/operations-reference.md`](docs/operations-reference.md)
- [`docs/cli-reference.md`](docs/cli-reference.md)
- [`docs/library-reference.md`](docs/library-reference.md)
- [`docs/security-guide.md`](docs/security-guide.md)
- [`docs/deployment-and-ops.md`](docs/deployment-and-ops.md)
- [`docs/faq.md`](docs/faq.md)
- [`docs/db-vfs.md`](docs/db-vfs.md)

## Quick Start (CLI)

1. Copy and edit a policy:

```bash
cp policy.example.toml ./policy.toml
# then replace <ABSOLUTE_PATH> with a real absolute path
```

2. Run help:

```bash
cargo run -p omne-fs-cli -- --policy ./policy.toml --help
```

3. Read a file:

```bash
cargo run -p omne-fs-cli -- \
  --policy ./policy.toml \
  read --root workspace README.md
```

## Quick Start (Library)

Add both `omne-fs` and `policy-meta`; `WriteScope` remains owned by `policy-meta`.

```rust
use omne_fs::ops::{Context, ReadRequest};
use omne_fs::policy::SandboxPolicy;
use policy_meta::WriteScope;

let mut policy =
    SandboxPolicy::single_root("workspace", "/abs/path/to/workspace", WriteScope::ReadOnly);
policy.permissions.read = true;

let ctx = Context::new(policy)?;
let resp = ctx.read_file(ReadRequest {
    root_id: "workspace".to_string(),
    path: "README.md".into(),
    start_line: None,
    end_line: None,
})?;

println!("{}", resp.content);
# Ok::<(), omne_fs::Error>(())
```

`SandboxPolicy` can also carry optional `[metadata.policy_meta]` fields for cross-tool policy
annotations. In `omne-fs` they are descriptive only and do not override
`[[roots]].write_scope`, permissions, or limits.

When the optional `git-permissions` feature is enabled, the revertible-write fallback evaluates
Git state against the declared root with a sanitized Git environment; ambient repository override
variables such as `GIT_DIR`, `GIT_WORK_TREE`, and `GIT_INDEX_FILE` are ignored for those checks.

## Cargo Features

- Default: `glob`, `grep`, `patch`
- Optional: `policy-io`, `git-permissions`

If a feature is disabled, the operation API remains available but returns `Error::NotPermitted`.

## Development

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo check -p omne-fs --all-targets --no-default-features
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
./scripts/gate.sh
```

Enable hooks once per clone:

```bash
git config core.hooksPath githooks
```
