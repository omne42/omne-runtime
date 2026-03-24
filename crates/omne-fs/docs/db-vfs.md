# Decision: DB-backed Virtual FS (DB-VFS)

Status: Implemented (MVP)  
Date: 2026-01-29  
Implementation: 2026-01-31

## Context

`omne-fs` is designed to enforce an explicit safety model (policy/roots/secrets/limits) while
executing filesystem tools against the **local OS filesystem**.

In server / high-concurrency workloads (docs processing, crawlers, many agents), “local disk as the
shared workspace” is operationally awkward:

- Ephemeral storage and deployment churn make persistence hard.
- Large directory walks are expensive and contend with other workloads.
- TOCTOU issues and cross-process coordination (locks) are harder to reason about.

Key observation from the target workload:

- Concurrency mostly comes from **many users**, not a single user doing huge parallel edits.
- Per-user file counts are usually small, files are small (often **< ~1000 lines**), and operations
  tend to be concentrated under a few directory prefixes (not whole-workspace “search everything”).

This makes a DB-backed “virtual filesystem” feasible if we keep search **scoped** (workspace +
directory prefix) and enforce strict budgets (files/bytes/time).

## Goal

Provide a DB-backed Virtual FS (DB-VFS) that supports tool semantics equivalent to:

- `read` (line ranges + byte caps)
- `glob` (path listing)
- `grep` / rg-like search (regex/substr, returning line numbers + lines)
- `overwrite write` (create/replace)
- `patch` (diff write / unified diff)
- `delete`

This is targeted at docs/crawler workflows (not full “build an entire repo” coding workflows).

## Decision

1. Keep `omne-fs` focused on local filesystem operations and a small dependency graph.
2. Implement DB-VFS as a **separate** project (crate and/or service), reusing semantics and error
   codes where possible.
3. Database support strategy:
   - **P0**: PostgreSQL (production)
   - **P0**: SQLite (dev/test, single-node deployments)
   - **P2**: MySQL (only if infrastructure requires it)

## Rationale

- Adding DB drivers/ORMs would significantly bloat `omne-fs` (compile time, binary size,
  system deps) and often forces async IO into otherwise sync-friendly code paths.
- A DB-backed backend benefits from independent evolution (schema migrations, pooling, quotas,
  indexes) without destabilizing local-fs semantics.
- Given directory-local, small-file workloads, a v1 grep can be “DB scope filter + streaming scan”
  without requiring a full search cluster.

## Compatibility targets (semantics)

- Preserve the explicit safety model shape: **Policy + Secrets + Limits** (or an equivalent).
- Preserve stable error codes where possible; add DB-specific ones as needed:
  `conflict`, `quota_exceeded`, `timeout`.
- Preserve ordering guarantees:
  - `glob` sorted by path
  - `grep` sorted by `(path, line)`

## Proposed API (DB-VFS)

Minimal operations (library or service):

- `read(workspace_id, path, {start_line,end_line}, limits)`
- `write(workspace_id, path, content, expected_version?)` (CAS / optimistic concurrency)
- `patch(workspace_id, path, unified_diff, expected_version)` (atomic apply + CAS)
- `delete(workspace_id, path, { expected_version, force? })`
- `glob(workspace_id, glob, path_prefix?, max_results)`
- `grep(workspace_id, pattern, {glob?, path_prefix?}, budgets)` (streaming)

Notes:

- DB-VFS “roots” are modeled as namespaces: `(workspace_id, path_prefix)` rather than OS paths.
- `expected_version` avoids silent lost updates and makes concurrent edits explicit.
- `path_prefix` is optional in the API shape, but request validation should require a bounded scope:
  - `grep`: require explicit `path_prefix` (or an exact-path query that is already bounded).
  - `glob`: require `path_prefix` when the pattern is broad (for example `"**/*.md"`).
  - Derivation rule: auto-derive only when the glob starts with a contiguous literal directory prefix
    before the first wildcard (for example `"docs/**/*.md"` -> `"docs/"`).
  - Otherwise (no safe literal prefix), reject requests that omit `path_prefix`.
- Concurrency (CAS) semantics in the MVP implementation:
  - `patch` requires `expected_version`.
  - `write(expected_version = None)` is **create-only** (conflicts if the file exists); updates
    require `expected_version`.
  - `delete(expected_version = Some(v))` enforces CAS.
  - `delete(expected_version = None)` should be rejected unless `force = true` is explicitly set.

## Minimal schema (Postgres-ish)

Single-table MVP:

`files(workspace_id, path, content, size_bytes, version, created_at, updated_at, metadata_json)`

Key indexes:

- Primary: `(workspace_id, path)`
- Optional: `(workspace_id, updated_at)` for incremental crawls
- Optional: prefix acceleration on `path` (implementation-specific)

Versioning/history is optional and can be added later:

- `file_versions(workspace_id, path, version, content, created_at, actor, op_metadata)`

## Grep strategy (v1)

Implement `rg`-like search as two phases:

1. **Scope reduction in DB**: `workspace_id` + required/encouraged `path_prefix` (+ optional glob).
2. **Streaming scan in app**: line-by-line regex/substr matching to produce `(path, line, text)`
   results, with redaction and strict budgets.

Budgets to enforce:

- `max_files`, `max_bytes_per_file`, `max_matches`, `max_ms`

## Future work

1. **Streaming and quotas**:
   - Cursor/pagination for `grep` (and optionally `glob`).
   - Per-workspace quotas + rate limits beyond per-request limits.
2. **Search acceleration (optional)**:
   - Postgres `pg_trgm` / FTS to reduce candidate sets before regex scanning.
3. **Service hardening**:
   - Postgres service mode (pooling, migrations at startup).
4. **Integration points**:
   - Allow higher-level products (e.g. `omne-agent`) to switch file tools to DB-VFS in server mode.

## Implementation notes

This decision is implemented in the sibling `db-vfs/` project (crate + HTTP service). For reproducible
local validation, pin to a known commit/tag in that repository before running the examples below.

Prerequisites:

- Repository: `https://github.com/omne42/db-vfs`
- Example setup:

```bash
git clone https://github.com/omne42/db-vfs.git ../db-vfs
cd ../db-vfs
git checkout <tag-or-commit>
```

Directory assumption for the commands below: this repository and `db-vfs/` are sibling directories.

Quick check:

```bash
cd ../db-vfs
cargo test
```

Run the HTTP service (SQLite):

```bash
cd ../db-vfs
cargo run -p db-vfs-service -- \
  --sqlite ./db-vfs.sqlite \
  --policy ./policy.example.toml \
  --listen 127.0.0.1:8080
```

Run the HTTP service (Postgres; requires `--features postgres`):

```bash
cd ../db-vfs
# Example only; do not commit or expose real credentials.
export DB_VFS_DSN="postgres://<user>:<password>@localhost:5432/<db>"
cargo run -p db-vfs-service --features postgres -- \
  --postgres "$DB_VFS_DSN" \
  --policy ./policy.example.toml \
  --listen 127.0.0.1:8080
```

Security note: do not put production credentials directly on a shell command line; prefer secrets
injection or protected environment configuration.

## Semantic differences vs local-fs `omne-fs`

Even if the high-level operations look similar (`read/glob/grep/write/patch/delete`), DB-VFS is
**not** a drop-in replacement for the local filesystem backend:

- **Path model**: DB-VFS paths live in a namespace `(workspace_id, path)` (optionally constrained by
  a `path_prefix`), not OS paths. There are no drive letters, UNC prefixes, or platform-specific
  separators.
- **Symlinks / special files**: local-fs semantics must defend against symlinks, special files, and
  best-effort root boundary enforcement. DB-VFS can (and should) exclude these concepts entirely.
- **Concurrency model**: DB-VFS uses CAS/versioning (`expected_version`) to make concurrent edits
  explicit. Local-fs `omne-fs` is best-effort and not TOCTOU-hardened.
- **Traversal cost**: DB-VFS “glob/grep” should be scoped by `path_prefix` and can leverage DB
  indexes; local-fs traversal is a directory walk with strict budgets.

## Open questions

- Do we want an append-only mode for crawlers (write new versions, never mutate)?
- Do we want to standardize a cursor protocol for `grep` streaming?

## Related

- [`index.md`](index.md)
- [`security-guide.md`](security-guide.md)
- [`../SECURITY.md`](../SECURITY.md)
