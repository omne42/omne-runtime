# Operations Reference

This page describes behavior contracts for each filesystem operation.

## Common Rules

All operations:

- require a valid `root_id`,
- enforce path/root boundary checks,
- apply secret deny checks,
- return typed errors with stable `Error::code()`.

Mutating operations additionally require:

- corresponding permission flag,
- root `write_scope = workspace_write`.
- when invoked via CLI, explicit confirmation flag `--confirm-mutating-ops`.

## `read`

Request: `ReadRequest { root_id, path, start_line?, end_line? }`

Response: `ReadResponse { path, requested_path?, truncated=false, bytes_read, content, start_line?, end_line? }`

Notes:

- UTF-8 only.
- Regular files only.
- Line-range requires both bounds and `start <= end`.
- Fails on `max_read_bytes` overflow (no truncation mode).

## `list_dir`

Request: `ListDirRequest { root_id, path, max_entries? }`

Response: `ListDirResponse { path, requested_path?, entries, truncated, skipped_io_errors }`

Notes:

- Lists direct children, sorted deterministically.
- `max_entries` is capped by `limits.max_results` and an internal runtime cap (`100_000`) to bound retained top-k memory during very large directory scans.
- If either cap is hit, `truncated=true` indicates that more visible entries existed than were returned.
- `max_entries=0` is valid and returns count-only style behavior with empty entries.

## `glob`

Request: `GlobRequest { root_id, pattern }`

Response includes matches and traversal diagnostics:

- `matches`, `truncated`, `scanned_files`, `scan_limit_reached`, `scan_limit_reason`,
- `elapsed_ms`, `scanned_entries`, `skipped_walk_errors`, `skipped_io_errors`, `skipped_dangling_symlink_targets`.

Notes:

- Pattern must be root-relative and safe (`/`/`..` invalid).
- Traversal does not follow directory symlinks.

## `grep`

Request: `GrepRequest { root_id, query, regex=false, glob? }`

Response includes matches and traversal diagnostics plus skip counters:

- `matches[] = { path, line, text, line_truncated }`
- `skipped_too_large_files`, `skipped_non_utf8_files`
- same traversal fields as `glob`.

Notes:

- Empty/whitespace query is invalid.
- Non-UTF8 and oversized files are skipped (not fatal).
- Match text is redacted and clipped by `limits.max_line_bytes`.
- Response truncation can happen by byte budget (`scan_limit_reason=response_bytes`) even when
  `matches.len() < limits.max_results`, especially with long relative paths.
- For very large directories, set `traversal.stable_sort=false` to reduce sort overhead when
  deterministic order is not required.

## `stat`

Request: `StatRequest { root_id, path }`

Response: `StatResponse { path, requested_path?, type, size_bytes, modified_ms?, accessed_ms?, created_ms?, readonly }`

Notes:

- `type` is `file | dir | other`.
- Includes best-effort identity revalidation on supported platforms.

## `edit`

Request: `EditRequest { root_id, path, start_line, end_line, replacement }`

Response: `EditResponse { path, requested_path?, bytes_written }`

Notes:

- UTF-8 text file editing by line range.
- Preserves platform line-ending semantics where possible.
- Enforces read/write limits before commit.
- Atomic checked write path.

## `patch`

Request: `PatchRequest { root_id, path, patch }`

Response: `PatchResponse { path, requested_path?, bytes_written }`

Notes:

- Unified diff (`diffy`) with header/target checks.
- `limits.max_patch_bytes` applies to patch input.
- Atomic checked write path.
- No-op patch yields `bytes_written=0`.

## `mkdir`

Request: `MkdirRequest { root_id, path, create_parents=false, ignore_existing=false }`

Response: `MkdirResponse { path, requested_path?, created }`

Notes:

- Rejects root-like target (must be non-root leaf).
- Revalidates parent/target to reduce race windows.

## `write`

Request: `WriteFileRequest { root_id, path, content, overwrite=false, create_parents=false }`

Response: `WriteFileResponse { path, requested_path?, bytes_written, created }`

Notes:

- UTF-8 content input.
- Enforces `max_write_bytes`.
- Uses temp-file + checked atomic replace.

## `move`

Request: `MovePathRequest { root_id, from, to, overwrite=false, create_parents=false }`

Response: `MovePathResponse { from, to, requested_from?, requested_to?, moved, type }`

Notes:

- Same-entity moves may no-op (`moved=false`).
- Destination parent may be created if requested.
- Rejects unsafe or inconsistent root-resolution cases.

## `copy_file`

Request: `CopyFileRequest { root_id, from, to, overwrite=false, create_parents=false }`

Response: `CopyFileResponse { from, to, requested_from?, requested_to?, copied, bytes }`

Notes:

- Source must be regular file.
- Enforces write-size limits.
- Uses checked temp + replace commit semantics.

## `delete`

Request: `DeleteRequest { root_id, path, recursive=false, ignore_missing=false }`

Response: `DeleteResponse { path, requested_path?, deleted, type }`

`type` values: `file | dir | symlink | other | missing`.

Notes:

- `recursive=false` rejects directory deletion.
- `ignore_missing=true` converts missing target to `deleted=false`, `type=missing`.
- Symlinks are unlinked; targets are not followed.

## Feature-Gated Behavior

When `glob`, `grep`, or `patch` cargo features are disabled, corresponding APIs return `Error::NotPermitted` with a deterministic message.
