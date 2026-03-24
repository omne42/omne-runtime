# CLI Reference

Binary: `omne-fs`

## Global Options

- `--policy <PATH>`: policy file (`.toml` / `.json`).
- `--pretty`: pretty-print JSON output.
- `--error-format <text|json>`: error output format.
- `--redact-paths`: best-effort path redaction in JSON errors.
- `--redact-paths-strict`: stricter redaction (implies `--redact-paths`).
- `--max-patch-bytes <N>`: cap patch input bytes (stdin/file), additionally bounded by policy limits.
- `--confirm-mutating-ops`: required for mutating commands (`edit`, `patch`, `mkdir`, `write`, `delete`, `move`, `copy-file`).

## Common Notes

- Success output is JSON on stdout.
- Errors go to stderr, exit code is non-zero.
- Use `--error-format json` for machine integrations.

## Commands

### `read`

```bash
omne-fs --policy policy.toml read --root <root_id> <path> [--start-line N --end-line N]
```

### `list-dir`

```bash
omne-fs --policy policy.toml list-dir --root <root_id> [--max-entries N] [path]
```

- Default `path` is `.`.

### `glob`

```bash
omne-fs --policy policy.toml glob --root <root_id> "<pattern>"
```

### `grep`

```bash
omne-fs --policy policy.toml grep --root <root_id> "<query>" [--regex] [--glob "<pattern>"]
```

### `stat`

```bash
omne-fs --policy policy.toml stat --root <root_id> <path>
```

### `edit`

```bash
omne-fs --policy policy.toml --confirm-mutating-ops edit --root <root_id> <path> --start-line N --end-line N "<replacement>"
```

### `patch`

```bash
omne-fs --policy policy.toml --confirm-mutating-ops patch --root <root_id> <path> <patch_file>
```

- Use `-` as `<patch_file>` to read from stdin.

### `mkdir`

```bash
omne-fs --policy policy.toml --confirm-mutating-ops mkdir --root <root_id> <path> [--create-parents] [--ignore-existing]
```

### `write`

```bash
omne-fs --policy policy.toml --confirm-mutating-ops write --root <root_id> <path> <content_file> [--overwrite] [--create-parents]
```

- Use `-` as `<content_file>` to read from stdin.

### `delete`

```bash
omne-fs --policy policy.toml --confirm-mutating-ops delete --root <root_id> <path> [--recursive] [--ignore-missing]
```

### `move`

```bash
omne-fs --policy policy.toml --confirm-mutating-ops move --root <root_id> <from> <to> [--overwrite] [--create-parents]
```

### `copy-file`

```bash
omne-fs --policy policy.toml --confirm-mutating-ops copy-file --root <root_id> <from> <to> [--overwrite] [--create-parents]
```

## Integration Patterns

### Safer machine-mode wrapper

```bash
omne-fs \
  --policy ./policy.toml \
  --error-format json \
  --redact-paths-strict \
  read --root workspace src/lib.rs
```

### Patch from stdin

```bash
cat change.diff | omne-fs --policy ./policy.toml patch --root workspace src/lib.rs -
```

## Related

- [`operations-reference.md`](operations-reference.md)
- [`policy-reference.md`](policy-reference.md)
- [`faq.md`](faq.md)
