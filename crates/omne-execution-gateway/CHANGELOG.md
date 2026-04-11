# Changelog

## [Unreleased]

- preserve `exit_code` / `signal` in `omne-execution` CLI output when the command already exited
  but the terminal audit write fails, so callers can distinguish "command ran, audit failed" from
  "command never produced a status"
- reject allowlisted wrapper chains such as `timeout ... env ...`, and rebuild prepared spawn
  commands only after final path revalidation, so non-mutating requests cannot smuggle opaque
  launchers through argv indirection or hold a stale `Command` across the prepare-to-spawn window
- stop treating runtime audit-sink availability as a preflight denial, so `resolve_request()` /
  `evaluate()` / `preflight()` stay pure projections while `execute()` / `prepare_command()`
  still fail closed before unaudited side effects
- classify opaque launcher families by executable family patterns instead of a small exact-name
  set, so variant frontends such as `python3.12`, `pip3.12`, and `nodejs` cannot bypass
  allowlist enforcement while still avoiding broad basename-based mutation guesses for direct
  tools
- reject relative `audit_log_path` values during preflight and appendable-sink validation, so
  audit logging cannot drift with caller-relative working directories or reopen a different sink
  after request evaluation
- always release the prepared audit sink lock even when a write fails, so one failed prepare or
  execution record cannot leave the bound audit handle locked and cascade into later audit write
  failures
- make `prepare_command()` request-only, so the prepared spawn is derived entirely from the
  audited `ExecRequest` instead of accepting a caller-supplied `Command` with hidden process state
- reject relative / drive-relative and other invalid executable paths before mutation allowlist
  classification, so default fail-closed policy no longer misreports `./tool`-style requests as
  allowlist denials instead of `relative_program_path_forbidden` / `program_path_invalid`
- add regression coverage proving rejected audit-log ancestor symlinks stay side-effect free
  during `preflight()`, so validation cannot recreate directories behind an unsafe path before
  failing closed
- bind every prepared executable to both file identity and a preflight content fingerprint, so
  even non-allowlisted requests fail closed if the same inode is rewritten between preflight and
  final spawn
- add regression coverage proving `prepare_command()` also keeps writing through the prepared
  audit sink after the on-disk audit path is rebound mid-execution, so the terminal record cannot
  be redirected or lost after preflight succeeds
- derive `omne-execution` CLI `request_resolution` from the same authoritative execution/preflight
  event snapshot returned for `event` and `result`, so the JSON output cannot mix a stale
  `resolve_request()` view with a later execution outcome
- classify copied or renamed opaque launchers against trusted launcher identity/content instead of
  basename text alone, so allowlisted aliases cannot smuggle `sh`/`python`/`env` behind a benign
  file name
- make the `omne-execution` CLI load request JSON through `omne-fs-primitives`' shared
  descriptor-backed no-follow reader instead of maintaining a second local file-open path, so
  request input stays on the same filesystem boundary as policy and audit-log handling
- rewrite authoritative audit events to `Deny` when final pre-spawn path/identity revalidation
  fails, so `RequestPathChanged` and related fail-closed errors no longer emit contradictory
  `decision=Run` records
- make audit-log sink validation/opening fail closed when any existing ancestor in the target path
  is a symlink/reparse point or a non-directory, so nested existing descendants cannot hide an
  unsafe earlier path component behind a "nearest existing ancestor" check
- route mutating and non-mutating allowlist authorization through native `OsStr` / `Path`
  matching instead of lossy request-program text, so Unix non-UTF-8 executable paths cannot
  collide with UTF-8 allowlist entries through replacement-character coercion
- route gateway policy JSON reads and audit-log sink validation/opening through
  `omne-fs-primitives` ancestor-safe helpers, so parent-directory symlink/reparse traversal stays
  fail-closed without re-implementing a second file-open boundary in `execution-gateway`
- drop the leftover audit-log ancestor precheck duplicated in `audit_log.rs`, so audit sink
  validation/opening stays bound to the stronger shared `omne-fs-primitives` descriptor walk
  instead of maintaining a second weaker race-prone path traversal check
- add regression coverage pinning the explicit `env` contract across `ExecRequest`,
  `RequestResolution`, `ExecEvent`, and the `omne-execution` CLI, so a future refactor cannot
  silently drop audited environment fields while execution still inherits them
- add regression coverage and README clarifications proving `resolve_request()` and the CLI keep
  bare-command requests bound to the resolved canonical executable path, so preflight and audit
  surfaces continue to describe the real executable identity
- make `ExecRequest` keep `required_isolation`, `requested_isolation_source`, and
  `declared_mutation` behind constructors/accessors/setters, so callers can no longer mutate those
  fields into self-contradictory states that only fail later during gateway evaluation
- add regression coverage proving `preflight()` itself rejects explicit non-executable program
  paths, so this fail-closed validation stays pinned before any execution attempt
- add regression coverage proving `non_mutating_program_allowlist` requests also bind a preflight
  content fingerprint, so in-place rewrites still fail closed before spawn instead of only pinning
  the mutating allowlist path
- keep prepared-command execution inside the authoritative audit boundary by making
  `PreparedChild::wait()` / `try_wait()` and drop finalization append the terminal execution record,
  so `prepare_command()` no longer stops at a preflight-only audit entry
- classify Windows drive-relative program paths such as `C:tool.exe` as explicit relative paths
  instead of bare commands, so gateway path validation and allowlist classification fail closed on
  the right branch
- clarify in docs and API references that `ExecGateway::new()` / `Default` stay fail-closed on
  mutation policy unless callers provide explicit allowlists or disable mutation enforcement, so
  the public constructor is not mistaken for a permissive execution baseline
- evaluate opaque launcher/interpreter policy against the final bound executable identity instead
  of the caller's alias path text, so an allowlisted symlink/alias cannot smuggle `sh`/`env`/`python`
  behind a benign-looking file name
- complete the public API reference's `ExecError` variant list so downstream callers can track the
  full documented gateway failure surface instead of an outdated subset
- normalize explicit and bare program bindings to the canonical real executable path before spawn,
  so validated symlink aliases are not passed back into the final `spawn()` call
- document `ExecRequest` / `RequestResolution` / `ExecEvent` environment fields more explicitly in
  the API reference, including `env_exact` and the fact that gateway-managed spawns clear inherited
  process state before applying only the audited request environment
- fail closed when request `cwd` or `workspace_root` traverses a symlink/reparse-point ancestor, while preserving macOS root aliases such as `/var` and `/tmp`, so canonical path binding does not silently re-authorize caller-controlled aliased directories
- stop hard-coding basename-based "known mutator" denials for declared non-mutating requests, so read-only calls such as `git status` or `cargo metadata` can be authorized explicitly through `non_mutating_program_allowlist` instead of product heuristics baked into the shared gateway
- add regression coverage proving explicit-path detection and request path validation keep non-UTF-8 / symlink-sensitive checks on native OS-string and filesystem boundaries
- return `PreparedChild` from `PreparedCommand::spawn()` so prepared spawns preserve the
  post-spawn sandbox observation instead of silently dropping monitor metadata after preflight
- deny startup-sensitive request env such as `PATH`, `LD_*`, `DYLD_*`, `BASH_ENV`,
  `PYTHONPATH`, `RUBYOPT`, and `NODE_OPTIONS` when mutation enforcement is enabled, so
  allowlisted execution cannot reopen loader/interpreter/search-path control through audited env
- add regression coverage proving bare-command `ExecEvent` output stays bound to the resolved
  absolute executable path instead of drifting back to the caller's unresolved token
- rebuild `prepare_command()` results from the validated request instead of reusing the caller's original `Command`, so hidden pre-exec and other opaque process state cannot bypass the gateway boundary
- bind audit-log writes to the appendable file handle opened during `execute()` / `prepare_command()`, so post-preflight path swaps cannot redirect the final record to a different sink
- treat `/usr/bin/env`-style launcher indirection as opaque execution, so non-mutating requests cannot bypass the launcher gate through `env`
- make `GatewayPolicy::default()` host-compatible on current `None`-only hosts, and teach `ExecGateway::new()` / `with_supported_isolation()` to choose a capability-aligned default isolation instead of advertising an unusable policy default
- require explicit absolute program paths to point at spawnable executables, and make Unix gateway
  tests resolve the actual shell path instead of assuming `/bin/sh`
- reuse `omne-fs-primitives` ambient no-follow regular-file helpers for policy/request/audit-log inputs, and let CLI request JSON carry exact OS-string encodings instead of forcing UTF-8-only input
- keep `evaluate()` / `resolve_request()` / `preflight()` side-effect free by moving audit-sink preparation to `execute()` / `prepare_command()`, while still failing closed before unaudited execution when the sink is unavailable
- retry appendable audit-log file opens when concurrent first-writer creation briefly reports `ENOENT`, so JSONL audit writes stay stable on macOS and other sensitive filesystems
- require `declared_mutation=false` requests to bind an explicit executable from `non_mutating_program_allowlist`; unknown tools can no longer bypass mutation policy just by self-labeling as read-only
- resolve bare command names to absolute executable identities before execution and fail closed
  when lookup cannot be bound
- reject explicit program paths that are not spawnable executables, and replace Unix test-only `/bin/sh` assumptions with runtime shell resolution so package tests stay portable across minimal hosts
- include `event.args` plus exact `program_exact` / `args_exact` JSON encodings so audit logs and CLI output preserve non-UTF-8 argv without relying on lossy replacement characters
- include explicit request `env` plus exact `env_exact` JSON encodings, and clear inherited process state so `execute()` / `prepare_command()` only spawn with the audited request environment
- harden audit-log parent creation so missing intermediate directories are created one component at a time with symlink checks instead of ambient `create_dir_all`
- move policy/request/audit-log file opens onto the same descriptor-backed no-follow parent walk, so ancestor symlinks/reparse points fail closed instead of being trusted between precheck and open
- reject policy, request, and audit-log paths that cross pre-existing symlinked ancestor directories even when the final nested directory already exists, closing the remaining ancestor-traversal gap in preflight and CLI file handling
- add regression coverage proving audit-log readiness checks still reject pre-existing symlinked ancestor directories even when deeper nested directories already exist behind the symlink target
- deny known-mutating tool families such as `git`, `make`, package managers, and core file-mutating utilities when callers label them `declared_mutation = false`; those tools must now declare mutation and bind an allowlisted explicit path
- bind allowlisted mutating programs to both executable identity and a preflight content fingerprint, so in-place binary rewrites fail closed before spawn
- add regression coverage for `cwd_invalid` so missing working directories do not regress back into `cwd_outside_workspace`
- reject symlinked, ancestor-symlinked, and special-file audit log destinations so audit logging fails closed on unsafe sinks
- reject symlinked, special-file, and oversized `omne-execution` request JSON inputs fail-closed
- require callers to declare mutation intent explicitly before gateway evaluation when mutation enforcement is enabled
- deny shell-like and interpreter launchers such as `sh`, `cmd`, `python`, `node`, and `perl` even when callers allowlist an explicit executable path, because the gateway cannot safely authorize arbitrary script or subcommand payloads behind one launcher binary
- bind mutating allowlist checks to the resolved executable identity behind explicit program paths instead of basename text
- surface missing, inaccessible, and non-directory working directories as `cwd_invalid` instead of `cwd_outside_workspace`
- make `resolve_request()` and CLI `request_resolution` reuse the gateway's validated canonical path view
- reject unknown `omne-execution` request JSON fields fail-closed
- stabilize oversized JSON fixture coverage so request/policy size-limit tests do not depend on free disk space
- keep mutation allowlist and opaque-launcher gates on native `OsStr` / `Path` inputs so non-UTF-8 program paths fail closed without lossy string coercion
- stabilize gateway full-workspace test coverage by making audit-log execution fixtures use an explicit `exit 0` shell command and giving nested noninteractive-stdin helpers enough timeout headroom under heavy test load
