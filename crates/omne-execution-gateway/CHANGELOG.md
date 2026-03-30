# Changelog

## [Unreleased]

- resolve bare command names to absolute executable identities before execution, fail closed when lookup cannot be bound, and require `prepare_command()` callers to pass the same resolved executable path instead of an unresolved bare `Command`
- include `event.args` plus exact `program_exact` / `args_exact` JSON encodings so audit logs and CLI output preserve non-UTF-8 argv without relying on lossy replacement characters
- include explicit request `env` plus exact `env_exact` JSON encodings, and clear inherited process state so `execute()` / `prepare_command()` only spawn with the audited request environment
- harden audit-log parent creation so missing intermediate directories are created one component at a time with symlink checks instead of ambient `create_dir_all`
- move policy/request/audit-log file opens onto the same descriptor-backed no-follow parent walk, so ancestor symlinks/reparse points fail closed instead of being trusted between precheck and open
- deny known-mutating tool families such as `git`, `make`, package managers, and core file-mutating utilities when callers label them `declared_mutation = false`; those tools must now declare mutation and bind an allowlisted explicit path
- bind allowlisted mutating programs to both executable identity and a preflight content fingerprint, so in-place binary rewrites fail closed before spawn
- add regression coverage for `cwd_invalid` so missing working directories do not regress back into `cwd_outside_workspace`
- reject symlinked, ancestor-symlinked, and special-file audit log destinations so audit logging fails closed on unsafe sinks
- reject symlinked, special-file, and oversized `omne-execution` request JSON inputs fail-closed
- require callers to declare mutation intent explicitly before gateway evaluation when mutation enforcement is enabled
- deny shell-like and interpreter launchers such as `python`, `node`, and `perl` unless callers allowlist an explicit executable path
- bind mutating allowlist checks to the resolved executable identity behind explicit program paths instead of basename text
- surface missing, inaccessible, and non-directory working directories as `cwd_invalid` instead of `cwd_outside_workspace`
- make `resolve_request()` and CLI `request_resolution` reuse the gateway's validated canonical path view
- reject unknown `omne-execution` request JSON fields fail-closed
- stabilize oversized JSON fixture coverage so request/policy size-limit tests do not depend on free disk space
- keep mutation allowlist, opaque-launcher, and known-mutator gates on native `OsStr` / `Path` inputs so non-UTF-8 program paths fail closed without lossy string coercion
