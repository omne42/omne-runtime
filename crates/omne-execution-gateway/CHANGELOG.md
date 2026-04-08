# Changelog

## [Unreleased]

- default `ExecGateway::new()` / `Default` / `with_supported_isolation()` policies now align with the
  actually supported isolation tier on the host instead of hard-coding `best_effort`; hosts that
  currently support only `none` now get a usable default gateway without silently weakening
  fail-closed isolation checks
- policy JSON loading and audit-log append setup now reuse `omne-fs-primitives` no-follow regular
  file helpers, so ancestor-symlink and special-file checks share the same fail-closed file-opening
  contract instead of carrying a weaker local copy
- include `event.args` plus exact `program_exact` / `args_exact` JSON encodings so audit logs and CLI output preserve non-UTF-8 argv without relying on lossy replacement characters
- deny known-mutating tool families such as `git`, `make`, package managers, and core file-mutating utilities when callers label them `declared_mutation = false`; those tools must now declare mutation and bind an allowlisted explicit path
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
