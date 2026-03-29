# Changelog

## [Unreleased]

- add regression coverage for `cwd_invalid` so missing working directories do not regress back into `cwd_outside_workspace`
- reject symlinked and special-file audit log destinations so audit logging fails closed on unsafe sinks
- reject symlinked, special-file, and oversized `omne-execution` request JSON inputs fail-closed
- require callers to declare mutation intent explicitly before gateway evaluation when mutation enforcement is enabled
- deny shell-like and interpreter launchers such as `python`, `node`, and `perl` unless callers allowlist an explicit executable path
- bind mutating allowlist checks to the resolved executable identity behind explicit program paths instead of basename text
- surface missing, inaccessible, and non-directory working directories as `cwd_invalid` instead of `cwd_outside_workspace`
- make `resolve_request()` and CLI `request_resolution` reuse the gateway's validated canonical path view
- reject unknown `omne-execution` request JSON fields fail-closed
- stabilize oversized JSON fixture coverage so request/policy size-limit tests do not depend on free disk space
