# Changelog

## [Unreleased]

- require callers to declare mutation intent explicitly before gateway evaluation when mutation enforcement is enabled
- bind mutating allowlist checks to the resolved executable identity behind explicit program paths instead of basename text
- surface missing, inaccessible, and non-directory working directories as `cwd_invalid` instead of `cwd_outside_workspace`
- make `resolve_request()` and CLI `request_resolution` reuse the gateway's validated canonical path view
- reject unknown `omne-execution` request JSON fields fail-closed
