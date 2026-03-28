# Changelog

## [Unreleased]

- bind mutating allowlist checks to the resolved executable identity behind explicit program paths instead of basename text
- make `resolve_request()` and CLI `request_resolution` reuse the gateway's validated canonical path view
- keep audit logging fail-closed by surfacing write failures as structured execution errors
