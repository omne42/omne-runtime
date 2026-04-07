# Changelog

## [Unreleased]

### Fixed

- require exact canonical package-manager names in `SystemPackageManager::parse`, so callers can no
  longer smuggle leading/trailing whitespace or case-normalized aliases past the primitive
- make default system-package recipe selection fail closed for known-but-unsupported operating
  systems such as `windows`, instead of collapsing them into an empty fallback list
- keep known operating-system parsing separate from default recipe support, so callers can tell the
  difference between an unknown OS string such as `freebsd` and a known platform such as `windows`
  that simply has no default system-package fallback in this crate
- stop hard-coding `-y`, `--noconfirm`, `--non-interactive`, cache toggles, and similar workflow
  flags into primitive install recipes, so caller policy does not leak into the shared manager API

### Changed

- split operating-system parsing from default recipe selection so callers can distinguish unknown OS
  strings from explicit unsupported-platform errors when asking for default recipes
- drop hard-coded non-interactive, cache, and idempotence flags from default install recipes, so
  the primitive now only exposes each manager's canonical install verb and leaves workflow policy
  to callers
