# Changelog

## [Unreleased]

### Fixed

- require exact canonical package-manager names in `SystemPackageManager::parse`, so callers can no
  longer smuggle leading/trailing whitespace or case-normalized aliases past the primitive
