# Changelog

## [Unreleased]

### Fixed

- detect musl/Alpine Linux hosts before selecting the default target triple so callers do not
  incorrectly fall back to `*-unknown-linux-gnu`
- stop defaulting Linux libc detection failures to `gnu`; unsupported or inconclusive hosts now
  fail closed instead of silently selecting a glibc target triple
