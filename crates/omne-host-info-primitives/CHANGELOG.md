# Changelog

## [Unreleased]

### Fixed

- detect musl/Alpine Linux hosts before selecting the default target triple so callers do not
  incorrectly fall back to `*-unknown-linux-gnu`
- stop Linux host libc detection from executing ambient `getconf`/`ldd`, and fail closed instead
  of defaulting unknown Linux hosts to `*-unknown-linux-gnu`
- reject unsupported target-triple overrides and stop inferring `.exe` from arbitrary strings that
  merely contain `windows`, so invalid triples fail closed back to the host target instead of
  leaking into downstream artifact selection
