# Changelog

## [Unreleased]

### Fixed

- stop inferring Windows executables from a raw `target_triple.contains("windows")` substring
  match; executable suffix detection now parses the target OS slot so malformed or unrelated custom
  triples no longer get a spurious `.exe`
- detect musl/Alpine Linux hosts before selecting the default target triple so callers do not
  incorrectly fall back to `*-unknown-linux-gnu`
- stop Linux host libc detection from executing ambient `getconf`/`ldd`, and fail closed instead
  of defaulting unknown Linux hosts to `*-unknown-linux-gnu`
