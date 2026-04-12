# Changelog

## [Unreleased]

### Fixed

- preserve Linux hosts with unknown libc as explicit `unknown` platform state instead of dropping
  them or letting callers treat the host as implicit `*-unknown-linux-gnu`
- make host-platform target-triple mapping checked: Linux hosts with unknown libc now surface a
  dedicated error, while compatibility helpers fail closed by returning no host target triple
- remove the remaining `unreachable!` from checked host target-triple mapping so inconsistent
  non-Linux `linux_libc` metadata now fails closed with a recoverable error instead of panicking
- restrict Linux libc detection to current-process `/proc/self/maps` runtime evidence, so the
  crate no longer executes ambient `getconf`/`ldd` or guesses from unrelated filesystem markers
- make Linux host libc detection fail closed when current-process mappings contain both musl and
  glibc markers, instead of silently preferring musl or reviving a filesystem fallback
- keep ambiguous or unavailable Linux libc detection from producing any host platform / target
  triple at all, so callers cannot accidentally recover a GNU fallback after the primitive layer
  already failed closed
- stop treating the current binary's compile target env as host libc evidence, so statically
  linked `musl` binaries running on `glibc` hosts no longer misclassify the host as musl; Linux
  libc detection now trusts only current-process runtime mappings and otherwise stays unknown
- add checked target-triple and executable-suffix helpers that return structured errors for blank
  or unsupported triples, while making the legacy compatibility wrappers fail closed instead of
  forwarding unsupported inputs or misclassifying unknown triples as Windows targets
- pin direct regression coverage showing Linux hosts with unknown libc keep returning no detected
  host target triple instead of silently reviving a `*-unknown-linux-gnu` fallback
