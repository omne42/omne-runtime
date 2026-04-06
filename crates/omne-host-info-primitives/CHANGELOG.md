# Changelog

## [Unreleased]

### Fixed

- preserve Linux hosts with unknown libc as explicit `unknown` platform state instead of dropping
  them or letting callers treat the host as implicit `*-unknown-linux-gnu`
- make host-platform target-triple mapping checked: Linux hosts with unknown libc now surface a
  dedicated error, while compatibility helpers fail closed by returning no host target triple
- detect musl/Alpine Linux hosts before selecting the default target triple so callers do not
  incorrectly fall back to `*-unknown-linux-gnu`
- make Linux host libc detection fail closed when musl and glibc loader markers coexist, instead
  of silently preferring musl and misclassifying ambiguous hosts
- prefer the current process' Linux loader/libc mappings over coarse filesystem markers when
  detecting `gnu` vs `musl`, so mixed-toolchain hosts stop selecting the wrong target triple just
  because an unrelated loader file exists on disk
- keep current-process glibc evidence authoritative even when musl loader files are present on
  disk, so mixed-toolchain hosts do not regress back to `*-unknown-linux-musl`
- stop treating ambiguous current-process loader/libc evidence as "no evidence"; conflicting
  glibc/musl process mappings now fail closed instead of falling back to filesystem markers
- stop Linux host libc detection from executing ambient `getconf`/`ldd`, and fail closed instead
  of defaulting unknown Linux hosts to `*-unknown-linux-gnu`
- add checked target-triple and executable-suffix helpers that return structured errors for blank
  or unsupported triples, while making the legacy compatibility wrappers fail closed instead of
  forwarding unsupported inputs or misclassifying unknown triples as Windows targets
