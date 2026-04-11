# Changelog

## [Unreleased]

### Fixed

- preserve Linux hosts with unknown libc as explicit `unknown` platform state instead of dropping
  them or letting callers treat the host as implicit `*-unknown-linux-gnu`
- make host-platform target-triple mapping checked: Linux hosts with unknown libc now surface a
  dedicated error, while compatibility helpers fail closed by returning no host target triple
- stop treating coarse distro markers such as `/etc/alpine-release` as Linux libc evidence; when
  runtime mappings are unavailable the crate now falls back only to concrete loader markers, so
  uncertain hosts fail closed instead of guessing a downloadable target triple
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
