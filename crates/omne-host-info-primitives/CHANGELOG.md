# Changelog

## [Unreleased]

### Fixed

- stop treating an unknown Linux libc as `gnu`; host platform detection now fails closed until
  `gnu`/`musl` detection succeeds, so callers do not select the wrong target triple
- stop inferring the host Linux libc from ambient musl/glibc filesystem markers, including glibc
  loader-path fallbacks, so hosts without runtime probe evidence now fail closed instead of
  guessing `gnu`
- stop probing Linux libc through ambient `PATH`; runtime detection now only executes trusted
  absolute `getconf`/`ldd` locations instead of whichever bare command name resolves first
- reject unsupported target overrides and unknown host target triples instead of accepting arbitrary
  strings
- infer executable suffixes only from validated canonical target triples instead of substring
  matches
- add regression coverage for blank/near-miss target triples so canonical target validation and
  suffix inference do not silently widen again
