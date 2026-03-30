# Changelog

## [Unreleased]

### Fixed

- stop treating an unknown Linux libc as `gnu`; host platform detection now fails closed until
  `gnu`/`musl` detection succeeds, so callers do not select the wrong target triple
- keep Linux libc detection working when `PATH` is narrowed by callers or test harnesses by
  recognizing standard glibc loader paths before command probes
