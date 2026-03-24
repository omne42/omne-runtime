# Unsafe Boundary ADR

## Status

Accepted and implemented.

## Decision

`omne-runtime` does **not** add a global `platform` crate as a catch-all home for
cross-platform code or `unsafe`.

Instead, the repository enforces capability-based boundaries:

- `crates/omne-archive-primitives`
  - low-level archive/compression primitives shared across callers
- `crates/omne-fs-primitives`
  - low-level filesystem primitives shared across callers
- `crates/omne-integrity-primitives`
  - low-level digest parsing and integrity verification primitives shared across callers
- `crates/omne-process-primitives`
  - low-level process/runtime primitives shared across callers
- `crates/omne-fs`
  - filesystem policy, path semantics, redaction, and tooling
- `crates/omne-execution-gateway`
  - execution policy, request routing, and sandbox orchestration

`unsafe` is governed the same way:

- binaries and leaf crates without local syscall/FFI boundaries use `#![forbid(unsafe_code)]`
- crates that must own a narrow syscall/FFI boundary use `#![deny(unsafe_code)]`
- those crates may locally allow `unsafe` only in narrow `platform/*` or `sandbox/*` modules

## Why

A global `platform` crate would collapse unrelated concerns into one bucket:

- archive parsing and compression format handling
- filesystem replacement semantics
- digest parsing and integrity verification
- path comparison quirks
- host command probing and sudo-eligible execution
- process-tree cleanup
- sandbox lifecycle hooks

Those are not one abstraction. They are different capabilities that happen to need
`cfg(...)` or low-level OS interaction.

The real goal is not “put all platform code together”. The goal is:

- zero duplication
- clear ownership
- auditable `unsafe` boundaries

Capability-based crates satisfy that goal without creating a dumping ground.

## Placement Rules

Move code into a primitives crate only if all of the following are true:

1. it is used by multiple callers
2. it is policy-free and product-neutral
3. it is a real low-level primitive, not domain behavior

Keep code local when it encodes domain semantics, even if it is cross-platform:

- path normalization and alias-root policy
- redaction and secret-path behavior
- timeout/cancellation policy
- sandbox choice and execution decision logic

## Consequences

- New archive/compression helpers belong in `omne-archive-primitives` only when they are
  reusable low-level primitives or format readers shared across callers.
- New platform-specific filesystem helpers belong in `omne-fs-primitives` only when they
  are reusable low-level primitives.
- New digest parsing and integrity verification helpers belong in
  `omne-integrity-primitives` only when they are reusable low-level primitives.
- New process-control or host-command helpers belong in `omne-process-primitives` only when they are reusable
  low-level primitives.
- `omne-fs` must not absorb process-control APIs just because they are cross-platform.
- `omne-execution-gateway` keeps sandbox lifecycle details local unless a lower-level,
  reusable primitive clearly emerges.
