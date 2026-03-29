# Introduction

`omne-execution-gateway` is a cross-platform command execution gateway for agent runtimes and tool orchestration systems.

It provides one policy-enforced path to execute third-party commands with deterministic isolation checks and fail-closed behavior.

## Why It Exists

Without a shared execution boundary, each caller tends to implement command safety differently. That creates inconsistent behavior, weak auditability, and security gaps.

This project centralizes execution policy and platform capability handling.

## Key Guarantees

- Explicit isolation levels (`none`, `best_effort`, `strict`).
- Fail-closed denial when required isolation is unavailable.
- Workspace boundary enforcement for `cwd` and `workspace_root`.
- Policy control for mutating commands and ambient script launchers via allowlisted tools.
- Structured event outputs for audit and debugging.

## Scope

This project governs command execution and isolation checks.

It does **not** replace dedicated filesystem operation controls. For mutating file operations, use `omne-fs` in combination with this gateway.

## Read This First

1. [Quickstart](getting-started/quickstart.md)
2. [Policy Model](guides/policy-model.md)
3. [Isolation Semantics](guides/isolation-semantics.md)
4. [API Reference](reference/api-reference.md)
