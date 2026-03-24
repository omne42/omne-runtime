#!/usr/bin/env bash
set -euo pipefail

if ! command -v git >/dev/null 2>&1; then
  echo "setup-githooks: git is not installed or not in PATH" >&2
  exit 1
fi

tmp_err="$(mktemp)"
trap 'rm -f "$tmp_err"' EXIT

if ! repo_root="$(git rev-parse --show-toplevel 2>"$tmp_err")"; then
  err="$(cat "$tmp_err" || true)"
  if [[ -n "$err" ]]; then
    echo "setup-githooks: failed to locate git repository: $err" >&2
  else
    echo "setup-githooks: not a git repository; run: git init" >&2
  fi
  exit 1
fi

for hook in pre-commit commit-msg; do
  hook_path="$repo_root/githooks/$hook"
  if [[ ! -f "$hook_path" ]]; then
    echo "setup-githooks: missing hook: $hook_path" >&2
    exit 1
  fi
  chmod +x "$hook_path"
done

current_hooks_path="$(git -C "$repo_root" config --local --get core.hooksPath || true)"
if [[ -n "$current_hooks_path" && "$current_hooks_path" != "githooks" ]]; then
  cat >&2 <<EOF
setup-githooks: existing core.hooksPath is '$current_hooks_path', refusing to overwrite.
If you intend to switch, run:
  git -C "$repo_root" config --local core.hooksPath githooks
EOF
  exit 1
fi

git -C "$repo_root" config --local core.hooksPath githooks

echo "Configured git hooks: core.hooksPath=githooks"
echo "Hooks enabled: pre-commit, commit-msg"
