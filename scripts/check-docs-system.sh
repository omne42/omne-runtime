#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_file() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    echo "missing required file: ${path#$root/}" >&2
    exit 1
  fi
}

require_contains() {
  local path="$1"
  local needle="$2"
  if ! grep -Fq "$needle" "$path"; then
    echo "missing required text in ${path#$root/}: $needle" >&2
    exit 1
  fi
}

require_agents_length() {
  local path="$1"
  local max_lines="$2"
  local line_count
  line_count="$(wc -l < "$path")"
  if (( line_count > max_lines )); then
    echo "AGENTS too long (${line_count} > ${max_lines}): ${path#$root/}" >&2
    exit 1
  fi
}

require_no_conflict_markers() {
  local path="$1"
  if grep -nE '^(<<<<<<< .+|=======|>>>>>>> .+)$' "$path" >/dev/null; then
    echo "git conflict marker detected in ${path#$root/}" >&2
    exit 1
  fi
}

require_nested_member_documented() {
  local member="$1"
  if ! grep -Fq "$member" \
    "$root/README.md" \
    "$root/docs/docs-system-map.md" \
    "$root/docs/source-layout.md" \
    "$root/docs/workspace-crate-boundaries.md" \
    "$root/docs/quality-and-doc-maintenance.md"; then
    echo "nested workspace member is not documented: $member" >&2
    exit 1
  fi
}

check_docs_conflict_markers() {
  local paths_file
  paths_file="$(mktemp)"

  find "$root" \
    \( -path "$root/.git" -o -path "$root/target" -o -path "$root/site" \) -prune -o \
    -type f \
    \( \
      -path "$root/docs/*" -o \
      -path "$root/crates/*/docs/*" -o \
      -path "$root/README.md" -o \
      -path "$root/AGENTS.md" -o \
      -path "$root/crates/*/README.md" -o \
      -path "$root/crates/*/AGENTS.md" \
    \) \
    -print0 >"$paths_file"

  while IFS= read -r -d '' path; do
    require_no_conflict_markers "$path"
  done <"$paths_file"
  rm -f "$paths_file"
}

check_crate_docs() {
  local crate_dir="$1"
  require_file "$crate_dir/README.md"
  require_file "$crate_dir/AGENTS.md"
  require_file "$crate_dir/docs/docs-system-map.md"
  require_file "$crate_dir/docs/architecture/source-layout.md"
  require_file "$crate_dir/docs/architecture/system-boundaries.md"
  require_contains "$crate_dir/README.md" "docs/docs-system-map.md"
  require_agents_length "$crate_dir/AGENTS.md" 160
}

workspace_member_list() {
  cargo metadata --manifest-path "$root/Cargo.toml" --format-version 1 --no-deps | \
    python3 -c '
import json
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
metadata = json.load(sys.stdin)
workspace_members = set(metadata["workspace_members"])
for package in metadata["packages"]:
    if package["id"] not in workspace_members:
        continue
    manifest_path = Path(package["manifest_path"]).resolve()
    print(manifest_path.parent.relative_to(root))
' "$root"
}

workspace_boundary_dir() {
  local member="$1"
  local first second _
  IFS='/' read -r first second _ <<<"$member"
  if [[ "$first" == "crates" && -n "$second" ]]; then
    printf '%s\n' "$root/$first/$second"
  else
    printf '%s\n' "$root/$member"
  fi
}

check_workspace_member_docs() {
  local member="$1"
  local member_dir="$root/$member"
  local boundary_dir

  if [[ ! -d "$member_dir" ]]; then
    echo "missing workspace member directory: $member" >&2
    exit 1
  fi

  boundary_dir="$(workspace_boundary_dir "$member")"
  check_crate_docs "$boundary_dir"

  if [[ "$member_dir" != "$boundary_dir" ]]; then
    require_nested_member_documented "$member"
  fi
}

require_file "$root/README.md"
require_file "$root/AGENTS.md"
require_file "$root/docs/README.md"
require_file "$root/docs/docs-system-map.md"
require_file "$root/docs/source-layout.md"
require_file "$root/docs/workspace-crate-boundaries.md"
require_file "$root/docs/quality-and-doc-maintenance.md"
require_contains "$root/README.md" "docs/README.md"
require_contains "$root/README.md" "docs/docs-system-map.md"
require_contains "$root/AGENTS.md" "docs/README.md"
require_agents_length "$root/AGENTS.md" 160
check_docs_conflict_markers

members_file="$(mktemp)"
workspace_member_list >"$members_file"
while IFS= read -r member; do
  [[ -n "$member" ]] || continue
  check_workspace_member_docs "$member"
done <"$members_file"
rm -f "$members_file"

for crate_dir in "$root"/crates/*; do
  [[ -d "$crate_dir" ]] || continue
  if [[ -f "$crate_dir/Cargo.toml" ]]; then
    continue
  fi
  check_crate_docs "$crate_dir"
done

echo "docs system check passed"
