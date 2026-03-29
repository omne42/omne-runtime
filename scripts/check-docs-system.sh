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

check_docs_conflict_markers() {
  while IFS= read -r -d '' path; do
    require_no_conflict_markers "$path"
  done < <(
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
      -print0
  )
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

for crate_dir in "$root"/crates/*; do
  [[ -d "$crate_dir" ]] || continue
  check_crate_docs "$crate_dir"
done

echo "docs system check passed"
