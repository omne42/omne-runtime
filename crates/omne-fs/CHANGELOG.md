# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- `list_dir` now spends `limits.max_walk_entries` budget while enumerating direct children, so oversized directory scans fail closed as `truncated=true` instead of walking arbitrarily many entries before applying the existing result/response caps.
- `create_parents` no longer relies on an internal `expect(...)` when parent-identity verification
  context is unexpectedly missing; the path now fails closed with an explicit `InvalidPath`
  error, and regression coverage locks that non-panicking behavior in place.
- `read` no longer hard-codes `.env*` refusal outside policy; direct reads now follow `secrets.deny_globs` as the single source of truth, with regression coverage for both allowed and denied `.env.local` paths.
- CLI text input loading now opens files through the same ambient-root no-follow path walk used by
  `policy_io`, so ancestor symlink paths are rejected fail-closed instead of only checking the
  final path component.
- Removed the stale empty `git-permissions` Cargo feature declaration now that the fallback code is
  gone, so crate metadata no longer advertises a non-existent PATH-sensitive authorization path.
- stop routing `edit` / `delete` through the undocumented `git-permissions` runtime fallback, so
  `omne-fs` no longer changes write authorization semantics through an optional Cargo feature or
  carries VCS subprocess policy inside the generic filesystem boundary
- Added regression coverage pinning the `git-permissions` fallback to explicit trusted `git`
  program paths and sanitized subprocess environment, so future refactors cannot regress back to
  ambient `PATH` lookup or inherited `GIT_*` hook/process state.
- `policy_io` now reports leaf symlink/reparse policy paths with a stable fail-closed diagnostic and inherits non-blocking regular-file opens from `omne-fs-primitives`, so FIFO/special-file policy inputs reject immediately instead of hanging the loader.
- `policy_io` now opens policy files through `omne-fs-primitives` capability roots plus
  no-follow regular-file handles, so parent-directory symlink/reparse ancestors can no longer
  redirect policy loads outside the caller's intended path.
- Added regression coverage proving `git-permissions` fallback ignores poisoned ambient `PATH`,
  `GIT_DIR`, and `GIT_WORK_TREE`, so trusted `git` resolution stays detached from caller-
  controlled lookup state.
- `Context::glob_paths` and `Context::grep` now stay compiled when the `glob` or `grep`
  cargo feature is disabled, so the public API once again matches the documented contract:
  callers get deterministic `Error::NotPermitted` instead of an external compile failure.
- `git-permissions` now reports the correct fail-closed requirement when trusted `git`
  resolution fails: the fallback depends on standard host locations, not ambient `PATH`.
- `git-permissions` now silences trusted `git` stderr/stdout on status-only probes, so failed
  fallback checks no longer leak raw git diagnostics back to the parent process output.
- `git-permissions` now clears inherited `GIT_*` state and disables external diff helpers before
  invoking `git`, so fallback write authorization no longer trusts caller-controlled git-side
  process hooks.
- `delete` now matches `copy_file` / `move_path` fail-closed semantics when parent or target
  identity cannot be revalidated before removal, instead of degrading unverifiable paths to
  best-effort success.
- Added regression coverage for delete's fail-closed identity checks so unverifiable parent or
  target revalidation cannot silently continue removal again.
- Windows regression coverage now accepts the earlier fail-closed delete identity branch when a
  recursive-delete race is caught before the secret-path recheck fires, keeping the safety
  contract platform-stable while avoiding a test-only false negative.
- `git-permissions` now routes its `git` subprocesses through `omne-process-primitives` instead of
  open-coding `Command::new("git")` inside `omne-fs`, and the shared `scripts/gate.sh` now
  explicitly checks/clippies/tests that feature path.
- `copy_file` / `move_path` / `create_parents` now fail closed when destination-parent identity
  cannot be revalidated, instead of treating Windows/exotic-filesystem `Unverifiable` results as
  success or falling back to canonical-path-only rechecks.
- `move_path` now re-verifies the source object with a stable handle when available and fails
  closed if the source identity cannot be revalidated before rename, closing the remaining
  Windows `Unverifiable` fallback that could otherwise move a replaced path.
- Documented and regression-tested the fail-closed `create_parents` parent-directory identity
  verification path on Windows so missing-handle/unverifiable cases cannot silently degrade to
  success.
- Renamed the public crate family from `omne-systems-*` to `omne-*` (`omne-fs`, `omne-fs-cli`,
  `omne-fs-primitives`, `omne-process-primitives`) so crate names no longer repeat the workspace
  prefix and instead expose the capability boundary directly.
- Added the sibling low-level crate `omne-process-primitives` to the umbrella workspace, moving generic process-tree spawn/cleanup primitives out of `omne_foundation::secret` without broadening `omne-fs` beyond filesystem policy/tooling; boundary docs now explicitly separate filesystem primitives, process primitives, policy/tooling, and domain adapters.
- `omne-fs-primitives` now also owns the shared bounded-read primitive used by `omne_foundation` text-resource and dynamic-catalog loaders, so duplicated `take(limit+1)+read_to_end` logic no longer exists in both downstream adapters; the boundary docs were also tightened to state explicitly that cross-platform runtime/process cleanup code does not belong in the fs crates just because it uses `cfg(...)`.
- Introduced the shared low-level crate `omne-fs-primitives` inside the `omne-fs` workspace; the no-follow open/error-classification code previously owned by `omne-fs::platform_open` now lives there, `ops::io` delegates its regular-file no-follow open path to that crate, and downstream consumers can depend on the same primitives directly instead of carrying duplicate low-level filesystem implementations under a second crate name.
- `copy_file`/`move_path` now share a transfer-path resolution helper that carries canonical parent/leaf state instead of forcing callers to re-derive it; `write`/`edit`/`patch`/`copy_file` now converge on a common staged temp-file commit path in `ops::io`; and directory identity snapshots used by `copy_file`/`move_path`/`list_dir`/`resolve::dir_ops`/`mkdir`/`delete` are now represented by a dedicated `ops::io` type instead of ad-hoc raw metadata plumbing, reducing duplicated TOCTOU-sensitive setup/verification logic without changing external behavior.
- `copy_file`/`move_path`/`delete` now also share a generic metadata-backed path-identity helper in `ops::io` for same-object checks and TOCTOU revalidation, centralizing file/symlink/dir target identity handling instead of open-coding `metadata_same_file` logic per operation.
- Windows identity checks now use stable `same-file` handle-based verification in critical TOCTOU-sensitive read/write/stat paths; non-reliable metadata-identity comparisons on Windows were removed from auxiliary paths, `Error::policy_rule()` no longer over-attributes all `NotPermitted` errors to `permissions/root.mode`, and the `secrets-secondary` workflow summary generation no longer depends on runtime `apt-get jq`.
- release: bump crate versions (`omne-fs`, `omne-fs-cli`) to `0.1.0`.
- `grep` now bounds initial line-buffer and reader-buffer preallocation by `limits.max_read_bytes + 1` (in addition to existing clamp limits), reducing per-request memory overhead under small read-budget policies without changing scan/truncation behavior; added unit coverage for the new capacity bounds.
- `delete --recursive` deny pre-scan now returns the denied child path without cloning the scratch `PathBuf` on the error branch, removing one unnecessary allocation on the deny-hit path.
- CLI redaction root setup now skips adding a canonical root when it is already lexically equivalent to the declared root (for example `/root/path/.` vs `/root/path`), removing redundant per-error prefix checks without changing redaction semantics; added regression coverage for lexical-equivalence deduplication.
- `read` line-range scanning now hoists `start_line - 1` out of the hot loop, removing repeated per-line `saturating_sub` work while preserving range and UTF-8 validation behavior.
- CLI best-effort path redaction now selects the most specific matching root using a borrow-first prefix check and performs `strip_prefix` only once for the winning root, removing repeated per-root `PathBuf` allocations in error-render hot paths while preserving root-priority semantics (including tie stability).
- `grep` plain-query hot loop now short-circuits non-matching lines before trailing line-ending trimming, removing two per-line buffer mutations on the common no-match path without changing UTF-8/non-UTF8 skip semantics.
- `read` line-range scanning now uses an explicit checked line-index increment (`checked_add`) and returns a deterministic `InvalidPath` overflow error instead of relying on arithmetic overflow behavior in extreme line-count edge cases; added unit coverage for the overflow guard.
- `list_dir` response-byte budgeting now includes the serialized decimal digit count of each entry’s `size_bytes` field (with a 1-digit minimum precheck), fixing systematic under-accounting that could delay expected `response_budget` truncation on large file-size listings; added regression coverage for size-digit accounting.
- `path_validation` leaf checks now skip an unnecessary release-build lexical-normalization allocation used only for debug assertions, and now reject non-normalized `./...` requested paths as explicit internal contract violations.
- `glob`/`grep` response-byte budgeting now counts path bytes using lossy UTF-8 display lengths (instead of raw OS bytes), fixing under-accounting for non-UTF8 paths that could delay expected `response_budget` truncation; added Unix regression coverage for both ops.
- Redaction regex replace-buffer preallocation now uses correct `String::reserve` semantics for reused buffers, fixing a capacity-growth bug that could miss intended preallocation and trigger extra reallocations on larger follow-up inputs; added regression coverage for reused-buffer capacity growth.
- `edit`/`patch` shared atomic-replace write path now performs a single post-write/post-metadata `sync_all` before rename (instead of two syncs), removing one redundant flush on overwrite-heavy workloads without changing durability/error semantics.
- CLI path redaction now precomputes normalized root-depth metadata and uses it for best-prefix selection, fixing a bug where roots containing lexical segments like `..` could win as “more specific” and produce less precise redacted relative paths; this also removes repeated per-error path-component counting in hot error-render paths.
- `list_dir` now revalidates directory identity once more after retained-entry materialization, reducing a late TOCTOU window where post-scan metadata could be read from a replaced directory path before response return.
- `grep` line-text clipping now uses a fast owned-prefix helper that skips UTF-8 boundary backtracking for already-in-budget text, trimming per-match hot-path overhead without changing truncation semantics.
- `grep` UTF-8 line-text truncation now uses `str::floor_char_boundary` via a shared helper in the hot match path, removing repeated per-match boundary backtracking loops while preserving truncation semantics.
- CLI error rendering now avoids several redundant `String` clones when the same redacted path/root id is used for both JSON details and public message output; `details_map` also preallocates map capacity for the mandatory `kind` field.
- `grep` glob-filter lazy-open path now reuses a single absolute-path scratch buffer instead of allocating `root_path.join(relative_path)` per candidate file, reducing hot-path `PathBuf` allocation churn on large scans without changing match/truncation semantics.
- `read` line-range scan now validates UTF-8 while streaming skipped prefix lines (before `start_line`), fixing a bug where invalid UTF-8 in discarded lines could be missed; this also enables earlier fail-fast on malformed inputs without retaining skipped-line buffers.
- `list_dir` response-byte budgeting now accounts path/name bytes using lossy display UTF-8 lengths (instead of raw OS bytes), fixing under-accounting for non-UTF8 directory entries that could delay expected `response_budget` truncation; added Unix regression coverage for non-UTF8 path/name accounting.
- `copy_file` destination leaf handling now keeps the destination file name as `OsString` through path preparation and only materializes `Path` views at join sites, removing one avoidable `PathBuf` allocation on the copy hot path.
- `resolve::dir_ops::ensure_dir_under_root` now keeps the accumulating relative path in-place (`push`) and validates path segments as borrowed `OsStr`, removing one per-segment `PathBuf` allocation/clone in `create_parents` directory resolution while preserving boundary and identity checks.
- `glob`/`grep` stable-sort now keeps an incremental `matches_sorted` hint while collecting results and only runs the final sort when that hint flips false, removing an extra full-result sortedness pre-scan on large outputs without changing truncation/order semantics.
- Fixed a `grep` streamed UTF-8 validation edge case where pending multi-byte state could stop processing the remainder of the same chunk, causing valid UTF-8 lines to be misclassified as non-UTF8 and skipped.
- `grep` plain-query chunk matching now short-circuits impossible substring checks (`haystack < needle`) and skips cross-boundary `memmem` probes when the combined tail/prefix length cannot satisfy the query length, trimming hot-loop overhead without changing match semantics.
- `path_utils::normalize_glob_pattern_for_matching` now keeps borrow-first semantics when trimming leading `"./"` segments from already-borrowed patterns, removing an avoidable `String` allocation on common `glob`/`grep` request normalization paths.
- Removed three redundant hot-path clones in `edit`/`list_dir`/`write` (`PathBuf` ownership now moved directly on early-return branches and scratch-path init), trimming avoidable allocation/copy work without changing behavior.
- CLI `glob`/`grep` scan-limit JSON 输出改为内建字符串映射（`entries/files/time/results/response_bytes`）并移除不必要的 fallible 序列化分支；`list_dir`/`glob`/`grep` 响应组装函数同步改为无错误返回，减少热路径分支与无效错误传播风险。
- `list_dir` `max_entries=0` 的 deny-glob count-only 扫描路径现在在命中首个非 deny 可见项后直接短路，不再额外探测 `DirEntry::file_type()`；减少潜在 metadata syscall 开销，并保持 `truncated` 判定语义不变（该路径的 `skipped_io_errors` 仅统计 `read_dir` 迭代错误）。
- `grep` stable-sort 的“已排序预检查”现在对相邻项只做一次 `path.cmp`，避免重复路径比较，降低大结果集下的排序前扫描开销。
- `list_dir` retained-entry materialization now reuses one precomputed per-candidate response-byte base (path+name) and consumes a precomputed `relative_is_root` flag during path emission, trimming repeated hot-loop byte accounting and root-path checks without changing truncation/order semantics.
- `list_dir` `max_entries=0` now uses a no-deny fast path that short-circuits on the first visible directory entry without probing `DirEntry::file_type()`, reducing syscall overhead on large directories while keeping truncation semantics.
- `write` overwrite staging now uses a single post-write/post-permission `sync_all` before atomic rename (instead of two syncs), reducing overwrite-path flush overhead without changing durability semantics; added a Unix regression test to lock permission-preservation behavior on overwrite.
- `resolve` root-path derivation now reads the declared root path from `Context` runtime state (same O(1) root map as canonical roots) instead of re-scanning `policy.roots` per request, reducing repeated linear lookups and removing split-source root metadata drift risk.
- `resolve` symlink escape classification now derives relative symlink parents from `current.parent()` instead of cloning and mutating a full `PathBuf` per symlink hop, trimming allocation churn on deep symlinked paths.
- Added a Unix regression test for absolute paths under symlink-declared roots to lock requested-path derivation behavior (`requested_path == "file.txt"` under alias roots).
- `list_dir` now routes `max_entries=0` through a dedicated count-only scan path and keeps the top-k materialization loop branch-free, reducing hot-loop branching/allocation overhead while preserving truncation and `skipped_io_errors` semantics.
- Traversal walk-root resolution now reuses the already-resolved caller root path instead of doing a second root-map lookup, trimming per-request setup overhead without changing boundary checks.
- `resolve` not-found escape classification now reuses mutable path buffers (`push`/`pop`) instead of rebuilding joined paths at every segment, removing quadratic allocation/copy behavior on deep paths while preserving outside-root symlink escape checks.
- `edit` replacement newline normalization now returns borrow-first `Cow<str>` and only allocates when line-ending conversion or trailing-newline append is required, reducing copy/allocation overhead for large unchanged replacement payloads.
- `list_dir` `max_entries=0` count-only path now skips deny-path name extraction when `secrets.deny_globs` is empty, avoiding unnecessary per-entry `OsString` allocations while preserving existing I/O error classification.
- `list_dir` internal candidate equality now compares `file_name` directly, removing redundant display-name normalization work in heap bookkeeping.
- Windows traversal filtering now reuses a single case-insensitive `strip_prefix` fallback result per entry (instead of recomputing it), trimming duplicate normalization on filtered walks.
- `glob` pattern normalization now returns borrow-first `Cow<str>` and traversal/secrets glob compilation paths consume borrowed normalized patterns when possible, avoiding unnecessary per-request `String` allocations on already-normalized inputs.
- `traversal.skip_globs` total-byte accounting now uses checked addition and returns an explicit overflow validation error instead of saturating arithmetic, tightening policy-shape validation for extreme inputs.
- `list_dir` now allocates the deny-path scratch buffer only when `secrets.deny_globs` is configured for a non-root target path, removing one unnecessary `PathBuf` clone on the common permissive-policy path.
- `glob`/`grep` safe-prefix directory-probe prechecks now use `symlink_metadata` (no-follow) so symlinked directory prefixes are not misclassified as traversable directories during skip/deny short-circuits.
- `grep` with `glob` filtering now treats lazily-opened non-regular paths (for example symlinked directories) as skippable I/O entries instead of failing the whole operation with `InvalidPath`.
- `grep` line scanning removed an unnecessary per-line query-window shrink check; query-window capacity is already bounded per request, reducing tiny hot-loop overhead on large scans.
- `glob` stable-sort post-processing now skips the final sort when matches are already lexicographically ordered, removing redundant `O(n log n)` work on preordered traversal results.
- `list_dir` top-k candidate ordering now compares retained file names directly (`OsString`) for tie-breaks, avoiding repeated `Path` wrapper construction in heap comparisons.
- CLI `list_dir`/`grep` JSON 输出组装改为显式预分配 `Vec/Map`（替代逐条 `serde_json::json!` 构造），降低大结果集下的中间分配与序列化开销。
- CLI 路径脱敏初始化现在预分配 root 容器，并在 `canonicalize(path) == path` 时跳过重复 canonical root 记录，减少错误渲染时的前缀匹配开销。
- `create_parents` 目录解析在已有非-symlink 目录组件上不再逐层 `canonicalize`，改为轻量 root 边界校验，降低深路径创建流程的 syscall 开销，同时保留 symlink 分支的严格校验语义。
- Traversal fast path now avoids materializing absolute entry paths when `open_mode=None`; `grep` now derives the absolute path lazily only when a glob-filtered candidate must be opened, reducing per-entry `PathBuf` allocation churn in large scans.
- `glob`/`grep` now report response-byte budget truncation as `scan_limit_reason=response_bytes` (instead of `results`), improving limit observability when byte budgets trigger early stops.
- `list_dir` now applies a conservative runtime cap to retained top-k entries, reducing worst-case heap growth under extreme `max_entries` policy/request combinations.
- `list_dir` runtime retained-candidate cap was tightened from `250_000` to `100_000`, reducing peak memory pressure on extreme large-directory scans while preserving top-k ordering semantics.
- Added a regression test that locks `list_dir` runtime-cap (`100_000`) behavior to `truncated=true` semantics when matched entries exceed the capped retention limit.
- `perf_ops` now includes dedicated redaction-path benchmarks (`read/full_large_file_with_redaction_regex` and `grep/plain_query_stable_sort_with_redaction_regex`), so `read`/`grep` regressions can be compared explicitly across no-redaction vs regex-redaction paths.
- Added Linux/Android regression coverage for the `src has no xattrs` branch in `preserve_unix_security_metadata`, ensuring destination xattrs are pruned when xattr copy is enabled.
- `perf-safety` ASan workflow now runs targeted Unix xattr metadata regression tests explicitly, so `preserve_unix_security_metadata` coverage remains pinned in sanitizer runs.
- Linux/Android Unix-metadata coverage now includes executable xattr sync regression tests for copy/prune and copy-disabled paths, improving dynamic safety verification of `preserve_unix_security_metadata`.
- `read` now short-circuits redaction when `secrets.redact_regexes` is empty, avoiding unnecessary redaction-state dispatch on the common no-regex path.
- `list_dir` now precomputes root-path flags and response path-prefix byte counts once per call, reducing repeated per-entry/path-candidate checks in large directory listings.
- `glob`/`grep` safe-prefix setup now skips deny/skip prechecks (and related probe metadata checks) when no traversal path filters are configured, reducing per-call overhead in common permissive policies.
- `list_dir` now skips per-entry deny-glob matcher calls when `secrets.deny_globs` is empty, reducing hot-loop overhead on common permissive policies.
- `glob`/`grep` stable-order post-sort now uses `sort_unstable`/`sort_unstable_by`, preserving key order semantics while reducing sort overhead on large match sets.
- `grep` stable-sort post-processing now skips the final sort pass when matches are already in `path+line` order, avoiding redundant `O(n log n)` work on preordered result sets.
- `grep` hot loop now only runs line-buffer shrink checks on capped-line paths (instead of every no-match line), reducing per-line overhead on large plain-text scans while preserving oversized-buffer memory recovery.
- `list_dir` `max_entries=0` count-only mode now restores classification of `DirEntry::file_type()` failures as skipped I/O errors instead of visible entries, preserving truncation/skipped-error diagnostics parity with non-zero entry mode.
- `glob`/`grep` stable-sort post-processing now sorts directly when `traversal.stable_sort=true` (removing the separate sortedness pre-scan), and aligned test-helper `cfg` gates with feature-gated test modules so `--no-default-features` clippy/gate runs stay green.
- `grep` now validates UTF-8 across the full streamed line (including bytes beyond retained capped prefixes) on both no-match and matched-line paths, fixing false negatives where invalid UTF-8 after a long capped ASCII prefix could be incorrectly treated as searchable text.
- `read` line-range path now uses a bounded `BufReader` preallocation (8 KiB to 64 KiB) based on `max_read_bytes` instead of always using the default 8 KiB, reducing syscall churn on large-file line scans.
- `copy_file`/`move_path` now skip one redundant destination secret-glob check after lexical resolution has already enforced the same deny rule, removing duplicate matcher work and one unnecessary `PathBuf` clone on write-path setup.
- Windows `glob`/`grep` path-normalization matching now clears thread-local wide-char scratch buffers before shrinking, avoiding one-call memory retention after very long path inputs.
- `list_dir` retained-entry materialization now reuses one absolute-path scratch buffer instead of allocating `dir.join(...)` per entry, reducing short-lived `PathBuf` churn on large listings.
- Added a `criterion` benchmark target (`perf_ops`) covering representative `read`/`list_dir`/`glob`/`grep` workloads, so performance regressions can be tracked with repeatable metrics.
- Expanded `perf_ops` benchmarks to compare `glob`/`grep` with `traversal.stable_sort=true/false`, so stable-order overhead can be measured directly before policy tuning.
- `mkdir` Windows parent-identity checks now treat missing file-ID fields as an explicit “identity unavailable” state (instead of “changed”), avoiding false parent-tamper rejections on filesystems that do not expose stable IDs while keeping cleanup safety checks fail-closed.
- `glob`/`grep` response post-sort now honors `traversal.stable_sort`: when disabled, large result sets skip the final O(n log n) ordering pass to reduce CPU cost.
- `list_dir` `max_entries=0` count-only mode now skips per-entry `file_type` probing and exits on the first visible non-denied entry, reducing syscall overhead on large directories.
- `list_dir` deny checks and traversal directory-probe checks now reuse mutable path buffers in hot loops, reducing per-entry temporary `PathBuf` allocations on large directory scans.
- Added `limits.preserve_unix_xattrs` (default `true`) to make Linux/Android overwrite xattr-copy behavior configurable for performance-sensitive environments while keeping secure/default metadata fidelity.
- Clarified `glob`/`grep`/`list_dir` response-budget accounting as estimated payload-byte guardrails (not strict process-memory caps), and aligned internal naming accordingly.
- `grep` plain-query streaming matcher now checks chunk-local hits first and limits cross-chunk checks to a bounded tail/prefix window, reducing per-chunk memory movement on long no-match lines.
- Redaction regex-chain state tracking now uses a typed internal enum (instead of `Option<usize>`), removing an unreachable branch and making buffer-state transitions compile-time checked.
- `list_dir` entry kind storage now uses an enum-backed serialized type string instead of per-entry heap `String` allocation, reducing allocation overhead on large directory listings without changing JSON output.
- `copy_file` now preserves same-path/same-file no-op semantics before enforcing `max_write_bytes`, avoiding false `file_too_large` errors for no-op copies.
- `move_path` and `delete` parent-path revalidation now uses boundary-semantic path equality (case-insensitive on Windows), avoiding false TOCTOU revalidation failures from case-only path differences.
- `delete --recursive` deny pre-scan now reuses a per-directory relative-path buffer for child checks and borrows the empty-suffix relative path, reducing per-entry `PathBuf` allocations in large tree scans.
- `delete --recursive` deny-glob pre-scan now reuses `SecretRedactor`-precompiled literal/prefix scan metadata instead of re-normalizing and re-parsing patterns per call, reducing repeated CPU/allocation overhead on recursive delete checks.
- Traversal policy now supports `traversal.stable_sort` (default `true`): keep deterministic sorted walk order by default, with an opt-out for large-directory `glob`/`grep` performance tuning.
- `list_dir` response assembly now performs a minimum-size budget precheck before per-entry `symlink_metadata` reads, avoiding avoidable metadata syscalls once the response budget is already exhausted.
- `patch` working-set guardrail now uses a policy-derived cap (`max_read_bytes + max_patch_bytes + max_write_bytes`) clamped by the existing 512 MiB hard limit, reducing peak-memory allowance under tighter policies.
- Policy/CLI large-input reads now cap initial `Vec` preallocation for policy files and text input files (while keeping existing hard byte limits), reducing one-shot allocation spikes under large inputs.
- `list_dir` now drops one redundant pre-`read_dir` directory-identity recheck and keeps post-open + post-scan verification, reducing one `symlink_metadata` syscall per call without changing TOCTOU guard semantics.
- Policy validation now applies a hard cap to `list_dir` response budget (`limits.max_results * limits.max_line_bytes`), preventing extreme misconfiguration from permitting very large in-memory listing responses.
- `list_dir` response assembly now uses a bounded initial `Vec` capacity for retained entries (instead of preallocating to full candidate count), reducing peak allocation spikes under very large `max_entries` settings.
- `list_dir` now enforces a per-call response byte budget (`max_entries * limits.max_line_bytes`) during entry materialization and marks `truncated=true` when the budget is hit, reducing large-response memory spikes.
- Windows path normalization micro-optimization: avoid temporary `String` allocation when appending the root separator after a prefix in lexical path reconstruction.
- `grep` per-file streaming reader now uses a bounded preallocated `BufReader` capacity (up to 64KiB) instead of the default 8KiB buffer, reducing syscall overhead on large-file scans.
- CLI JSON path-output hardening: `list-dir`/`glob`/`grep` now emit lossy UTF-8 path strings for non-UTF8 filesystem paths instead of failing response serialization with `path contains invalid UTF-8 characters`.
- `list_dir` truncation correctness: responses now set `truncated=true` when directory enumeration loses entries due to I/O errors (including `max_entries=0` count-only mode), so partial results are never reported as complete.
- `delete --recursive` deny pre-scan now enforces `limits.max_walk_entries` and `limits.max_walk_ms`, preventing unbounded pre-delete subtree scans when secret-glob checks require descendant traversal.
- Unix xattr sync micro-optimization: pre-size the source-name membership set during metadata copy, reducing hash table growth churn on files with many extended attributes.
- Unix xattr sync now skips building the source-name membership set when the destination has no xattrs, trimming avoidable hash-allocation work on the common fresh-temp-file path.
- Unix xattr sync now skips per-attribute destination-value probes when the destination starts with no xattrs, removing one extra `fgetxattr` syscall per source attribute on fresh temp files.
- `delete --recursive` deny-glob pre-scan now treats `!` as a literal unless it appears inside a character class (`[...]`), avoiding unnecessary subtree pre-scans for literal-bang paths like `!private/token.txt`.
- `delete --recursive` deny-glob pre-scan now uses boundary helpers with Windows case-insensitive semantics for literal/prefix overlap checks, preventing case-variant patterns from skipping required descendant scans on Windows.
- `list_dir` top-k candidate retention now keeps UTF-8 display names lazy (store `OsString` + on-demand lossy cache) instead of eagerly duplicating `String` names, reducing retained memory for large directory listings.
- `delete --recursive` deny pre-scan now stores target-relative suffixes in its traversal stack (instead of repeating full root-relative prefixes), reducing transient memory footprint on deep/wide directory trees.
- `delete --recursive` deny pre-scan stack now stores only target-relative suffixes and derives absolute paths on demand, removing an extra per-node `PathBuf` from queued traversal state in wide directory trees.
- `delete --recursive` deny pre-scan now keeps target-relative suffix joins borrow-first (`Cow<Path>`), avoiding per-entry relative `PathBuf` clones when scanning from the root target (`.`).
- Traversal entry resolution now keeps walk-relative paths borrow-first (`Cow<Path>`) and only materializes `PathBuf` at result emission, reducing per-entry temporary allocations in large scans.
- `delete --recursive` deny pre-scan now computes child-relative deny-check paths without always materializing a child-suffix `PathBuf`, reducing per-entry allocations for non-directory children.
- `list_dir` top-k candidate heap now stores file-name-only state and derives absolute/relative paths on demand during final materialization, reducing per-entry retained memory in large-directory scans.
- `edit` write path now applies line-range replacement in-place via `String::replace_range` instead of rebuilding a second full output string, reducing peak transient memory during large-file edits.
- `list_dir` candidate materialization now reuses cached lossy names by ownership move when available, avoiding an extra `String` clone per retained non-UTF8 entry.
- `patch` change detection now short-circuits on `len()` mismatch before full string equality, reducing unnecessary O(n) comparisons on common size-changing patches.
- `patch` now enforces a combined in-memory working-set guard (`original content + patch text + estimated patched output`) with a 512 MiB hard cap, failing early instead of risking extreme-memory patch applications.
- Unix metadata copy now short-circuits the xattr sync path when the source file has no xattrs: destination xattrs are removed directly without building source membership sets, reducing transient allocations in empty-source xattr cases.
- `list_dir` deny-path filtering now uses borrow-first relative paths for root (`.`) listings, avoiding per-entry temporary `PathBuf` allocations on the common root-directory path.
- `copy_file` temp commit hardening: keep a single temp-file handle through permission/sync/commit and reject commits when the temp path no longer points to that same file, closing a TOCTOU window in path-reopen staging.
- Windows `glob` path-normalization hot path now reuses a thread-local UTF-16 buffer in traversal matching (with retention cap), reducing per-entry temporary vector allocations when converting `\` to `/` without keeping unbounded peak capacity.
- Windows `create_parents` directory-identity checks now distinguish “identity changed” from “identity unavailable”, avoiding false “parent changed” failures on filesystems that do not expose file ID fields.
- Recursive delete deny-glob pre-scan now derives a stable literal prefix for glob patterns and skips full descendant scans when the target subtree is provably disjoint, reducing unnecessary pre-delete tree walks on large directories.
- Context root-overlap checks now return immediately for 0/1 roots (all platforms) and pre-size Windows non-disk root buckets, trimming avoidable setup work in small policies.
- Redaction marker fast path: `redact_text_cow` now returns a borrowed static marker on output-limit overflow instead of allocating a new `String`.
- Redaction no-op fast path: `redact_text_outcome` now returns immediately when no redaction regexes are configured, avoiding per-call loop overhead on common allow-list policies.
- Redaction empty-input fast path: `redact_text_outcome` now returns immediately for empty text even when regexes are configured, avoiding needless per-regex scans.
- Redaction chain short-circuit: when text becomes empty after a regex replacement, `redact_text_outcome` now stops scanning later regexes.
- Windows root-overlap validation now skips per-group overlap checks for single-item groups after drive partitioning, reducing unnecessary calls on mixed-drive root sets.
- Windows root-overlap partitioning now uses fixed disk-letter buckets (`A-Z`) instead of a map, reducing grouping overhead while preserving overlap-check semantics.
- Windows root-overlap validation now sorts roots case-insensitively within each drive/UNC group and checks adjacent pairs only, reducing per-group comparisons from O(n^2) to O(n log n) while preserving overlap detection.
- `list_dir` entry materialization now uses `OsString::into_string()` fast path for UTF-8 names and only falls back to lossy conversion for non-UTF8 names, trimming avoidable string conversion overhead on large directories.
- `list_dir` top-k maintenance now uses `BinaryHeap::peek_mut()` replacement when the heap is full, avoiding an extra `pop + push` pair on candidate upgrades.
- Canonical-path boundary checks in `copy_file`/`move_path`/`mkdir`/`write`/`delete`/`resolve` now use internal normalized-path fast helpers, reducing repeated lexical-normalization overhead on hot validation paths without changing boundary semantics.
- Traversal walk hot path now uses normalized prefix helpers for `walk_root`/entry relative derivation, reducing repeated lexical-normalization overhead during large directory walks.
- `glob` response-byte budgeting now supports a dedicated optional `limits.max_glob_bytes` override, decoupling glob truncation behavior from `limits.max_line_bytes` while preserving backward-compatible defaults.
- `list_dir` now defers type/size metadata probing to retained top-k candidates, reducing `symlink_metadata` call volume on large directories while preserving stable result ordering and security checks.
- Boundary-check allocation trim: `resolve_path_checked`/`derive_requested_path` now reuse borrowed normalized-path fast paths and avoid extra normalization allocations when inputs are already lexical-clean.
- `derive_requested_path` now returns the already-normalized stripped relative path directly, removing a redundant second lexical-normalization pass on successful resolves.
- `resolve/dir_ops` micro-optimization: avoid one first-segment `PathBuf` clone in `ensure_dir_under_root` traversal when building relative paths.
- `grep` query-window tuning: preallocate a bounded per-request plain-query window to reduce initial growth reallocations for long query strings.
- `glob`/`grep` root setup now reuses borrowed canonical-root references instead of cloning them into temporary `PathBuf`s per request.
- Traversal root setup trim: `resolve_walk_root_for_traversal` now reuses case-insensitive prefix helpers directly and removes an extra pair of per-call lexical-normalization `PathBuf` allocations.
- Traversal root fallback trim: when canonicalization reports `NotFound`, traversal now reuses the already-built requested walk root instead of rebuilding the same `PathBuf`.
- Traversal alias-check fast path: skip `symlink_metadata` probing when canonical and requested walk roots are already path-equal, avoiding an extra filesystem stat on the common non-alias path.
- Traversal relative-path extraction now uses `Path::strip_prefix` fast path first and only falls back to case-insensitive helpers on Windows edge cases, reducing per-entry boundary-check overhead in large walks.
- Traversal root fast path: when the effective walk root is `.`, traversal now returns the canonical root immediately instead of re-entering canonical path resolution, trimming common-case setup overhead for full-root scans.
- `copy_file` small-allocation trim: avoid eager parent-path `PathBuf` materialization and defer destination-requested-path cloning to the rare denied-path error branch.
- `copy_file` destination setup now moves prepared parent-directory ownership with `Option::take()` instead of cloning, removing one extra `PathBuf` allocation on the copy path.
- `move_path` directory-target validation now reuses borrow-first lexical normalization helpers (`normalized_for_boundary` + normalized prefix check), avoiding unconditional `PathBuf` normalization allocations on the common already-normalized path.
- Path-resolution allocation trim: `resolve_path_in_root_lexically` now returns borrowed canonical-root references (`&Path`) and `copy_file` path resolution now threads that borrow through intermediate state, removing extra per-request canonical-root `PathBuf` clones.
- `grep` response-size guardrail: result assembly now tracks per-match `(path + text)` byte cost and truncates deterministically at the existing response budget boundary to avoid deep-path response bloat.
- `grep` response-budget fast path: check per-match `(path + text)` byte budget before cloning match paths, avoiding wasted `PathBuf` clones when the next hit is dropped by truncation.
- `grep` per-file match loop now computes path byte length once per file and reuses it for all hits, trimming repeated path-byte recomputation in multi-match files.
- `grep` response-budget guardrail now applies a path-only precheck before per-hit text truncation/redaction, avoiding unnecessary string work when remaining budget is already insufficient.
- `grep` request-level constants (`is_regex`, `plain_query`, line-read options) are now computed once per call and reused across file scans, trimming repeated branch/setup work in hot loops.
- `grep` plain single-byte query fast path: line scanning now uses `memchr` directly for 1-byte plain queries and skips query-window maintenance, reducing per-line allocation churn on long-file scans.
- `delete` recursive deny precheck now skips descendant tree scanning when `secrets.deny_globs` are literal-only patterns that cannot match paths under the target subtree, avoiding a redundant directory walk on large deletes.
- Windows regression coverage: add `delete` identity helper tests that lock in "all identity fields must be present" semantics.
- Small allocation tuning: pre-size `Context` root runtime map and redaction regex vector during initialization to avoid avoidable growth reallocations.
- `ensure_dir_under_root` allocation trim: reuse borrowed canonical-root reference and avoid one extra `PathBuf` clone per directory resolution.
- Docs overhaul: rebuilt project documentation into a structured portal (`docs/index.md`) with dedicated guides for getting started, concepts, policy/operations/CLI/library references, security usage, deployment/ops, and FAQ.
- `grep` regex long-line fast skip: once a scanned line exceeds the regex line cap, line scanning now short-circuits immediately instead of draining the rest of that line before skipping the file.
- `grep` plain-query memory smoothing: shrink oversized reusable query-window buffers between lines so isolated long-line scans do not retain multi-megabyte capacity for the rest of the request.
- `copy_file` commit-path I/O trim: remove a redundant pre-commit temp-file `sync_all` and keep the single post-permissions sync before atomic replace, reducing large-copy latency without weakening durability semantics.
- `resolve_path_in_root_lexically` hot-path trim: defer normalization of the original requested path to the rare error branch, removing one avoidable allocation on successful resolves.
- Traversal I/O optimization: `walk_traversal_files` now supports per-operation open mode so `grep` reuses a single no-follow open per file and `glob` avoids unnecessary pre-open checks.
- `grep` glob-filter optimization: when `grep.glob` is set, traversal defers file open until after glob match filtering (avoids opening non-matching files).
- Traversal filter fast path: when both `secrets.deny_globs` and `traversal.skip_globs` are empty, directory walking now skips per-entry glob/path normalization checks and keeps the iterator on a cheaper straight-through path.
- Traversal root setup trim: `resolve_walk_root_for_traversal` now reuses one borrowed canonical-root lookup instead of repeating root map lookups in the same call.
- `list_dir` entry-path derivation now builds root-relative paths from `(relative_dir, file_name)` directly, removing per-entry `strip_prefix` work in large-directory scans.
- Result collection tuning: `glob`/`grep` now cap initial match-vector reservation and skip sorting when zero/one result to reduce avoidable CPU and allocation overhead.
- Large-line memory smoothing: `grep` and `read` line-range loops now trim oversized reusable line buffers after long-line reads to reduce post-spike retained capacity.
- Internal write path cleanup: `commit_write` now consumes `WriteCommitContext` so permission metadata is moved into temp-file commit without an extra `Permissions` clone.
- Redaction compilation cleanup: redact patterns now compile once into `Regex` values (remove duplicate `Regex` + `RegexSet` compilation of the same rules).
- Redaction hot-path allocation trim: per-regex replacement now delays `String` allocation until first match instead of allocating on no-match paths.
- Redaction regex-chain allocation trim: multi-regex replacement now reuses a two-buffer ping-pong strategy across passes instead of allocating a new `String` on every matching regex.
- Path-boundary fast path: add internal normalized-path helpers to avoid repeated lexical normalization in hot root-boundary checks.
- `grep` line scanning now treats bare `\r` as a line terminator (and still normalizes `\r\n`), fixing cross-line matching/line-number errors on CR-delimited files.
- Path-boundary helper fast path: avoid normalization allocation for already-clean paths (no `.`/`..` segments).
- Path-boundary empty/curdir fast path: `normalized_for_boundary` now returns borrowed `"."` for empty/curdir-only inputs and direct `"."`, avoiding tiny-path allocation/scan overhead.
- Path-boundary scan short-circuit: `normalized_for_boundary` now stops component scanning early once normalization is known and curdir-only is impossible.
- Policy docs/hardening note: add explicit TOCTOU warning comment at `resolve_path_checked` return site to emphasize lexical-only guarantees.
- IO read-path allocation trim: preallocate read buffer from known file size when bounded by `max_read_bytes`.
- `grep` match assembly: remove per-file intermediate match vector and append directly to output matches.
- `read` line-range scanning: use a dedicated scratch buffer for pre-range skipped lines to avoid growing output capacity on skipped long lines.
- `read` line-range allocation tuning: bound initial output capacity by `min(file_size, max_read_bytes)` before capping, reducing small-file over-allocation when policy limits are large.
- `glob`/`grep` hot paths: preallocate output match vectors to `limits.max_results`.
- `glob` response budget hardening: cap cumulative matched-path bytes using the existing policy budget (`limits.max_results * limits.max_line_bytes`) and stop with deterministic truncation when exceeded.
- `glob` response-budget accounting now uses `OsStr::as_encoded_bytes().len()` per match, avoiding per-hit lossy UTF-8 allocation in large/non-UTF8 path sets.
- `grep` hot loop: skip redaction regex processing entirely when no redact rules are configured.
- Cleanup: simplify `list_dir` filename extraction and remove avoidable `Metadata` clone in `resolve/dir_ops` create path.
- Context init cleanup: remove redundant runtime duplicate-`root.id` policy error path in `Context` construction and rely on `SandboxPolicy::validate_structural` as the single source of truth.
- `grep` internal allocation trim: per-file match assembly now moves one owned `relative_path` into output and only clones for additional matches in that same file.
- `grep` correctness fix: preserve the first match path when reusing per-file path allocations so multi-match files never emit empty `path` values.
- CLI input IO trim: reuse metadata from no-follow open and preallocate file-read buffers from known file size in `load_text_limited`.
- CLI stdin read-path allocation trim: preallocate a bounded initial buffer before `read_to_end` to reduce realloc churn on large piped inputs.
- Rename durability semantics: when path replacement succeeds but parent-directory sync fails on Unix, operations now return an explicit `committed_unsynced` error code instead of collapsing into a generic rename I/O failure.
- Redaction-limit correctness: `read` now fails with an explicit `redact` I/O-path error when redacted output exceeds the hard cap, and `grep` now marks `line_truncated=true` when redaction output limit is exceeded instead of silently reporting a non-truncated marker line.
- `grep` read-path memory trim: switch per-file scan from full-buffer reads to streaming `BufRead` line scanning while preserving too-large/non-UTF-8 skip semantics.
- `grep`/`list_dir` allocation tuning: preallocate per-file grep line buffers and list-directory candidate heap capacity to reduce repeated growth in hot paths.
- Policy safety guardrail: reject configurations where `limits.max_results * limits.max_line_bytes` exceeds a hard response-budget cap, reducing worst-case grep memory amplification from misconfigured limits.
- Context initialization optimization: on non-Windows platforms, canonical root-overlap checks now use sorted adjacent comparisons instead of quadratic pairwise scans.
- Context initialization optimization (Windows): canonical root-overlap checks now partition disk roots by drive letter before pairwise overlap checks, avoiding unnecessary cross-drive comparisons while preserving overlap semantics.
- `grep` long-line safety: line scanning now caps per-line buffering and drains oversized lines incrementally, preventing unbounded in-memory line growth on newline-free large files.
- Windows path-compare fast path: add zero-allocation ASCII case-insensitive comparison before UTF-16 buffer allocation + FFI fallback, reducing hot-path compare overhead on common ASCII paths.
- Windows identity revalidation correctness: `delete`/`move`/`copy_file` now treat missing filesystem identity fields as "cannot verify" (explicit error) instead of conflating them with "identity changed".
- Traversal/grep allocation trim: traversal now constructs directory `probe` paths only for directory entries, and `grep` now reuses a single per-request line buffer across files.
- `grep` response build fast path: skip final result sorting when matches are already in `(path, line)` order.
- `glob` traversal-root setup: avoid cloning canonical root path when no safe traversal prefix is derived.
- `grep` traversal-root setup: avoid cloning canonical root path when no safe traversal prefix is derived.
- `grep` input hardening: reject oversized queries before plain/regex execution with a fixed byte limit to reduce DoS surface from unbounded user patterns.
- `grep` long-line correctness: plain queries now match over full streamed line content (not only buffered prefix), and regex mode expands line buffering to `max_read_bytes` so suffix matches on long lines are not silently missed.
- `grep` regex safety guardrail: cap per-line regex buffering to 8 MiB and fail closed (`skipped_too_large_files`) when a single line exceeds that bound, preventing high-memory/OOM spikes from pathological single-line inputs.
- `grep` plain-query hot path: switch byte-slice substring detection to `memchr::memmem::find` and shrink oversized reusable line buffers on early file-skip branches.
- `list_dir` allocation guardrail: cap `BinaryHeap` initial reservation to a bounded size instead of preallocating to arbitrarily large `max_entries` values.
- `glob` response fast path: skip final sorting when traversal output is already in lexicographic path order.
- `list_dir` hot path: avoid cloning canonical root `PathBuf` on each call; use borrowed root path directly during entry processing.
- Unix metadata-copy docs: document why Linux/Android xattr preservation uses fd-scoped libc syscalls (std has no xattr API) and clarify syscall-level `unsafe` invariants.
- Unix xattr sync allocation trim: stop cloning source xattr names into owned `Vec<u8>` set entries; reuse borrowed name bytes during destination-diff checks.
- `grep` glob-prefix correctness: only apply directory-probe skip checks when the derived prefix is a directory, so file globs like `a.txt` are not incorrectly filtered by skip rules such as `a.txt/*`.
- `grep` readability cleanup: flatten per-line regex/plain query match selection via `Option` combinator (`map_or_else`) in the hot scan loop.
- Delete API cleanup: remove over-designed `DeleteKind`/`&str` `PartialEq` impls and keep comparisons explicit at call sites.
- CLI command dispatch: consume `Cli`/`Command` by value in `command_exec` so request payload fields are moved instead of repeatedly cloned per branch.
- Policy ergonomics: mark `Permissions` as `Copy` (it is a bool-only value type), reducing incidental clone noise at call sites.
- Ops permission-gate cleanup: centralize policy-permission checks in `Context` helpers and route operation entry checks through them to reduce repeated inline guards.
- `write` internals: rename generic lifetime parameter in `WriteCommitContext` to a semantic name (`'ctx`) for clearer ownership intent.
- Redaction internals: factor shared `normalize_path_for_glob` logic into a common helper; Windows keeps only the extra path-separator/non-Unicode handling.
- Policy docs: clarify lexical-only path-check wording for `resolve_path_checked`.
- Combinator cleanup: replace selected small `match`/`if let` return plumbing with `and_then`/`map_or(_else)` chains in traversal/patch helpers.
- Platform boundary cleanup: isolate platform-specific FFI/`unsafe` into `src/platform/{rename,windows_path_compare,unix_metadata}.rs` and keep `ops/io` + `path_utils` on safe wrappers.
- Windows identity hardening: `copy_file`/`delete` now only treat two paths as the same file when all identity fields (`volume_serial_number`, `file_index`) are present on both sides; unknown IDs are no longer treated as implicit same-file matches.
- Windows identity verification fallback: `copy_file`/`move_path`/`delete` now treat missing file-ID metadata as best-effort (continue with canonical-path revalidation) instead of hard-failing the operation.
- `read` line-range memory tuning: switch from file-size-based upfront reservation to a small bounded initial capacity to avoid large allocations for narrow line windows.
- `read` line-range skip-path memory tuning: skipped pre-range lines are now consumed in streaming chunks instead of buffering whole lines, avoiding large temporary allocations on very long prefix lines.
- `read` line-range correctness: line-based reads now treat bare `\r` as a line ending (and handle `\r\n` as a single newline), fixing out-of-bounds errors on classic-Mac style files.
- Unix metadata portability: fix ownership-preservation `gid` sentinel to use `libc::gid_t::MAX` (instead of `uid_t`) when preserving uid/gid deltas.
- `grep` plain-query scan loop: reuse one query-window buffer per request in `read_line_capped` instead of allocating a new window per line/file, reducing hot-path allocation churn on large-file and many-file scans.
- `grep` hot-path cleanup: precompute per-request capped-line budget once and reuse it across all scanned files, removing repeated invariant work inside the file loop.
- `grep` line scanning micro-optimization: replace front-`drain` window trimming with bounded suffix compaction (`copy_within` + `truncate`) to avoid repeated O(n) front-removal costs on long-line plain-query scans.
- `list_dir` `max_entries=0` fast path: skip per-entry metadata/kind materialization and run count-only filtering, cutting unnecessary I/O while preserving truncation and error accounting behavior.
- `list_dir` zero-limit traversal fast path: stop scanning after the first visible entry when `max_entries=0`, avoiding full-directory scans when callers only need truncation presence.
- `list_dir` zero-limit parity fix: `max_entries=0` count-only flow now classifies `file_type()` failures as skipped I/O errors (instead of counting them as visible entries), preserving diagnostics consistency.
- `list_dir` allocation trim: keep candidate names as `OsString` and defer lossy UTF-8 allocation until response emission, reducing per-entry string churn in large directory scans.
- Windows move/copy same-target fallback: when platform file IDs are unavailable, no-op same-path detection now uses lexical case-insensitive path equality (normalized) to avoid false `destination exists`/redundant move-copy behavior on case-only aliases.
- Windows path-compare hot path: short-circuit exact `OsStr` equality before UTF-16 conversion/FFI, reducing per-call allocation overhead on already-identical segments.
- Traversal glob matching on Windows now checks for backslashes first and skips UTF-16 normalization allocation when paths already use forward slashes.
- Traversal glob matching on Windows now avoids double `encode_wide()` passes in the hot path by using a byte-level separator fast check before a single UTF-16 normalization pass.
- `stat` now builds responses from post-revalidation metadata (instead of the pre-check snapshot), reducing stale size/timestamp responses under concurrent file mutation.
- `grep` now enforces `max_walk_ms` inside per-file line scanning loops (not only between files), so large single-file scans respect time-budget truncation more predictably.
- `grep` time-budget enforcement: line scanning now checks `max_walk_ms` inside the chunked `read_line_capped` loop as well, preventing oversized single-line inputs from overshooting the configured traversal budget.
- `grep` hot-loop cleanup: remove duplicate per-line `elapsed()` guard in the line-scan loop and rely on the chunk-level `read_line_capped` budget check, reducing redundant time-budget probes on hot paths.
- `grep` line-buffer reuse tuning: defer hot-loop shrink operations to per-file boundaries to reduce repeated grow/shrink allocation churn on long-line scans.
- `grep` no-match scan path now opportunistically shrinks oversized reusable line buffers, preventing long-running scans from retaining multi-megabyte capacity after isolated long-line spikes.
- Policy hard caps for `limits.max_read_bytes` / `limits.max_patch_bytes` / `limits.max_write_bytes` are reduced from 1 GiB to 256 MiB to lower worst-case in-memory operation risk under misconfiguration.
- `grep` plain-query scan loop now bypasses UTF-8 decode for ASCII no-match lines while preserving non-UTF8 file-skip behavior.
- `grep` path allocation trim: delay per-file match-path cloning until the second match so single-match files avoid one `PathBuf` clone.
- Windows rename error mapping: `copy_file`/`write_file` now treat raw OS errors `80/183` as destination-exists when `overwrite=false`, matching `move_path` semantics under race conditions.
- `list_dir` top-k selection now defers file `metadata()` reads until an entry is a real heap candidate, reducing syscall pressure on large directories with small `max_entries`.
- `list_dir` result materialization now uses `BinaryHeap::into_sorted_vec()` directly, removing a redundant extra sort pass during response assembly.
- `list_dir` hot-path syscall trim: remove per-entry preflight `file_type()` probes and keep no-follow metadata reads only on selected candidates, reducing directory-scan syscall volume.
- `list_dir` zero-limit count path: restore a lightweight `file_type()` guard in `max_entries=0` counting mode so transient entry-read failures are tracked as `skipped_io_errors` instead of being overcounted as visible entries.
- `glob`/`grep` prefix precheck: run deny/skip short-circuit before `walk_root.is_dir()` probing, avoiding unnecessary filesystem metadata checks when traversal is already excluded by policy.
- `list_dir` TOCTOU hardening: candidate finalization now uses `symlink_metadata` (no-follow) to derive final type/size, preventing raced symlink replacements from being followed while collecting entry metadata.
- `resolve/dir_ops` deep-path traversal now reuses borrowed parent-relative paths instead of cloning `PathBuf` on every segment, reducing O(depth²) path-copy overhead.
- `list_dir` candidate-name comparison now uses borrowed lossy views in heap ordering checks, deferring owned `String` allocation to final response materialization for selected entries only.
- `list_dir` non-UTF8 name ordering now caches lossy conversion per candidate for repeated heap comparisons, avoiding duplicate string allocation in large-directory top-k scans.
- Unix xattr metadata copy now enforces explicit safety caps for xattr value/name-list lengths before allocation, reducing peak-memory risk on pathological filesystems.
- `edit` range rewrite no longer builds a full `Vec<&str>` line index; it now scans once to locate byte offsets and rewrites via prefix/replacement/suffix slicing to reduce peak memory on large files.
- `delete --recursive` now pre-scans descendants against `secrets.deny_globs` and fails closed on denied nested paths before `remove_dir_all`, preventing parent deletes from bypassing deny rules.
- `delete --recursive` deny-prescan now short-circuits when `secrets.deny_globs` is empty and uses `DirEntry::file_type()` during traversal, reducing unnecessary directory-tree scan overhead and metadata syscalls on non-secret-policy workloads.
- `list_dir` finalization no longer mutates visible-entry counters on post-selection metadata races; those races now only impact entry materialization and `skipped_io_errors`, preserving truncation semantics from the initial scan pass.
- `list_dir` now marks `truncated=true` when post-selection metadata races drop retained entries under the `max_entries` limit, making incomplete responses explicit instead of appearing fully complete with only `skipped_io_errors`.
- Unix xattr metadata copy now retries boundedly on `ERANGE` races during two-phase `flistxattr`/`fgetxattr` reads, reducing spurious failures when attributes mutate concurrently.
- `copy_file` no-op fast paths now move already-owned request/response paths instead of cloning them, trimming hot-path allocations when source and destination resolve to the same file.
- Policy validation now enforces the effective `glob` response budget (explicit `limits.max_glob_bytes` or default `limits.max_results * limits.max_line_bytes`) against the hard cap, closing a large-budget configuration gap when `max_glob_bytes` is omitted.
- Traversal no longer re-checks secret deny globs for files after `walkdir` entry filtering, removing duplicate hot-path glob matches while preserving filtering behavior.
- `list_dir` now defers `DirEntry::path()` materialization until after deny-glob filtering, avoiding unnecessary absolute-path allocations for denied entries during large-directory scans.
- Traversal glob fast path: in `open_mode=None`, non-symlink entries now skip per-file canonical-path revalidation and reuse already-validated root-relative walk paths, reducing `canonicalize` syscall pressure on large glob scans while preserving symlink/read-mode safety checks.
- Windows path-compare fix: `ascii_case_insensitive_cmp_fast` now continues scanning after case-only-equal ASCII units instead of returning early, preventing false-equal results on strings that differ at later characters.

## [0.2.0] - 2026-02-14

### Added

- New filesystem operations: `list_dir`, `stat`, `mkdir`, `write_file`, `move_path`, `copy_file` (all root-bounded and policy-gated).
- Policy: add `permissions.{list_dir,stat,mkdir,write,move,copy_file}`.
- CLI: add commands `list-dir`, `stat`, `mkdir`, `write`, `move`, `copy-file` and extend `delete` with `--recursive` and `--ignore-missing`.
- Dev: add GitHub Actions workflows (CI/docs/release) and a shared `scripts/gate.sh`.
- Tests: add a Windows regression test for `rename_replace` overwrite semantics.
- Tests: add large-directory/large-file integration scenarios to exercise `list_dir` and `read` under heavier inputs.

### Changed

- CLI internals now reuse the library's shared no-follow regular-file open helper (`open_regular_readonly_nofollow`) instead of maintaining a separate platform-specific opener implementation.
- Docs/internal comments: align `ops` module notes with the current crate-root `glob`/`grep` export behavior.
- Internal cleanup: `read` line-range scanning now uses a single reusable output buffer, and `Context::new` root-overlap checks reuse existing root runtime entries instead of maintaining a duplicate `(id, canonical_path)` side list.
- API: `Context` now supports `Context::builder(policy).build()` as a forward-compatible construction entrypoint while keeping `Context::new(policy)` behavior unchanged.
- Internal path-resolution cleanup: `resolve_path_in_root_lexically` now keeps `canonical_root` borrowed as `&Path` for intermediate checks and only materializes a `PathBuf` at the return boundary.
- API docs: `ReadRequest.path` now documents the ownership rationale (`PathBuf` request boundary, borrowed hot path) to avoid unnecessary lifetime-driven API complexity.
- Batch review/apply refresh (`10` 并发) across `cli`/`src/ops`/`tests`: tightened error-path consistency, reduced deeply nested control flow, and normalized formatting/readability in hot and boundary-sensitive paths.
- Path-resolution contract hardening: internal lexical resolve flow now uses `resolve_path_checked` for explicit root-boundary validation semantics.
- Batch review-driven maintenance sweep across core ops/CLI/tests: tightened path/permission/error handling contracts, reduced control-flow complexity, and aligned helper APIs with clearer ownership and typing boundaries.
- Review follow-up refactor/hardening sweep: strengthened root-relative path contract validation for mutating ops, tightened IO/path error typing and redaction plumbing, and expanded cross-op regression coverage in `tests/*`.
- Internal refactor: flattened traversal walk error/symlink handling into focused helpers in `src/ops/traversal/walk.rs` to reduce nested control flow.
- `list_dir` now uses a dedicated count-only fast path for `max_entries=0`, avoiding unnecessary entry materialization.
- `stat` responses now include optional `accessed_ms`/`created_ms` timestamps and a `readonly` flag.
- Path utils: mark hot short helpers with `#[inline]` for lower call overhead in tight path-processing loops.
- Internal dedup: extracted shared no-follow read-open helpers (`platform_open`) used by `policy-io`, CLI text-input loading, and core read paths; extracted shared non-root leaf validation for `write`/`delete`.
- Internal refactor: split `resolve` directory-walk enforcement into `src/ops/resolve/dir_ops.rs`, split traversal internals into `src/ops/traversal/{compile,walk}.rs`, and moved CLI command dispatch/validation into `cli/src/command_exec.rs`.
- CI supply-chain hardening: all third-party GitHub Actions in `ci/docs/release` workflows are now pinned to immutable commit SHAs (with version comments for auditability).
- Docs wording cleanup: README and DB-VFS notes now use neutral “future work” wording instead of ad-hoc TODO markers in examples/headings.
- Review follow-up hardening: `grep` now rejects empty/whitespace-only queries, `list_dir` now honors explicit `max_entries=0`, and `edit` no longer inserts an extra blank line when replacement text is empty.
- CI/release reproducibility and least-privilege updates: release workflow now defaults to `contents: read` (publish job keeps write), and release/docs cargo commands now run with `--locked`.
- Hook robustness: `githooks/pre-commit` now protects released changelog sections by diffing all non-`[Unreleased]` content instead of relying on a numeric version-heading regex.
- Tests: tightened regression coverage for `grep` entry-limit reason, `list_dir max_entries=0`, empty-line replacement semantics, readonly write side effects, and TOML policy fixture serialization.

- Hooks/tests hardening from full-file review: tightened `commit-msg` subject validation, strengthened `pre-commit` staged-diff failure handling, and added regression assertions for failure-side-effect invariants.
- Error/CLI contract: `tool_error_details*` now always returns a JSON object, and `patch` error details/messages are path-redaction aware.
- API typing: `stat` response `type` is now modeled by `StatKind` enum in Rust while preserving lowercase JSON serialization.
- Internal API cleanup: `Context::canonical_root` now returns `&Path` instead of `&PathBuf` to avoid leaking storage details.
- Docs: refresh `README`/`SECURITY`/`docs/db-vfs.md`/`AGENTS.md` wording for command naming, disclosure channel, reproducible DB-VFS setup, and execution flow.

- Hooks/scripts: `pre-commit` now parses staged files via `--name-status -z` (including rename/copy cases) and explicitly rejects deleting `CHANGELOG.md`; `scripts/gate.sh` now derives the workspace root from script location instead of caller `pwd`.
- Docs/examples: tighten wording in `README.md`/`AGENTS.md`/`SECURITY.md`, clarify DB-VFS `path_prefix` derivation rules, and make `policy.example.toml` use a neutral absolute-path placeholder with a Windows example.
- Workspace: `cli/Cargo.toml` now uses only the local `path` dependency for `omne-fs` (drops redundant fixed `version`).

- Breaking: consolidate delete APIs as `delete` (remove `delete_file`/`delete_path`); `DeleteRequest` adds `recursive`/`ignore_missing` and the response adds `{deleted, type}`.
- `policy-io`: `parse_policy` now validates by default; use `parse_policy_unvalidated` when raw parse-without-validate is explicitly required.
- Windows: keep atomic overwrite replacement semantics by using `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` behind a single, documented `unsafe` boundary in `rename_replace` (explicitly reject delete+rename fallback for overwrite paths).
- Dev: pre-commit rejects oversized Rust files (default 1000 lines; configurable via `SAFE_FS_MAX_RS_LINES`).
- Docs: expand README and policy example to include new operations and permissions.
- Docs: split MSRV and toolchain-pin wording, pin the dependency example version, and keep troubleshooting terminology consistent in English.
- Docs: `docs/example-survey.md` is now explicitly non-normative and references authority docs (`README.md`/`SECURITY.md`) instead of stale workspace-local paths.
- Docs: `docs/db-vfs.md` now aligns `path_prefix` and delete/CAS contract wording, and uses env-var DSN examples instead of inline Postgres credentials.
- Docs/Security: add an explicit local-first scope statement and detailed rationale for not adopting a full `openat`/`cap-std` descriptor-chain confinement model at this stage.
- Docs: mark DB-VFS decision implemented, reference the `db-vfs` project, clarify `path_prefix`/CAS semantics, and add a Postgres run example for `db-vfs-service`.
- Docs: update the example upstream integration name to `omne-agent`.
- CI: `release` workflow now runs `cargo test --workspace` before publishing artifacts.
- Docs: README now includes a TOC and a "常见失败" troubleshooting section.

### Fixed

- `glob`/`grep` traversal now preserves requested file/symlink-file aliases for file-root walks, so exact patterns like `link.txt` continue matching symlink entries instead of being silently canonicalized to target names.
- `stat` unsupported-platform identity errors now explicitly document that identity revalidation is currently Unix/Windows-only.
- `copy_file` replacement commit path handling now avoids `TempPath::as_ref()` type ambiguity by using an explicit `&Path` binding, restoring clean `cargo check` on current toolchain.
- Regression cleanup after bulk review apply: restored `mkdir` leaf-validation contract, restored default test redaction/permission baseline, aligned read-range error wording back to `invalid line range`, and normalized missing-parent metadata error tagging in directory resolution.
- Tests: expanded `glob` edge coverage for missing derived prefixes and `.` pattern stability.
- CLI tests: Unix FIFO helper now treats `EEXIST` as success, reducing flaky failures in retry/parallel test scenarios.
- `write_file` overwrite path now re-checks canonicalized relative paths against `secrets.deny_globs`, and size conversions avoid lossy `as u64` casts.
- `delete(ignore_missing=true)` now consistently handles `NotFound` races during `remove_file`/`remove_dir_all`.
- `move_path` now delays destination parent creation until after key validations and early-returns `moved=false` for same-entity destinations.
- `mkdir` now re-validates root boundaries for `ignore_existing` directories and rolls back newly-created directories on post-create boundary check failures.
- `policy-io` extension detection is now ASCII case-insensitive (`.JSON`/`.Toml` accepted).
- `pre-commit` now detects `CHANGELOG.md` deletion via rename (`R old -> new`) in addition to direct deletes.

- CLI: strict path redaction now redacts relative paths too (`--redact-paths-strict` no longer leaks path fragments), and stdout `BrokenPipe` handling is centralized.
- Limits/path correctness: `glob`/`grep` now enforce `max_results` before pushing matches; `edit` line indexes now use checked `u64 -> usize` conversion; traversal limit comparisons now avoid lossy integer casts.
- Policy/path safety: `root.id` now rejects leading/trailing whitespace; `policy-io` now treats non-UTF-8 extensions as invalid instead of defaulting to TOML; deny checks now defensively reject parent-relative (`..`) paths.
- Write/move/delete semantics: `copy_file` same-path no-op now still validates source existence/type; `patch` reports `bytes_written=0` on no-op; `move_path`/`delete` now fail closed when root-relative derivation fails instead of falling back to absolute paths.
- `move_path`: destination-exists checks now allow same-entity case-only renames on case-insensitive filesystems.
- `mkdir`: `AlreadyExists` races through symlinks now return explicit symlink errors, and created/accepted directories get an additional canonical post-check against the selected root.
- Platform hardening: on Windows, `policy-io` and CLI input loading now use no-follow (reparse-point) open semantics with handle-based symlink checks; on unsupported non-Unix/non-Windows platforms these paths now fail closed.
- Non-Linux/Android Unix: no-replace rename fallback no longer uses `exists()+rename` (TOCTOU-prone); it now returns `Unsupported` when an atomic primitive is unavailable.

- Unix: file reads and policy/CLI text inputs now open with `O_NOFOLLOW` and validate type on the opened handle, reducing symlink/FIFO TOCTOU windows.
- Non-Windows: `rename_replace(..., replace_existing = false)` now enforces no-replace semantics (Linux/Android uses `renameat2(RENAME_NOREPLACE)`; other Unix fails with `Unsupported` when no atomic primitive exists).
- Unix: atomic rename paths now fsync parent directories after rename for better crash consistency.
- `write_file`: create-new writes now use temp-file + no-replace rename, preventing readers from observing partially written new files.
- `copy_file`/`move_path`/`write_file`: race-time `AlreadyExists` on no-overwrite paths now maps to stable `invalid_path` errors.
- `resolve`: absolute-input requested-path derivation no longer falls back to absolute paths when root-relative derivation fails.
- `secrets.deny_globs`: non-root-relative paths are now denied defensively instead of being implicitly treated as non-matching.
- CI: fix Windows build by using `MoveFileExW` for atomic replacement (avoid missing `ReplaceFileW` bindings).
- CI: fix Windows-only test compilation (`PathBuf` comparison).
- CI: fix Windows `policy_io` TOML tests (avoid backslash escape issues in `path`).
- Docs: add a GitHub Pages root `index.html` redirect so the docs site doesn’t 404.
- CLI: reject symlink paths for patch/content input files loaded by `load_text_limited`.
- CLI: JSON error output now honors `--pretty` and success stdout writes handle `BrokenPipe` without panic.
- CLI: stdin-backed text input errors are now emitted as contextual `io_path` details (`op=read_stdin`, `path=-`).
- `read` line-range mode now validates regular-file type via the opened file handle (instead of split metadata/open checks).
- `patch` errors now include the target relative path for easier diagnostics, and no-op patches avoid unnecessary writes.
- `patch` now performs best-effort same-file identity verification between read and write on Unix (detects inode replacement races).
- `mkdir` now fails closed if root-relative parent derivation fails and handles `create_dir` `AlreadyExists` races more predictably with `ignore_existing`.
- `edit` now normalizes replacement line endings for LF files (converts `\r\n`/`\r` to `\n`) to prevent mixed-EOL output.
- `delete` now returns a consistent missing-path payload (`path=requested_path`) across missing-parent and missing-target branches.
- Hooks/scripts: tighten commit-message bypass rules (`MERGE_HEAD`/`REVERT_HEAD` checks, guarded `fixup!/squash!`), make pre-commit filename-safe with NUL-delimited git plumbing, validate `SAFE_FS_MAX_RS_LINES`, and scope Rust line checks to staged `.rs` files.
- `scripts/gate.sh` now supports configurable core crate name, enforces stricter behavior under CI when workspace metadata is missing, and validates `--no-default-features` with `check+clippy+test` on the core crate.
- `scripts/setup-githooks.sh` now validates/chmods hook files before writing `core.hooksPath` and writes config with `--local`.
- CLI redaction now masks relative-path error inputs to file names, redacts `not_permitted` detail messages, and avoids leaking raw `io`/`not_permitted` text in public redacted messages.
- Hooks/dev scripts: `scripts/gate.sh` now recognizes CI truthy values case-insensitively, fails by default when no workspace is found (with explicit local skip override), and runs cargo gates with `--locked`; `scripts/setup-githooks.sh` now preserves existing non-default `core.hooksPath` and emits success messages on stdout.
- CLI/path guardrails: CLI line-range arguments now enforce `>=1` with early `start_line <= end_line` checks, JSON error fallback remains valid JSON, and text-input `ELOOP` diagnostics now use safer wording.
- Policy/path consistency: `walkdir_root` now has a distinct programmatic error code, policy validation rejects `max_walk_files > max_walk_entries`, policy loading detects unsupported extensions before file reads, and write/copy/delete path checks fail closed more consistently.
- CI/release workflow reliability: CI now has a job timeout, and release tag-version verification now reads `cargo metadata` from a temp file (fixes stdin/here-doc parsing breakage).
- Redaction/policy/tests hardening: empty redaction regex patterns are rejected explicitly, policy byte-limit guard now rejects `>= usize::MAX`, and regression tests were strengthened for readonly delete side effects, FIFO patch input semantics, policy field parsing, symlink-to-secret denial, and Windows traversal skip-glob behavior.

## [0.1.0] - 2026-01-31

### Added

- Initial `SandboxPolicy`/`Root`/`SecretRules` model.
- Library + CLI for `read/glob/grep/edit/patch/delete` with root-bounded access and redaction.
- `read` supports optional line ranges (`start_line`/`end_line`).
- `grep` reports skipped file counts for non-UTF8 / too-large files.
- `grep` matches include `line_truncated` when a matched line is clipped to `limits.max_line_bytes`.
- `edit` preserves CRLF line endings.
- `glob` results are sorted by path; `grep` results are sorted by `(path, line)`.
- Split CLI into `omne-fs-cli` so the library has no CLI-format dependencies.
- Add `limits.max_walk_files` and report `scanned_files` / `scan_limit_reached` in `glob`/`grep` responses.
- Add `limits.max_walk_entries` to cap directory traversal work (helps bound huge directory trees with few files).
- Add `limits.max_walk_ms` traversal time budget for `glob`/`grep` and report `elapsed_ms` in responses.
- `glob`/`grep` responses now include `scan_limit_reason` (`entries`/`files`/`time`/`results`) when a cap is hit.
- `glob`/`grep` responses now include traversal diagnostics (`scanned_entries`, `skipped_walk_errors`, `skipped_io_errors`, `skipped_dangling_symlink_targets`).
- Add `traversal.skip_globs` to skip paths during traversal (`glob`/`grep`) without denying direct access.
- Add `paths.allow_absolute` to optionally reject absolute request paths (require root-relative tool inputs).
- Enforce `limits.max_read_bytes` for `edit`/`patch` file reads (and use bounded reads for `read`/`grep`).
- `delete` unlinks symlinks (does not follow link targets).
- Add stable `Error::code()` for programmatic classification.
- Add `Error::InputTooLarge` (code: `input_too_large`) for oversized CLI inputs.
- Add `limits.max_patch_bytes` to cap unified-diff patch input size (defaults to `limits.max_read_bytes`).
- `read`/`edit`/`patch` responses now include `requested_path` (normalized input path).
- `delete` responses now include `requested_path` (normalized input path).
- Add `Context` method wrappers and crate-root re-exports for easier library consumption.
- Add `SandboxPolicy::single_root` helper for simpler library integration.
- Add `Context::from_policy_path` helper for a one-call policy+context load (via `policy-io`).
- CLI: add `--error-format json` for structured errors.
- CLI: add `--max-patch-bytes` to cap patch stdin/file input size.
- CLI: add `--redact-paths` to best-effort redact absolute paths in JSON error output.
- CLI: include `error.details` in JSON errors for most tool error kinds.
- Add `docs/example-survey.md` (notes from `example/` repositories).
- Add `docs/db-vfs.md` (DB-backed VFS decision + TODOs).
- Add optional cargo features: `glob`/`grep`/`patch` (default on) and `policy-io`.
- Library: expose `path_utils::{starts_with_case_insensitive, strip_prefix_case_insensitive}` helpers (useful for Windows-safe prefix comparisons).

### Changed

- Bump crate editions to Rust 2024.
- `Error` is now `#[non_exhaustive]`; downstream code should include a wildcard match arm.
- `Error::code()` now distinguishes `io` and `io_path`.
- Enforce roots are absolute directories (policy validation + context init).
- `glob`/`grep` now include symlinked files (still do not traverse symlinked directories).
- `glob`/`grep` traversal now uses deterministic entry ordering (stable behavior under truncation caps).
- `glob`/`grep` may narrow traversal scope based on a literal prefix in the glob pattern.
- `edit` now checks `limits.max_write_bytes` before constructing the edited output.
- `patch` now enforces patch input size via `limits.max_patch_bytes`/`limits.max_read_bytes` (rejects oversized patch input with `input_too_large`).
- CLI `--max-patch-bytes` defaults to `limits.max_patch_bytes` if set (else `limits.max_read_bytes`) and is capped by policy.
- IO errors produced by operations include operation/path context where available.
- Internal: consolidate lexical path normalization into a shared helper to avoid drift between ops and deny-glob matching.
- Atomic write on Windows now uses `ReplaceFileW` for true replacement semantics.
- On Windows, `secrets.deny_globs` matching is now explicitly case-insensitive.
- On Windows, `glob` patterns and `traversal.skip_globs` matching are now explicitly case-insensitive.
- CLI: JSON `error.details` for `io`/`io_path` now always include `io_kind` and `raw_os_error` (even without `--redact-paths`).
- CLI: add `--redact-paths-strict` for stricter path redaction in JSON errors.
- `policy-io`: `load_policy` now enforces a maximum policy file size (default 4 MiB); use `load_policy_limited` for custom limits.
- `policy-io`: `load_policy` now runs `SandboxPolicy::validate` to catch structural issues early.
- Docs: clarify `glob`/`grep` truncation semantics when `limits.max_results` is hit.
- Docs: clarify atomic write durability semantics.
- Docs: clarify `SandboxPolicy::validate` is structural (no filesystem IO).
- Docs: clarify `glob`/`grep` traversal does not read `.gitignore`.
- Docs: clarify `grep` match text may be empty when `limits.max_line_bytes` is smaller than a UTF-8 character.
- Docs: clarify `edit`/`patch` operate on existing files (do not create new files).
- CLI: success JSON output is now compact by default; use `--pretty` for pretty-printed output.
- Internal: share traversal loop between `glob` and `grep` to reduce drift.
- Internal: deduplicate glob builder configuration across tool and deny/skip patterns to avoid semantic drift.
- Docs: align the `Dev` commands with the `pre-commit` hook gates (`--workspace`, `--no-default-features`).
- Internal: make `Context::canonical_path_in_root` easier to audit without changing behavior.
- Docs: clarify `delete` semantics for directories vs special files.
- Docs: clarify Windows hardening scope for `path` inputs (best-effort; prefer root-relative paths for untrusted inputs).
- Docs: note `SandboxPolicy::resolve_path` rejects drive-relative Windows paths (e.g. `C:foo`).
- Internal: split `ops` implementation into smaller modules for readability.
- Tests: split the large `basic` integration test into smaller per-area test files.
- Internal: make the `delete` directory error message more precise.
- Internal: share lexical root/requested path resolution between `delete` and `canonical_path_in_root`.
- Docs: clarify how `secrets.deny_globs` applies to `delete` (parent canonicalization vs unlink target).

### Fixed

- `read_bytes_limited` now validates file metadata before opening (avoids blocking on FIFOs/special files and hardens special-file rejection).
- Traversal deny/skip filtering now derives relative paths case-insensitively on Windows.
- `--no-default-features` now builds cleanly (gate `walkdir` error variant behind traversal features).
- `delete` now applies `secrets.deny_globs` to the normalized requested path (prevents bypass via symlinked directories).
- `secrets.deny_globs` can no longer be bypassed via symlink paths (deny rules are applied before resolving symlink targets).
- `secrets.deny_globs` matching now performs lexical normalization (e.g. `sub/../.git/...`), preventing bypass via `..` segments.
- Lexical normalization now preserves repeated leading `..` segments (e.g. `../../b`), improving path reporting and deny-glob behavior.
- On Windows, glob/deny-glob matching now handles `\\` path separators.
- On Windows, prefix-optimized traversal rejects drive-letter glob prefixes (e.g. `C:/...`) to prevent escaping the selected root.
- On Windows, prefix-optimized traversal also rejects embedded drive prefixes (e.g. `src/C:foo/*`) to prevent escaping the selected root.
- On Windows, drive-relative paths (e.g. `C:foo`) are now rejected by `SandboxPolicy::resolve_path`.
- Redaction replacement strings are now treated literally (no `$1` / `$name` capture expansion).
- `edit`/`patch` now write atomically (temp file + rename) and preserve existing file permissions.
- Atomic write temp files are created with restrictive permissions on Unix to avoid transient exposure.
- Dangling symlinks that would escape a root are now classified as `outside_root` (instead of a generic IO error).
- `glob`/`grep` no longer fail on dangling symlink targets; they skip the entry.
- `glob`/`grep` no longer fail on traversal/read errors (e.g. permission-denied directories/files); they skip the entry and report skip counts.
- Prefix-optimized traversal no longer follows symlink directories (`walkdir` root links are not followed).
- CLI `--redact-paths` no longer includes raw `walkdir` error messages in JSON `error.details` (which could leak absolute paths).
- On Windows, lexical path normalization no longer drops drive/UNC prefixes (fixes `..` handling for absolute paths).
- Invalid `secrets.redact_regexes` patterns are now rejected as `invalid_policy` (instead of `invalid_regex`).
- CLI `--redact-paths` now omits raw `io` error messages in JSON `error.details` and includes structured `io_kind`/`raw_os_error` instead.
- `outside_root` and related `canonicalize` errors now report the normalized requested path (avoids leaking absolute root paths for relative inputs).
- Root-level traversal (`glob`/`grep`) errors no longer leak absolute paths via `walkdir` errors.
- Traversal now fails closed if a root-relative path cannot be derived (avoids falling back to absolute paths).
- `glob`/`grep` now treat missing derived traversal roots as empty results, but surface permission/IO errors for existing but unreadable roots.
- `requested_path` derivation for absolute inputs no longer depends on canonicalizing missing/unreadable parents; it uses lexical normalization and root-relative stripping when possible.
- Paths that are lexically outside the selected root are now rejected before filesystem canonicalization, reducing filesystem probing side-channels for missing/outside paths.
- `requested_path` no longer serializes as an empty string for `.` inputs.
- `canonical_path_in_root` no longer returns an empty `path` for the root itself; it uses `.` for consistency in errors/responses.
- `grep` line truncation now respects UTF-8 character boundaries (avoids replacement characters).
- CLI: redacted JSON error formatting no longer re-loads the policy file; it reuses the already-loaded policy roots for consistent path redaction.
- CLI: redacted JSON error details now include safe `message` strings for `invalid_path`/`invalid_policy`.
- CLI: on Windows, `--redact-paths` now strips root prefixes case-insensitively for more consistent relative paths.
- On Windows, canonical root-boundary checks now compare paths case-insensitively to avoid false `outside_root` errors.
- CLI: `--max-patch-bytes` now rejects `0` (must be > 0).
- Atomic write temp file names are now randomized to reduce pre-creation attacks in untrusted workspaces.
- Internal: add a regression test locking traversal skip-glob directory probe semantics.
- `read` line-range mode now reports `file_too_large.size_bytes` using file metadata when available (instead of scanned bytes).
- Glob patterns now normalize leading `./` for `glob`/`grep` and policy glob rules (`secrets.deny_globs`, `traversal.skip_globs`).
- On Windows, `SandboxPolicy::resolve_path` now rejects paths containing `:` in a normal component (blocks NTFS alternate data stream access like `file.txt:stream`).
- Glob patterns starting with `/` or containing `..` are now rejected early as invalid inputs (instead of being accepted but never matching).
- On Windows, `walkdir` root errors now compute relative paths case-insensitively for more consistent diagnostics.
- `glob`/`grep` no longer fail when `paths.allow_absolute=false` and encountering symlinked files during traversal.
- `read`/`edit`/`patch` now reject non-regular files (FIFOs, sockets, device nodes) to prevent blocking/DoS.
- `policy-io` now rejects non-regular policy files (FIFOs, sockets, device nodes) to prevent blocking/DoS.
- CLI: patch input files now reject non-regular files (FIFOs, sockets, device nodes) to prevent blocking/DoS.
