# Quality And Doc Maintenance

## 核心原则

- 文档系统是记录系统，不是聊天记录的缓存。
- `AGENTS.md` 只保留导航，不重新复制详细事实。
- 事实优先写进最靠近代码边界的位置，也就是对应 crate 的本地 docs。
- 文档入口必须稳定、可预测、可机械检查。

## 最小文档骨架

workspace 根必须具备：

- `README.md`
- `AGENTS.md`
- `docs/docs-system-map.md`
- `docs/source-layout.md`
- `docs/workspace-crate-boundaries.md`

每个 `crates/<name>/` 必须具备：

- `README.md`
- `AGENTS.md`
- `docs/docs-system-map.md`
- `docs/architecture/source-layout.md`
- `docs/architecture/system-boundaries.md`

嵌套在某个 crate 边界里的 workspace package 继续复用父 crate 的文档系统；只有当它被提升为
新的 sibling capability crate 时，才补自己的顶层文档骨架。`scripts/check-docs-system.sh`
会按 `Cargo.toml` 的真实 workspace members 校验这一点，而不是只扫顶层 `crates/*`。

## AGENTS 规则

- `AGENTS.md` 是地图，不是百科全书。
- 保持简短，优先控制在 160 行以内。
- 它必须把读者指向 `docs/` 中更深的事实来源。
- 不在 `AGENTS.md` 里放难以维护的长规则、角色扮演或一次性流程细节。

## 变更触发器

- crate 行为边界变化：更新该 crate 的 `system-boundaries.md`。
- crate 模块或文件职责变化：更新该 crate 的 `source-layout.md`。
- workspace 新增 crate 或 crate 归属变化：更新 `workspace-crate-boundaries.md` 和 `source-layout.md`。
- workspace 新增嵌套 package 但未形成新边界：更新对应父边界的 workspace 文档，不机械复制新的 crate docs skeleton。
- README 不再指向文档入口：在同一改动中修正。

## 机械校验

- 运行 `../scripts/check-docs-system.sh` 检查 workspace members 对应的文档骨架、README 入口、`AGENTS.md` 长度，以及文档系统范围内残留的 git conflict marker。
- 运行任何 workspace 级 Rust gate 之前，先确认网络和 Cargo git 获取能力可用，
  因为跨仓 foundation 依赖通过 canonical git source pin 拉取；gate 入口不应再把
  sibling checkout 当作前置条件。
- 文档变更至少运行一次该脚本。
- 如涉及代码行为变化，再补对应 crate 的测试或 workspace 测试。
