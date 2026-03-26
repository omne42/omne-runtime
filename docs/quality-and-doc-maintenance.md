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

## AGENTS 规则

- `AGENTS.md` 是地图，不是百科全书。
- 保持简短，优先控制在 160 行以内。
- 它必须把读者指向 `docs/` 中更深的事实来源。
- 不在 `AGENTS.md` 里放难以维护的长规则、角色扮演或一次性流程细节。

## 变更触发器

- crate 行为边界变化：更新该 crate 的 `system-boundaries.md`。
- crate 模块或文件职责变化：更新该 crate 的 `source-layout.md`。
- workspace 新增 crate 或 crate 归属变化：更新 `workspace-crate-boundaries.md` 和 `source-layout.md`。
- README 不再指向文档入口：在同一改动中修正。

## 机械校验

- 运行 `../scripts/check-docs-system.sh` 检查骨架、README 入口和 `AGENTS.md` 长度。
- 文档变更至少运行一次该脚本。
- 如涉及代码行为变化，再补对应 crate 的测试或 workspace 测试。
