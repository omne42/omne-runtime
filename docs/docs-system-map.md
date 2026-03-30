# Workspace Docs System

## Start Here

- 外部概览：`../README.md`
- 执行者地图：`../AGENTS.md`
- workspace crate 边界：`workspace-crate-boundaries.md`
- workspace 布局：`source-layout.md`
- 文档维护规则：`quality-and-doc-maintenance.md`

## 记录系统规则

- `README.md` 负责外部概览和最小入口。
- `AGENTS.md` 只做短地图，不承载完整事实。
- `docs/` 才是受版本控制的事实记录系统。
- 每个 crate 都必须有自己的 `docs/docs-system-map.md`、`docs/architecture/system-boundaries.md`、`docs/architecture/source-layout.md`。
- `site/`、`target/` 这类生成物不能当作事实来源。

## Workspace 级文档

- `workspace-crate-boundaries.md`
  - 定义 crate 之间的职责边界与放置规则。
- `source-layout.md`
  - 说明 workspace 根目录和各 crate 的入口位置。
- `quality-and-doc-maintenance.md`
  - 规定文档维护、AGENTS 长度和机械校验要求。
- `unsafe-boundary-adr.md`
  - 记录 workspace 对 `unsafe` 边界的结构化约束。

## Crate 级文档

- `crates/omne-artifact-install-primitives/docs/docs-system-map.md`
- `crates/omne-archive-primitives/docs/docs-system-map.md`
- `crates/omne-execution-gateway/docs/docs-system-map.md`
- `crates/omne-fs/docs/docs-system-map.md`
- `crates/omne-fs-primitives/docs/docs-system-map.md`
- `crates/omne-host-info-primitives/docs/docs-system-map.md`
- `crates/omne-integrity-primitives/docs/docs-system-map.md`
- `crates/omne-process-primitives/docs/docs-system-map.md`
- `crates/omne-system-package-primitives/docs/docs-system-map.md`

嵌套 workspace package 如果仍落在某个现有 crate 边界内，例如 `crates/omne-fs/cli`，继续
沿用父边界的文档系统，不单独复制一套顶层 crate docs skeleton。

## 维护要求

- 新增 crate 时，同步补齐该 crate 的文档系统骨架。
- crate 目录职责变化时，先更新 crate 自己的边界文档，再更新 workspace 边界文档。
- 不把评审聊天、Slack 决策或口头约定当作长期知识存放处。
- 文档系统骨架由 `../scripts/check-docs-system.sh` 机械校验。
