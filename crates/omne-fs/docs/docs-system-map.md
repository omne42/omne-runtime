# omne-fs Docs System

## Start Here

- 外部概览：`../README.md`
- 执行者地图：`../AGENTS.md`
- 文档门户：`index.md`
- 边界说明：`architecture/system-boundaries.md`
- 源码布局：`architecture/source-layout.md`
- workspace 边界：`../../../docs/workspace-crate-boundaries.md`

## 文档分工

- `README.md`
  - 对外概览、快速开始和最小验证。
- `AGENTS.md`
  - 短地图，不承载完整事实。
- `docs/index.md`
  - 面向调用方的文档门户。
- `docs/architecture/system-boundaries.md`
  - `omne-fs` 与 `omne-fs-primitives`、`omne-process-primitives` 等 sibling crate 的边界。
- `docs/architecture/source-layout.md`
  - 核心源码目录、CLI、tests、scripts 和 githooks 的布局说明。

## 现有文档入口

- `getting-started.md`
  - 初次接入和快速上手。
- `concepts.md` / `policy-reference.md`
  - 策略模型和字段语义。
- `operations-reference.md` / `library-reference.md` / `cli-reference.md`
  - API 与操作面说明。
- `security-guide.md`
  - 安全边界与威胁模型。

## 维护规则

- 不把长流程、一次性决策或角色扮演继续堆进 `AGENTS.md`。
- 策略边界变化时，先更新 architecture 文档，再更新 reference 文档。
- 新增 `src/ops/*`、`src/platform/*` 或 `cli/` 结构变化时，更新源码布局文档。

## Verify

- `cargo test -p omne-fs`
- `../../../scripts/check-docs-system.sh`
