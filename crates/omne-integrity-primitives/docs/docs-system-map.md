# omne-integrity-primitives Docs System

## Start Here

- 外部概览：`../README.md`
- 执行者地图：`../AGENTS.md`
- 边界说明：`architecture/system-boundaries.md`
- 源码布局：`architecture/source-layout.md`
- workspace 边界：`../../../docs/workspace-crate-boundaries.md`

## 文档分工

- `README.md`
  - 对外概览与最小验证。
- `AGENTS.md`
  - 短地图。
- `docs/architecture/system-boundaries.md`
  - 摘要与校验职责边界。
- `docs/architecture/source-layout.md`
  - 源码职责说明。

## 维护规则

- 如果新增摘要算法或 reader 校验入口，同步更新边界文档。
- 下载和来源选择逻辑不应下沉到这里。

## Verify

- `cargo test -p omne-integrity-primitives`
- `../../../scripts/check-docs-system.sh`
