# omne-system-package-primitives Docs System

## Start Here

- 外部概览：`../README.md`
- 执行者地图：`../AGENTS.md`
- 边界说明：`architecture/system-boundaries.md`
- 源码布局：`architecture/source-layout.md`
- workspace 边界：`../../../docs/workspace-crate-boundaries.md`

## 文档分工

- `README.md`
  - 对外概览和最小验证。
- `AGENTS.md`
  - 短地图。
- `docs/architecture/system-boundaries.md`
  - 包管理器识别与 recipe 原语边界。
- `docs/architecture/source-layout.md`
  - 源码职责说明。

## 维护规则

- 若新增包管理器或默认 recipe 顺序，同步更新边界文档。
- 进程执行或产品级计划语义不应下沉到这里。

## Verify

- `cargo test -p omne-system-package-primitives`
- `../../../scripts/check-docs-system.sh`
