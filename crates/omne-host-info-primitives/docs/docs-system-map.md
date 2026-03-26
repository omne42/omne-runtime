# omne-host-info-primitives Docs System

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
  - 宿主识别与 target triple 原语边界。
- `docs/architecture/source-layout.md`
  - 源码职责说明。

## 维护规则

- 宿主识别、target triple、home 目录相关规则变化时，同步更新边界文档。
- 产品级目录策略不能写进这个 crate 的职责说明。

## Verify

- `cargo test -p omne-host-info-primitives`
- `../../../scripts/check-docs-system.sh`
