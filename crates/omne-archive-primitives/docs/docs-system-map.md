# omne-archive-primitives Docs System

## Start Here

- 外部概览：`../README.md`
- 执行者地图：`../AGENTS.md`
- 边界说明：`architecture/system-boundaries.md`
- 源码布局：`architecture/source-layout.md`
- workspace 边界：`../../../docs/workspace-crate-boundaries.md`

## 文档分工

- `README.md`
  - 对外概览、scope 和最小验证。
- `AGENTS.md`
  - 给执行者的短地图，不承载完整事实。
- `docs/architecture/system-boundaries.md`
  - 记录这个 crate 负责什么、不负责什么。
- `docs/architecture/source-layout.md`
  - 记录源码文件职责。

## 维护规则

- 新增 archive 格式、匹配策略或公共 API 时，先更新边界文档。
- 新增源码文件或文件职责变化时，更新源码布局文档。
- 不把文件落盘、下载或来源策略写进这里的职责说明。

## Verify

- `cargo test -p omne-archive-primitives`
- `../../../scripts/check-docs-system.sh`
