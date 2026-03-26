# omne-execution-gateway Docs System

## Start Here

- 外部概览：`../README.md`
- 执行者地图：`../AGENTS.md`
- 文档门户：`index.md`
- 边界说明：`architecture/system-boundaries.md`
- 源码布局：`architecture/source-layout.md`
- workspace 边界：`../../../docs/workspace-crate-boundaries.md`

## 文档分工

- `README.md`
  - 对外概览、核心保证和最小用法。
- `AGENTS.md`
  - 短地图，不承载完整事实。
- `docs/index.md`
  - 面向用户和调用方的门户入口。
- `docs/architecture/system-boundaries.md`
  - gateway、audit、sandbox 的职责边界。
- `docs/architecture/source-layout.md`
  - 源码和二进制入口布局。

## 现有文档入口

- `getting-started/`
  - 快速开始和集成入门。
- `guides/`
  - policy、isolation、audit 和安全说明。
- `reference/`
  - API、CLI 和治理说明。

## 维护规则

- `site/` 不是记录系统，它只是生成站点输出。
- sandbox 语义变化时，先更新边界文档，再更新 guide/reference。
- 新增 `src/bin/*` 或 `src/sandbox/*` 文件时，同步更新源码布局文档。

## Verify

- `cargo test -p omne-execution-gateway`
- `../../../scripts/check-docs-system.sh`
