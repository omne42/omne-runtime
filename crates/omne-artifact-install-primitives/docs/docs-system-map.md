# omne-artifact-install-primitives Docs System

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
  - artifact 下载与安装原语的职责边界。
- `docs/architecture/source-layout.md`
  - 源码职责说明。

## 维护规则

- GitHub release DTO、镜像优先级和产品级来源策略不应下沉到这里。
- 新增 artifact 安装模式时，同步更新边界和源码布局文档。

## Verify

- `cargo test -p omne-artifact-install-primitives`
- `../../../scripts/check-docs-system.sh`
