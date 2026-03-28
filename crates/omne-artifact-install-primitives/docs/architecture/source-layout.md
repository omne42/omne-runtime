# 源码布局

## 入口

- `src/lib.rs`
  - crate 入口与公开导出。

## 主要模块

- `src/artifact_download.rs`
  - 下载候选模型、下载错误分类和受限响应体下载执行。
- `src/binary_artifact.rs`
  - direct binary 原子安装与 binary-from-archive 安装。
- `src/archive_tree.rs`
  - archive tree 解包、budget/link 校验和目录树安装编排。

## 布局规则

- 下载候选执行与安装语义放在这里，不回流到产品仓库。
- 纯 archive 读取匹配逻辑继续留在 `omne-archive-primitives`。
- 产品级 release/schema/source policy 不进入这个 crate。
