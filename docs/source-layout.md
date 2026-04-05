# Workspace Source Layout

## Top Level

- `Cargo.toml`
  - Workspace 成员与默认成员入口。
- `../omne_foundation`
  - 当前构建图要求存在的 sibling foundation checkout；提供 `http-kit`、`policy-meta`
    等 path dependency，不属于本仓库记录系统但属于本仓库的 build prerequisite。
- `README.md`
  - 外部概览与最小验证命令。
- `AGENTS.md`
  - workspace 级短地图。
- `docs/`
  - workspace 级记录系统。
- `scripts/`
  - workspace 级机械校验脚本。
- `.github/workflows/`
  - CI、发布和 Pages 流程定义。

## Crates

- `crates/omne-artifact-install-primitives`
  - 制品下载、SHA 校验、binary 安装与 archive-tree 安装编排原语。
- `crates/omne-archive-primitives`
  - 归档格式识别、条目遍历、archive tree walker 和目标二进制提取原语。
- `crates/omne-execution-gateway`
  - 命令执行边界、隔离语义、审计和 sandbox 编排。
- `crates/omne-fs`
  - 文件系统策略层、高层操作和 CLI。
- `crates/omne-fs/cli`
  - 嵌套 workspace package，承载 `omne-fs-cli` 二进制入口；它属于 `omne-fs` 边界，不是新的 sibling capability crate。
- `crates/omne-fs-primitives`
  - 低层文件系统原语，如 no-follow open、bounded read、atomic file/directory replace。
- `crates/omne-host-info-primitives`
  - 宿主平台识别、target triple、home 目录和可执行后缀原语。
- `crates/omne-integrity-primitives`
  - 摘要解析、哈希计算和校验原语。
- `crates/omne-process-primitives`
  - 宿主机命令/recipe 执行、默认 `sudo` 模式推断、`sudo -n` 试探和进程树清理原语。
- `crates/omne-system-package-primitives`
  - 包管理器归一化和安装 recipe 原语。

## Layout Rules

- workspace 根只放跨 crate 的导航、规则和机械校验。
- 本仓库的 Rust 构建不是孤立的；凡是运行 `cargo check/test/clippy` 的入口，都默认
  相邻目录下已有 `../omne_foundation`。
- 具体能力事实优先沉到对应 crate 的本地 docs 系统。
- 每个 crate 的文件名必须能直接表达职责，不新增 `misc`、`helpers` 之类兜底名字。
- 生成物目录不是记录系统的一部分。
