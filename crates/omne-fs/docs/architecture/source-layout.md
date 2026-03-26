# 源码布局

## 顶层入口

- `src/lib.rs`
  - crate 入口与公开导出。
- `cli/`
  - `omne-fs-cli` crate，负责 CLI 入口与参数处理。

## 核心源码目录

- `src/policy.rs`
  - 策略模型和字段语义。
- `src/redaction.rs`
  - 输出 redaction 与 secret 相关辅助。
- `src/error.rs`
  - 错误类型。
- `src/path_utils.rs`
  - 共享路径工具。
- `src/policy_io.rs`
  - policy 文件加载与解析。

## 高层操作

- `src/ops/context.rs`
  - `Context` 和操作入口装配。
- `src/ops/read.rs`、`write.rs`、`edit.rs`、`patch.rs`
  - 文本与文件修改操作。
- `src/ops/delete.rs`、`mkdir.rs`、`copy_file.rs`、`move_path.rs`
  - 变更类文件系统操作。
- `src/ops/list_dir.rs`、`glob.rs`、`grep.rs`、`stat.rs`
  - 查询类操作。
- `src/ops/resolve.rs`、`path_validation.rs`、`traversal.rs`、`io.rs`、`transfer.rs`
  - 高层操作共享的路径解析、遍历和 I/O 适配。

## 平台与测试

- `src/platform/*`
  - 平台相关文件系统辅助。
- `tests/`
  - 按行为划分的集成测试。
- `scripts/`
  - 质量门禁和本地开发辅助。
- `githooks/`
  - 提交阶段钩子脚本。

## 布局规则

- `docs/` 才是事实记录系统，`AGENTS.md` 只保留地图。
- 新增操作文件时，文件名必须直接表达操作职责。
