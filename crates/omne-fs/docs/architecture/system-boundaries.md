# 系统边界

## 目标

`omne-fs` 提供面向工具和调用方的高层文件系统策略层：它解释 `SandboxPolicy`，并把策略应用到 read/write/edit/delete/glob/grep 等高层文件操作上。

## 负责什么

- `SandboxPolicy`、`Context`、root/path/permission/limit/secret 语义。
- 高层文件系统 request/response 模型。
- `read`、`write`、`edit`、`patch`、`delete`、`list_dir`、`glob`、`grep`、`stat`、`mkdir`、`copy`、`move`。
- policy I/O、CLI 和相关集成测试。
- 输出 redaction 与 secret deny 逻辑。
- `git-permissions` fallback 的授权探测和状态检查；这些 probe 只允许使用受信任的 `git`
  路径和清洗后的环境，失败时也不能把原始 git stderr/stdout 泄漏回父进程输出。
- 对会创建或替换路径的写操作，重校验父目录/源对象身份；无法可靠验证时 fail-closed，而不是降级成 best-effort 成功。
- policy I/O 读取也保持 ancestor-safe no-follow 边界：既拒绝最终叶子是 symlink/reparse，也拒绝父目录链通过 symlink/reparse 重定向。

## 不负责什么

- descriptor/handle 级 no-follow open 原语。
- 无策略 bounded read、atomic write 或 advisory lock 原语。
- 通用进程清理机制。
- OS 强制 sandbox。

## 相邻边界

- `omne-fs-primitives`
  - 持有低层文件系统原语。
- `omne-process-primitives`
  - 持有宿主机命令与进程树原语，不属于 `omne-fs`。
- workspace 根 docs
  - 持有跨 crate 的边界规则，而不是 `omne-fs` 自己的行为事实。

## 调用方边界

- 调用方依赖 `omne-fs` 的稳定策略语义和操作面。
- 调用方也依赖 mutating 路径在 post-resolution 身份无法再次验证时 fail closed，而不是把
  “已校验” 降级成 best-effort。
- 调用方不应复制 secret/redaction/root 边界逻辑到自己仓库。
