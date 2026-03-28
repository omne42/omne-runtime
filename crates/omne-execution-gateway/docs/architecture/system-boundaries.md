# 系统边界

## 目标

`omne-execution-gateway` 提供统一的命令执行边界，让调用方通过一致的 request/policy/audit 模型执行第三方命令，并在隔离能力不足时 fail-closed。

## 负责什么

- `ExecRequest`、`ExecEvent`、`ExecGateway`、`GatewayPolicy` 和能力报告模型。
- `cwd`、`workspace_root`、隔离级别和 `policy_default` 来源一致性校验。
- 对 `cwd` / `workspace_root` 做 canonical path + 目录 identity 绑定，并在真正 spawn 前重新校验。
- 声明式变更命令门控，以及 allowlisted mutator、`declared_mutation` 和 opaque launcher 之间的一致性校验。
- 平台 sandbox 编排与 runtime 观测。
- 结构化审计事件和日志输出。

当前平台语义补充：

- Linux、macOS 和 Windows 当前都只报告 `None` 为受支持隔离级别。
- Linux 原生 sandbox 暂时下线，直到能在不依赖 post-`fork` unsafe Rust 执行的前提下重新引入。
- 当请求的隔离级别高于宿主报告能力时，gateway 必须 fail-closed 拒绝，而不是回退到未隔离执行。
- mutating allowlist 只授权显式程序路径；bare program name 因为无法绑定稳定可执行文件而 fail-closed 拒绝。
- Windows 上命令路径和 workspace 边界比较按平台语义做大小写不敏感处理，不要求调用方传入与文件系统完全同大小写的字面量。
- 配置了 `audit_log_path` 时，gateway 会在 preflight 阶段创建缺失父目录并验证日志可追加；如果审计日志不可用，请求必须 fail-closed 拒绝，而不是在无审计记录下继续执行。
- 如果 preflight 之后的最终审计写入失败，gateway 会把结果显式返回给调用方，而不是只在 stderr 打印失败后继续返回成功。

## 不负责什么

- 高层文件系统读写 API。
- `omne-fs` CLI 语义。
- 通用进程树原语。
- 产品层超时、取消和保密策略。
- 二进制来源或供应链校验。

## 本地保留的边界

- `src/sandbox/*` 仍然属于 gateway 自己的执行编排边界，不是独立 shared primitive crate。
- `site/` 是生成产物，不是事实来源。

## 调用方边界

- 调用方负责决定何时发起请求、怎样解释结果。
- gateway 负责统一执行边界，而不是替调用方提供所有本地工具 API。
