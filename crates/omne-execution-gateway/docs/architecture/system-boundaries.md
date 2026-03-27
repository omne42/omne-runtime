# 系统边界

## 目标

`omne-execution-gateway` 提供统一的命令执行边界，让调用方通过一致的 request/policy/audit 模型执行第三方命令，并在隔离能力不足时 fail-closed。

## 负责什么

- `ExecRequest`、`ExecEvent`、`ExecGateway`、`GatewayPolicy` 和能力报告模型。
- `cwd`、`workspace_root`、隔离级别和 `policy_default` 来源一致性校验。
- 声明式变更命令门控，以及 allowlisted mutator、`declared_mutation` 和 opaque launcher 之间的一致性校验。
- 平台 sandbox 编排与 runtime 观测。
- 结构化审计事件和日志输出。

当前平台语义补充：

- Linux 可以报告并尝试执行 `BestEffort` / `Strict`。
- macOS 和 Windows 当前只报告 `None` 为受支持隔离级别。
- 当请求的隔离级别高于宿主报告能力时，gateway 必须 fail-closed 拒绝，而不是回退到未隔离执行。

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
