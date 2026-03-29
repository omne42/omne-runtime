# 系统边界

## 目标

`omne-execution-gateway` 提供统一的命令执行边界，让调用方通过一致的 request/policy/audit 模型执行第三方命令，并在隔离能力不足时 fail-closed。

## 负责什么

- `ExecRequest`、`ExecEvent`、`ExecGateway`、`GatewayPolicy` 和能力报告模型。
- `cwd`、`workspace_root`、隔离级别和 `policy_default` 来源一致性校验。
- 请求里的 `program` 只能是 bare command name 或绝对路径；像 `./tool`、`bin/tool` 这类相对路径会 fail-closed 拒绝，避免执行语义依赖 gateway 进程自身的工作目录。
- 对显式绝对 `program` 路径做 file identity 绑定，并在真正 spawn 前再次校验；mutating allowlist 也按最终可执行文件 identity 匹配，而不是按 basename 或原始路径字面量放行，避免 preflight 通过后被换文件或通过稳定别名漂移到别的可执行文件。
- 对 `cwd` / `workspace_root` 做 canonical path + 目录 identity 绑定，并在真正 spawn 前重新校验。
- 声明式变更命令门控，以及显式 mutation declaration、allowlisted mutator 和 opaque launcher 之间的一致性校验。
- gateway 自己管理的 spawn 路径会把子进程 `stdin/stdout/stderr` 绑定到空句柄，避免执行边界意外退化成交互式命令会话或把输出直接泄漏回调用方终端。
- 平台 sandbox 编排与 runtime 观测。
- 结构化审计事件和日志输出。

当前平台语义补充：

- Linux、macOS 和 Windows 当前都只报告 `None` 为受支持隔离级别。
- Linux 原生 sandbox 暂时下线，直到能在不依赖 post-`fork` unsafe Rust 执行的前提下重新引入。
- 当请求的隔离级别高于宿主报告能力时，gateway 必须 fail-closed 拒绝，而不是回退到未隔离执行。
- mutating allowlist 只授权显式程序路径；bare program name 因为无法绑定稳定可执行文件而 fail-closed 拒绝。
- 当 `enforce_allowlisted_program_for_mutation=true` 时，所有请求都必须显式声明 `declared_mutation`；否则 gateway 会以 `mutation_declaration_required` fail-closed 拒绝。
- Windows 上命令路径和 workspace 边界比较按平台语义做大小写不敏感处理，不要求调用方传入与文件系统完全同大小写的字面量。
- `GatewayPolicy::load_json()` 只接受 no-follow regular file 输入，不会把 symlink、目录或其他特殊文件当成可信策略文件读取。
- `omne-execution` CLI 的 `request.json` 也只接受 bounded no-follow regular file 输入，避免通过 symlink、特殊文件或超大输入把 CLI 边界退化成非确定性文件读取。
- 缺失、不可访问或不是目录的 `cwd` 会被报告为 `cwd_invalid`，避免把普通输入/环境错误误记成 workspace 越界。
- 配置了 `audit_log_path` 时，gateway 会在 preflight 阶段逐层创建缺失父目录、拒绝任何 symlink/special-file 祖先，并验证日志可追加；如果审计日志不可用，请求必须 fail-closed 拒绝，而不是在无审计记录下继续执行。
- 如果 preflight 之后的最终审计写入失败，gateway 会把结果显式返回给调用方，而不是只在 stderr 打印失败后继续返回成功。

## 不负责什么

- 高层文件系统读写 API。
- `omne-fs` CLI 语义。
- 通用进程树原语。
- 交互式终端桥接或输出捕获适配。
- 产品层超时、取消和保密策略。
- 二进制来源或供应链校验。

## 本地保留的边界

- `src/sandbox/*` 仍然属于 gateway 自己的执行编排边界，不是独立 shared primitive crate。
- `site/` 是生成产物，不是事实来源。

## 调用方边界

- 调用方负责决定何时发起请求、怎样解释结果。
- gateway 负责统一执行边界，而不是替调用方提供所有本地工具 API。
