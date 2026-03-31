# 系统边界

## 目标

`omne-execution-gateway` 提供统一的命令执行边界，让调用方通过一致的 request/policy/audit 模型执行第三方命令，并在隔离能力不足时 fail-closed。

## 负责什么

- `ExecRequest`、`ExecEvent`、`ExecGateway`、`GatewayPolicy` 和能力报告模型。
- `cwd`、`workspace_root`、隔离级别和 `policy_default` 来源一致性校验。
- 请求里的 `program` 只能是 bare command name 或绝对路径；像 `./tool`、`bin/tool` 这类相对路径会 fail-closed 拒绝，避免执行语义依赖 gateway 进程自身的工作目录。
- 对显式绝对 `program` 路径做 file identity 绑定，并在真正 spawn 前再次校验；bare command name 也会在 preflight 阶段解析成绝对可执行文件路径并绑定 identity，如果无法稳定解析就 fail-closed 拒绝。mutating allowlist 仍按最终可执行文件 identity 匹配，而不是按 basename 或原始路径字面量放行，避免 preflight 通过后被换文件或通过稳定别名漂移到别的可执行文件；但在最终 revalidate 到内核 `spawn/exec` 之间仍存在无法完全消除的 OS 级 TOCTOU 窗口，这里只承诺尽量缩小而不是假装消灭它。
- 对 `cwd` / `workspace_root` 做 canonical path + 目录 identity 绑定，并在真正 spawn 前重新校验。
- 声明式变更命令门控，以及显式 mutation declaration、`mutating_program_allowlist` / `non_mutating_program_allowlist`、opaque launcher 和 known mutator 之间的一致性校验。
- gateway 自己管理的 spawn 路径会把子进程 `stdin/stdout/stderr` 绑定到空句柄，避免执行边界意外退化成交互式命令会话或把输出直接泄漏回调用方终端。
- 平台 sandbox 编排与 runtime 观测。
- 结构化审计事件和日志输出，包括可读的 lossy `program` / `args` / `env` 字段，以及面向机器恢复的 exact OS-string 编码字段。allowlist、opaque launcher 和 known mutator 门控本身继续保持在原生 `OsStr` / `Path` 边界，不先把请求收窄成 lossy UTF-8。
- policy / request / audit log 的 bounded regular-file 读取与 appendable-file 校验现在直接复用 `omne-fs-primitives` 的 ambient-root no-follow helper，而不是在 gateway 本地复制一套文件系统原语。

当前平台语义补充：

- Linux、macOS 和 Windows 当前都只报告 `None` 为受支持隔离级别。
- Linux 原生 sandbox 暂时下线，直到能在不依赖 post-`fork` unsafe Rust 执行的前提下重新引入。
- 当请求的隔离级别高于宿主报告能力时，gateway 必须 fail-closed 拒绝，而不是回退到未隔离执行。
- mutating allowlist 只授权显式程序路径；bare program name 因为无法绑定稳定可执行文件而 fail-closed 拒绝。
- 对 bare command 的普通执行路径，audit / `request_resolution` / `ExecEvent` 记录的是 gateway 解析并绑定后的绝对执行体路径，而不是原始 bare token。
- `prepare_command()` 只接受与 gateway 已解析执行体一致的 `Command` 程序路径；如果调用方仍传 bare command name，会以 `prepared_command_mismatch` fail-closed 拒绝。
- 当 `enforce_allowlisted_program_for_mutation=true` 时，所有请求都必须显式声明 `declared_mutation`；否则 gateway 会以 `mutation_declaration_required` fail-closed 拒绝。
- 当 `enforce_allowlisted_program_for_mutation=true` 时，`declared_mutation=true` 的请求必须绑定到 `mutating_program_allowlist` 里的显式程序路径；`declared_mutation=false` 的请求也必须绑定到 `non_mutating_program_allowlist` 里的显式程序路径，避免“未知 mutator 只要自称只读就能绕过”。
- 当 `enforce_allowlisted_program_for_mutation=true` 时，已知高风险 mutator/toolchain（例如 `git`、`make`、包管理器和核心文件变更命令）以及 opaque launcher/interpreter（例如 `sh`、`python`、`node`）不能宣称 `declared_mutation=false`；调用方必须显式声明 mutation 并跨过 mutating allowlist 边界。
- Windows 上命令路径和 workspace 边界比较按平台语义做大小写不敏感处理，不要求调用方传入与文件系统完全同大小写的字面量。
- `GatewayPolicy::load_json()` 只接受通过 descriptor-backed 祖先目录 no-follow walk 打开的 regular file；祖先 symlink/reparse point、目录或其他特殊文件都会 fail-closed 拒绝。
- `omne-execution` CLI 的 `request.json` 也只接受同样的 bounded no-follow regular file 输入，避免通过祖先 symlink、特殊文件或超大输入把 CLI 边界退化成非确定性文件读取；其中 `program` / `args` / `env` 既可以用普通 UTF-8 JSON string，也可以用 exact OS-string 编码对象保留非 UTF-8 输入。
- 缺失、不可访问或不是目录的 `cwd` 会被报告为 `cwd_invalid`，避免把普通输入/环境错误误记成 workspace 越界。
- `ExecRequest` 的显式环境变量现在属于 request/audit 契约的一部分；`execute()` 和 `prepare_command()` 在 spawn 前都会清空继承环境，只注入 request 声明过的 env，避免调用方用未审计的 `PATH`、`LD_PRELOAD`、`PYTHONPATH` 等变量偷偷改变执行语义。
- 配置了 `audit_log_path` 时，`evaluate()` / `resolve_request()` / `preflight()` 保持纯评估，不提前创建日志目录或文件；真正的 audit sink 准备只在 `execute()` / `prepare_command()` 前发生，并继续通过 descriptor-backed no-follow walk 拒绝祖先 symlink/reparse point 或其他不安全路径。
- mutating allowlist 对显式程序路径除了 file identity 绑定外，还会在 preflight 记录内容指纹，并在真正 spawn 前再次校验，防止同 inode 的原地改写绕过 allowlist。
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
