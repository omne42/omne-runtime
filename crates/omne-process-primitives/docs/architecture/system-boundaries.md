# 系统边界

## 目标

`omne-process-primitives` 提供无策略的宿主机命令与进程生命周期原语，供上层 runtime 和 domain caller 复用。

## 负责什么

- 探测命令是否存在和是否可执行。
- 对宿主命令 request/recipe 维持 `OsStr` / `OsString` 边界，不把 argv/env 先强制收窄成 UTF-8 `String`。
- 运行宿主机命令并捕获输出；捕获实现以临时文件为边界，因此 direct child 退出后不会再被继续持有 stdout/stderr 的后台后代进程永久卡住；当 stdout/stderr 超过上限时，仍在读取完整捕获后返回超限错误。
- 对显式相对程序路径保持调用方 cwd 语义，不会因为 request 同时设置了 `working_directory` 就把同一个程序路径重新解释到另一个目录。
- `command_exists_for_request` / `command_available_for_request` 在 bare command 上会沿用 request 显式覆盖的 `PATH`，但对显式相对程序路径仍保持与执行路径相同的调用方 cwd 语义。
- `command_available` / `command_available_os` / `command_available_for_request` 只会把真正可执行的命令视为 available，不会把普通文件或缺少执行位的路径伪装成“已可运行”。
- direct 显式路径 spawn 如果返回 `ENOENT`，只有在解析后的目标路径确实不存在时才会折叠成 `CommandNotFound`；如果目标文件仍在，本 crate 会保留原始 spawn 失败，让缺失 shebang 解释器或动态 loader 这类问题不会被误报成“命令不存在”。
- 当命中 `sudo` 路径时，把调用方显式提供的环境变量改写成 `env -- KEY=VALUE ...` 形式并放到提权后的目标命令边界内，但 request `PATH` override 会在 sudo 边界被丢弃，避免在 root 目标命令上重新引入调用方的搜索路径。
- `sudo` 可用性判定、`sudo` 可执行路径选择以及提权后的 bare target 解析都不使用 request 里显式覆盖的 `PATH` 来决定提权边界；auto-sudo 只允许 canonical system package manager 命令，并且 bare target 必须能从宿主机环境解析到对应 manager 二进制。
- 对需要走 `sudo` 的 bare command，如果宿主机环境里解析不到对应的 canonical manager 二进制，会在真正调用 `sudo` 之前返回 `CommandNotFound`。
- 对显式 package-manager 路径，只有它与宿主机对该 manager 名称解析到的 canonical 二进制是同一个文件时，才保留 `IfNonRootSystemCommand` 语义；相对路径、别名到不同目标的 symlink，或名字相同但不是宿主机 canonical manager 的其他可执行体都不会被误判成系统命令。
- 运行 host recipe，并把非零退出统一建模成结构化错误。
- `HostRecipeError::Display` 只输出退出状态和捕获字节数，不把完整 stdout/stderr 直接拼进错误字符串；需要原始输出的调用方仍可从结构化 `Output` 读取。
- 基于 `omne-system-package-primitives` 的 canonical manager 目录为系统包命令提供默认 `sudo` 模式选择，避免并行维护两份 manager 名称表。
- Unix 下对 bare system command 做 `sudo -n` 试探。
- 配置子进程以支持进程树清理；如果子进程没有被放进独立进程组，cleanup capture 会 fail-closed。
- 捕获进程树清理标识并执行 best-effort 终止。
- Windows 下先等待 `taskkill /T /F` 的真实退出结果；只有它失败时才回退到 descendant sweep。
- Unix 上一旦无法重新验证原始 leader 身份，默认停止继续对该 process-group 做 `killpg`；但 Linux 会在 `/proc` 中继续回扫同 session 的残留成员，因此即使 leader 在 cleanup capture 之后退出，仍能清理原 process-group 里的 orphan descendants，同时对“capture 时已丢失 leader 身份且 cleanup 时 leader PID 已被复用”的情况继续 fail closed。leader 的 `start_ticks` 和 `session_id` 也必须来自同一次 `/proc/<pid>/stat` 读取，避免把不同进程生命周期的字段拼成伪身份。

## 不负责什么

- 命令 allowlist。
- 超时、取消或重试策略。
- 环境变量过滤。
- stdout/stderr 的产品级脱敏、裁剪或持久化策略；这里仅避免在默认 `Display` 中直接倾倒完整捕获内容。
- sandbox / isolation 选择。
- 产品级错误码映射。

## 调用方边界

- 上层调用方负责决定何时执行命令以及失败后如何处理。
- 如果调用方需要跨平台可移植的 env 名约束或更高层过滤规则，应在自己边界处理；这里保留宿主原生字符串。
- 这里不拥有产品级安全策略。
