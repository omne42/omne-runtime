# 系统边界

## 目标

`omne-process-primitives` 提供无策略的宿主机命令与进程生命周期原语，供上层 runtime 和 domain caller 复用。

## 负责什么

- 探测命令是否存在和是否可执行。
- 运行宿主机命令并捕获输出。
- 当命中 `sudo` 路径时，把调用方显式提供的环境变量通过 `sudo --preserve-env=...` 继续传给目标命令。
- `sudo` 可用性判定和 `sudo` 可执行路径选择遵循同一份有效 `PATH`（优先采用调用方在请求里显式覆盖的 `PATH`）。
- 运行 host recipe，并把非零退出统一建模成结构化错误。
- 为常见系统包命令提供默认 `sudo` 模式选择。
- Unix 下对 bare system command 做 `sudo -n` 试探。
- 配置子进程以支持进程树清理。
- 捕获进程树清理标识并执行 best-effort 终止。
- Windows 下先等待 `taskkill /T /F` 的真实退出结果；只有它失败时才回退到 descendant sweep。
- 在非 Linux Unix 上，当原始 leader 已退出时对 orphan process-group 清理 fail-closed，避免仅凭复用 PGID 误杀无关进程。

## 不负责什么

- 命令 allowlist。
- 超时、取消或重试策略。
- 环境变量过滤。
- stdout/stderr 的产品级脱敏、裁剪或持久化策略。
- sandbox / isolation 选择。
- 产品级错误码映射。

## 调用方边界

- 上层调用方负责决定何时执行命令以及失败后如何处理。
- 这里不拥有产品级安全策略。
