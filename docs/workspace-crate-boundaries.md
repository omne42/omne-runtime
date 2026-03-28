# Workspace Crate 边界说明

## 目的

本文说明这个 workspace 中九个 runtime crate 的职责划分：

- `crates/omne-artifact-install-primitives`
- `crates/omne-archive-primitives`
- `crates/omne-execution-gateway`
- `crates/omne-fs`
- `crates/omne-fs-primitives`
- `crates/omne-host-info-primitives`
- `crates/omne-integrity-primitives`
- `crates/omne-process-primitives`，对应 package 名为 `omne-process-primitives`
- `crates/omne-system-package-primitives`

这份文档把现有 ADR 的结论汇总成一份 workspace 级说明，方便后续新增代码时快速判断该放在哪里。

命名规则也一并固定下来：统一采用 `omne-<能力/边界>`，用 `-primitives`、`-gateway`
这类后缀表达层级和职责，不再重复 workspace 名本身；对外 package/crate 名避免引入新的
晦涩缩写，但像 `fs` 这样已被团队稳定使用、且一眼可识别领域的缩写可以保留；目录名与
package 名保持一致。

## 一屏模型

这里的边界是按能力划分，不是把“所有跨平台代码”堆到同一个地方。

```text
制品下载 / SHA 校验 / binary/tree 安装
  -> omne-artifact-install-primitives
       -> omne-archive-primitives
       -> omne-fs-primitives
       -> omne-integrity-primitives

归档 / 压缩格式读取与条目提取
  -> omne-archive-primitives

完整性 / 摘要解析与校验
  -> omne-integrity-primitives

宿主平台识别 / target triple / home 目录
  -> omne-host-info-primitives

系统包管理器识别 / install recipe 归一化
  -> omne-system-package-primitives

执行策略 / sandbox 编排
  -> omne-execution-gateway

文件系统策略 / 面向工具的高层操作
  -> omne-fs
       -> omne-fs-primitives

宿主机命令执行 / host recipe 执行 / 进程树清理原语
  -> omne-process-primitives
```

直接含义是：

- 不创建一个兜底式 `platform` crate。
- `omne-artifact-install-primitives` 负责 artifact 候选下载执行与安装管道，
  但不持有 release metadata 或候选顺序策略。
- `omne-archive-primitives` 负责 archive/compression 格式读取与条目提取，
  不和文件落盘或执行策略混放。
- `omne-fs` 是文件系统策略和工具层，不是所有 Unix/Windows 底层 helper 的归宿。
- `omne-host-info-primitives` 只放宿主平台与 home 目录这类 identity/helper，不扩展成兜底式 platform crate。
- `omne-integrity-primitives` 负责 digest 解析与校验，不和下载、release 元数据或安装编排混放。
- `omne-system-package-primitives` 负责 canonical package manager、枚举和 install recipe，不和命令执行或 plan 语义混放。
- `omne-execution-gateway` 负责执行决策和 sandbox 编排，但不负责通用进程生命周期策略。
- `omne-process-primitives` 是独立 sibling crate，不是 `omne-fs` 的子模块。

## 当前依赖方向

- `omne-fs` 依赖 `omne-fs-primitives`。
  证据见 `crates/omne-fs/Cargo.toml`、
  `crates/omne-fs/src/platform_open.rs`、
  `crates/omne-fs/src/ops/io.rs`。
- `omne-artifact-install-primitives` 依赖 `omne-archive-primitives`、
  `omne-fs-primitives`、`omne-integrity-primitives` 与 foundation 的 `http-kit`。
  它首先面向需要共享 artifact 下载 + 校验 + 落盘/解压安装管道的 sibling caller。
- `omne-execution-gateway` 当前不依赖另外七个 workspace crate。
  它直接依赖 `policy-meta`，并把平台相关 sandbox 代码保留在 `src/sandbox/*` 下。
- `omne-process-primitives` 是独立的 sibling crate，供需要通用命令探测、宿主机命令执行、host recipe 执行和进程树清理能力的下游 runtime 或 domain caller 直接依赖。
- `omne-archive-primitives` 当前也不被其他 runtime crate 依赖。
  它首先面向需要共享 archive/compression 提取能力的 sibling caller。
- `omne-host-info-primitives` 当前也不被其他 runtime crate 依赖。
  它首先面向需要共享宿主识别、home 目录解析与 target triple 映射能力的 sibling caller。
- `omne-integrity-primitives` 当前也不被其他 runtime crate 依赖。
  它首先面向需要共享摘要解析、内容哈希与校验能力的 sibling caller。
- `omne-system-package-primitives` 当前不依赖其他 runtime crate。
  它首先面向需要共享 canonical manager、默认 OS 级顺序和 install recipe 的 sibling caller。

也就是说，这个 workspace 现在是有意拆成“七类共享能力 crate”和“两类高层策略/编排 crate”。
随着 artifact install 管道进入 workspace，这个原则仍然不变：新增的是一个新的能力型
crate，不是新的兜底桶。

## 边界总表

| Crate | 负责什么 | 不负责什么 |
| --- | --- | --- |
| `omne-artifact-install-primitives` | 无产品策略的 artifact 安装管道：下载候选执行、可选 SHA-256 校验、direct binary 原子落盘、binary-from-archive 安装、archive-tree 预算/link 校验与 staged directory replace 编排 | GitHub release 元数据、候选顺序策略、产品目录布局、领域错误码、CLI |
| `omne-archive-primitives` | 无策略的 archive/compression 能力：`.tar.gz`、`.tar.xz`、`.zip` 识别，归档条目遍历，按精确 hint 或约定布局匹配目标二进制，提取目标二进制字节 | 文件写入、权限设置、原子替换、下载、来源校验、领域错误映射、CLI |
| `omne-execution-gateway` | 执行请求模型、隔离级别校验、`policy_default` 来源校验、执行时的 `workspace/cwd` 校验、声明式变更命令门控、sandbox 应用、审计事件与日志 | 文件系统操作策略、通用文件 API、`omne-fs` CLI 语义解析、超时/取消策略、stdout/stderr 保密策略、通用进程树清理原语 |
| `omne-fs` | 文件系统 `SandboxPolicy`、root/path/permission/limit/secret 语义、redaction、高层文件操作、CLI、policy I/O | 描述符级 no-follow open、通用 bounded-read 原语、进程清理、OS sandbox |
| `omne-fs-primitives` | 无策略的文件系统原语：root materialization、capability 风格目录访问、no-follow open、symlink/reparse 分类、bounded read、staged atomic file/directory replace、advisory lock | `SandboxPolicy`、alias-root 语义、权限决策、secret 处理、redaction、CLI |
| `omne-host-info-primitives` | 无策略的宿主信息原语：宿主 OS/arch 识别、canonical target triple 映射、target override 归一化、home 目录解析、目标可执行后缀推断 | `OMNE_DATA_DIR`/产品目录策略、包管理器适配、安装编排、CLI |
| `omne-integrity-primitives` | 无策略的完整性原语：`sha256:<hex>` 解析、原始 hex 输入解析、内容摘要计算与校验错误建模 | HTTP 下载、release 元数据、来源选择、安装编排、CLI |
| `omne-process-primitives` | 无策略的宿主机命令与进程原语：命令探测、带输出捕获的命令执行、host recipe 执行、默认 `sudo` 模式推断、Unix `sudo -n` 试探、process group、Linux `/proc` 身份校验、Windows Job Object、树形终止 helper | 命令 allowlist、环境变量过滤、超时/取消策略、领域错误映射、sandbox 选择 |
| `omne-system-package-primitives` | 无策略的系统包管理器原语：canonical manager 枚举与解析、install recipe 建模、按显式 OS 标识生成默认 recipe 顺序 | 进程执行、宿主机探测、plan method、tool/package 映射、领域错误码、CLI |

## `omne-artifact-install-primitives`

### 它负责什么

`omne-artifact-install-primitives` 是可复用的 artifact install building-block crate。

它负责：

- 消费调用方给定的有序下载候选
- 以受限响应体流式下载 artifact
- 对下载结果执行可选的 SHA-256 校验
- 把 direct binary asset 原子安装到目标路径
- 从受支持的 archive 中提取目标二进制并安装
- 把 archive tree 解到 `omne-fs-primitives` 提供的 staged 目录并在成功后替换目标目录

这些职责可以从下面这些文件直接看到：

- `crates/omne-artifact-install-primitives/src/lib.rs`
- `crates/omne-artifact-install-primitives/src/artifact_download.rs`
- `crates/omne-artifact-install-primitives/src/binary_artifact.rs`
- `crates/omne-artifact-install-primitives/src/archive_tree.rs`

### 它不负责什么

它不负责：

- GitHub release metadata 或 latest tag 选择
- `gateway|canonical|mirror` 的候选顺序策略
- 产品级目标目录布局或 tool/package 映射
- 领域错误码、结果 contract 或 CLI

判断原则同样简单：如果逻辑的核心是“把调用方给定的 artifact 候选变成本地已安装产物”，它属于这里；如果
逻辑的核心是“这个产品应该优先用哪个来源”或“安装结果怎样映射到产品 contract”，它不属于这里。

## `omne-archive-primitives`

### 它负责什么

`omne-archive-primitives` 是可复用的 archive/compression building-block crate。

它负责：

- 识别受支持的二进制归档格式，例如 `.tar.gz`、`.tar.xz`、`.zip`
- 遍历归档条目并统一归一化条目路径
- 按精确 `archive_binary` hint 或约定布局查找目标条目；`tool_name` 只用于少数已知 archive 布局特例
- 读取并返回匹配到的目标二进制字节

这些职责可以从下面这些文件直接看到：

- `crates/omne-archive-primitives/src/lib.rs`
- `crates/omne-archive-primitives/src/binary_archive.rs`

### 它不负责什么

它不负责：

- 下载 archive
- 校验来源、哈希或 release 元数据
- 创建目录、chmod、flush/sync、原子替换
- artifact 候选执行或 archive tree 目录替换
- 领域级安装错误映射
- CLI 或面向产品的 request/response 合约

判断原则同样简单：如果逻辑的核心是“理解归档格式并找到目标条目”，它属于这里；如果
逻辑的核心是“把目标二进制落到本地系统里”，它不属于这里。

## `omne-host-info-primitives`

### 它负责什么

`omne-host-info-primitives` 是可复用的宿主信息 building-block crate。

它负责：

- 识别当前宿主机是否是受支持的 `linux` / `macos` / `windows` 与 `x86_64` / `aarch64` 组合
- 把受支持的宿主组合映射到 canonical target triple
- 解析可选 target override，并在空值时回退到宿主 triple
- 解析当前用户的 home 目录
- 根据 target triple 推断目标可执行后缀，例如 Windows 的 `.exe`

这些职责可以从下面这些文件直接看到：

- `crates/omne-host-info-primitives/src/lib.rs`

### 它不负责什么

它不负责：

- `OMNE_DATA_DIR`、产品级目录布局或 `managed_dir` 规则
- 包管理器适配、下载策略或安装编排
- CLI 或领域错误映射

判断原则同样简单：如果逻辑的核心是“识别当前宿主机是谁、home 在哪里、目标二进制后缀是什么”，它属于这里；如果
逻辑的核心是“这个产品该把文件放到哪里、该怎样安装”，它不属于这里。

## `omne-integrity-primitives`

### 它负责什么

`omne-integrity-primitives` 是可复用的完整性 building-block crate。

它负责：

- 解析外部元数据中的 `sha256:<hex>` 值
- 解析调用方输入的原始 hex 或 prefixed digest
- 计算内容的 SHA-256 摘要
- 产出结构化的校验失败错误

这些职责可以从下面这些文件直接看到：

- `crates/omne-integrity-primitives/src/lib.rs`

### 它不负责什么

它不负责：

- 下载 HTTP 内容
- 拉取 release 元数据
- 来源优先级或镜像回退
- 安装计划、CLI 或领域错误映射

判断原则同样简单：如果逻辑的核心是“把字节变成 digest 并做校验”，它属于这里；如果
逻辑的核心是“从哪里拿到这些字节”或“拿到后怎样安装”，它不属于这里。

## `omne-execution-gateway`

### 它负责什么

`omne-execution-gateway` 是命令执行边界。

它负责：

- `ExecRequest`、`ExecEvent`、`ExecGateway`、`GatewayPolicy`、能力报告和审计记录
- 对 `program + args + cwd + workspace_root + required_isolation` 进行校验
- 对 `requested_isolation_source = policy_default` 的来源声明进行一致性校验
- 当请求的隔离级别超过宿主机支持能力时，采用 fail-closed 拒绝
- 通过文件系统工具 allowlist 对声明式变更命令做门控
- `crates/omne-execution-gateway/src/sandbox/*` 下的平台 sandbox 编排

这些职责可以直接从下面这些公开入口看到：

- `crates/omne-execution-gateway/src/lib.rs`
- `crates/omne-execution-gateway/src/gateway.rs`
- `crates/omne-execution-gateway/src/policy.rs`
- `crates/omne-execution-gateway/src/types.rs`

### 它不负责什么

它不负责：

- `read`、`write`、`patch`、`glob`、`grep` 这类高层文件系统操作
- `omne-fs` CLI flag/subcommand 的语法解析
- 文件系统 root、secret redaction、遍历限制这类文件系统策略语义
- 通用进程树清理 API
- 产品策略层的超时、取消、stderr 保密等决策
- 二进制来源校验

### 为什么 sandbox 代码现在留在本地

sandbox 安装本身就是执行编排的一部分，所以 `exec-gateway` 目前把平台相关 sandbox 逻辑留在 `src/sandbox/*` 下。

只有同时满足下面条件时，这部分代码才应该继续下沉为更低层 crate：

1. 被多个调用方复用
2. 无策略、无产品语义
3. 真的是可复用原语，而不是 gateway 专属的执行逻辑

在此之前，隔离能力探测和 sandbox 安装仍应由 `exec-gateway` 持有。

## `omne-fs`

### 它负责什么

`omne-fs` 是文件系统策略层和高层操作层。

它负责：

- `SandboxPolicy`、`Context` 以及 policy metadata 集成
- named roots、root mode、path rules、permission gate、limits、traversal rules
- secret deny rules 和输出 redaction
- 各类高层操作的 request/response 结构与实现
- CLI 和可选的 policy 文件加载

`crates/omne-fs/src/lib.rs` 的导出就说明了这一点：它对外暴露的是策略类型、操作 request/response，以及 `read_file`、`write_file`、`delete`、`glob_paths`、`grep` 这类高层 helper。

### 它不负责什么

它不负责：

- 原始 descriptor/handle 原语
- 无策略 no-follow open helper
- 通用 UTF-8 bounded-read helper
- 通用进程 runtime 清理
- OS 强制级 sandbox

当前实现已经体现了这个边界：

- `crates/omne-fs/src/platform_open.rs` 是 crate-private shim，
  仅在 crate 内部把 no-follow open 委托给 `omne-fs-primitives`
- `crates/omne-fs/src/ops/io.rs` 也把 regular-file no-follow open 委托给
  `omne-fs-primitives`

换句话说，`omne-fs` 负责解释策略，不对外重新导出可复用的低层文件系统原语。

## `omne-fs-primitives`

### 它负责什么

`omne-fs-primitives` 是可复用的低层文件系统 building-block crate。

它负责：

- root materialization / opening，例如 `materialize_root`、`open_root`、`open_ambient_root`
- 基于 `cap_std` 的 capability 风格目录访问
- no-follow 文件打开和 regular-file 校验
- symlink / reparse point 打开错误分类
- bounded read helper，例如 `read_to_end_limited`、`read_utf8_limited`
- staged atomic write
- 共享的字节限制常量
- advisory file locking

这些职责可以从下面这些文件直接看到：

- `crates/omne-fs-primitives/src/lib.rs`
- `crates/omne-fs-primitives/src/cap_root.rs`
- `crates/omne-fs-primitives/src/platform_open.rs`
- `crates/omne-fs-primitives/src/read_limited.rs`
- `crates/omne-fs-primitives/src/atomic_write.rs`

### 它不负责什么

它不负责：

- `SandboxPolicy`
- root alias 语义
- 权限和 limit 决策
- secret path 拒绝或输出 redaction
- 面向工具的 CLI 和 request/response 合约
- 领域级错误映射

判断原则很简单：如果一个 helper 虽然低层、可复用，但仍然编码了产品策略，那它就不属于这里。

## `omne-process-primitives`

### 它负责什么

`crates/omne-process-primitives` 导出的 package 名叫 `omne-process-primitives`。

它负责低层宿主机命令与进程生命周期原语，包括：

- `command_exists`、`command_exists_os`、`command_available`、`command_available_os`、
  `command_path_exists`
- `resolve_command_path`、`resolve_command_path_os`
- 以 `OsStr` / `OsString` 为边界的 `HostCommandRequest`、`run_host_command`
- 以 `OsStr` / `OsString` 为边界的 `HostRecipeRequest`、`run_host_recipe`
- `default_recipe_sudo_mode_for_program`
- Unix 下对 bare system command 的 `sudo -n` 试探
- `configure_command_for_process_tree`
- `ProcessTreeCleanup`
- Unix process group 的建立与终止
- Linux leader 身份捕获和 `/proc` 复用校验
- Windows Job Object 挂接与 kill-on-close 行为
- Windows fallback 路径下的 best-effort 后代进程清理

这些能力主要实现在下面这些文件中：

- `crates/omne-process-primitives/src/lib.rs`
- `crates/omne-process-primitives/src/host_command.rs`

### 它不负责什么

它不负责：

- 什么时候取消一个命令
- 超时策略
- stdout/stderr 的产品级保密、裁剪或持久化规则
- secret 专属或产品专属错误映射
- 命令 allowlist 或环境变量过滤
- sandbox / isolation 选择

这个 crate 故意保持无策略。它提供的是底层宿主机命令与进程机制，至于何时、为何调用，由上层 caller 决定。

## `omne-system-package-primitives`

### 它负责什么

`omne-system-package-primitives` 是可复用的系统包管理器 building-block crate。

它负责：

- 识别受支持的系统包管理器，例如 `apt-get`、`dnf`、`yum`、`apk`、`pacman`、`zypper`、`brew`
- 根据 manager + package 构建 install recipe
- 根据宿主 OS 推导默认 manager 顺序和默认 install recipe

这些职责主要实现在下面这些文件中：

- `crates/omne-system-package-primitives/src/lib.rs`

### 它不负责什么

它不负责：

- 实际执行 install recipe
- plan method、tool/package 映射或产品级安装策略
- CLI 或领域错误码

这个 crate 只负责“系统包管理器是谁、recipe 长什么样”，不负责“什么时候执行、执行失败后怎样处理”。

## 新代码应该放哪里

新增 helper 时，可以按下面规则判断归属。

### 放进 `omne-fs-primitives` 的条件

- 它是文件系统相关能力
- 它会被多个调用方复用
- 它不携带策略和产品语义
- 它是 descriptor/handle/path 级原语，而不是面向工具的高层操作

### 放进 `omne-archive-primitives` 的条件

- 它是 archive/compression 相关能力
- 它会被多个调用方复用
- 它不携带下载策略、安装策略或产品语义
- 它负责格式识别、条目遍历、条目读取或目标条目匹配，而不是最终落盘

### 放进 `omne-artifact-install-primitives` 的条件

- 它是 artifact 下载、校验、binary/tree 安装相关能力
- 它会被多个调用方复用
- 它不负责 release metadata、来源顺序策略或产品 contract
- 它是安装管道原语，而不是单个产品的编排层

### 放进 `omne-process-primitives` 的条件

- 它是进程/runtime 相关能力
- 它会被多个调用方复用
- 它属于低层 host-command / spawn / cleanup 基础设施
- 它不负责产品策略决策

### 放进 `omne-system-package-primitives` 的条件

- 它是系统包管理器识别、归一化或 install recipe 相关能力
- 它会被多个调用方复用
- 它不执行命令，也不携带产品级安装编排语义

### 留在 `omne-fs` 的情况

- 它解释 `SandboxPolicy`
- 它决定 read/write/delete/patch/glob/grep 的行为
- 它应用 secret rules、limits 或 redaction
- 它暴露面向工具的 request/response 合约

### 留在 `omne-execution-gateway` 的情况

- 它决定是否允许执行
- 它解析最终隔离级别
- 它校验执行用的 `cwd` 和 `workspace_root`
- 它应用 gateway 专属 sandbox 行为或审计语义

## 需要避免的边界错误

- 不要因为某段逻辑有跨平台 `cfg(...)` 分支，就把进程树清理塞进 `omne-fs`。
- 不要把归档格式解析和条目匹配塞进 `omne-fs-primitives`；那不是文件系统原语。
- 不要因为某段文件系统策略在单个 crate 内可复用，就把它下沉到 `omne-fs-primitives`。
- 不要把完整 artifact 下载 + 校验 + 解压安装管道继续堆在产品仓库里，也不要硬塞进 `omne-archive-primitives`。
- 不要把 `omne-process-primitives` 变成超时、保密或产品策略的收纳箱。
- 不要把 `omne-system-package-primitives` 扩展成命令执行器或 plan method 解释器。
- 不要把 `omne-execution-gateway` 扩展成通用文件系统工具 API。
- 不要再造一个把文件系统、进程和 sandbox 混在一起的 `platform` crate。

## 相关 ADR

- `docs/unsafe-boundary-adr.md`
- `crates/omne-fs/docs/fs-primitives-boundary-adr.md`
- `crates/omne-fs/docs/process-primitives-boundary-adr.md`
