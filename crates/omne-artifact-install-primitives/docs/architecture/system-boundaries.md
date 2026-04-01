# 系统边界

## 目标

`omne-artifact-install-primitives` 提供一个窄边界的 runtime 级 artifact 物化管道，避免调用方重复实现“候选下载 + SHA 校验 + 原子落盘/解压安装”。

## 负责什么

- 消费调用方给定的有序下载候选列表。
- 当调用方给出空候选列表时，立即返回“缺少 download candidates”的输入错误，而不是伪装成“所有候选下载都失败了”。
- 以受限响应体流式下载 artifact。
- 对外只暴露 caller-supplied `ArtifactDownloader` 边界；具体 HTTP client（例如 `reqwest` 或 `http-kit` profile）适配留在实现层，不把 transport 类型直接写进 primitive public API。
- 对下载结果执行可选的 SHA-256 校验。
- 把直接二进制资产原子安装到目标路径，并在 install/commit 阶段按目标路径做 advisory lock 串行化。
- install 阶段使用的 advisory lock root 也遵循和 staged destination 相同的 no-follow 祖先校验，不能沿 symlink 祖先把锁建到目标边界之外。
- 从受支持的 archive 中按精确 `archive_binary_hint` 或约定 `bin/<binary>` 布局提取目标二进制并安装到目标路径，且提取阶段受 crate-local binary-archive extracted-byte 预算约束。
- 把受支持的 archive 目录树解到 `omne-fs-primitives` 提供的 staged 目录，并在默认 extracted-byte / entry-count 预算内成功后替换目标目录。
- archive tree 在 staged 目录里的目录、regular file、symlink 和 hard link 物化继续绑定在 capability-backed directory handle 上，不回退成 ambient path-based `create_dir` / `File::create` / `hard_link` 流程。
- `async` 下载入口只把网络阶段留在 Tokio worker 上；SHA 校验、archive 解压和 staged commit 这类重本地 I/O / CPU 阶段切到 blocking 线程，避免把 runtime worker 长时间占满。
- 对同一个 binary / archive-binary / archive-tree 目标，安装阶段按目标做 advisory lock 串行化，避免并发 staged commit / directory replace 互相踩坏目标状态。
- 对 archive tree 中会物化目录项的条目，要求落点父目录链必须是 staging 目录下的真实目录；命中 symlink 祖先时 fail-closed，不能借由已创建链接把后续 regular file 写出到 staging 目录之外。
- 在 Unix 上把 zip symlink 条目按 symlink 语义物化，并对 symlink target 读取施加独立长度上限；非 Unix 平台遇到 zip symlink 条目时 fail-closed。
- 对 tar hard link 条目允许目标成员晚于 link 条目出现，只要最终目标仍解析到 staging 目录内的 regular file。
- 候选来源只记录调用方给定的 `source_label`，不把 `gateway|canonical|mirror` 之类产品来源枚举硬编码进 primitive contract。
- 对聚合后的 install-phase 失败，只在所有 install 尝试都指向同一类 runtime 原因时才保留结构化 detail；这样调用方可以基于稳定 error signal 决定是否重试，而不用依赖错误文案。

## 不负责什么

- GitHub release API、release DTO 或 latest tag 选择。
- 候选来源顺序策略生成。
- 产品级目标目录布局、tool name 到 destination 的映射。
- 产品级错误码、JSON 结果 contract 或 CLI。

## 依赖边界

- 依赖 `http-kit` 做受限响应体下载。
- 依赖 `omne-integrity-primitives` 做 digest 校验。
- 依赖 `omne-fs-primitives` 做 staged atomic file/directory replace。
- 依赖 `omne-archive-primitives` 做 archive binary 提取和 archive tree walker。
- 对 archive tree 安装，archive 格式读取、entry/path/link 语义、以及 tree 级预算收口在 `omne-archive-primitives`；目录 staging/replace 原语下沉到 `omne-fs-primitives`。
- 对外返回的 binary-archive match metadata 和 binary-archive 预算常量由本 crate 自己定义，不把 `omne-archive-primitives` 的同名符号直接重导出到更高层调用方。

## 调用方边界

- 调用方负责构造候选列表和决定重试顺序。
- 调用方负责解释成功来源并映射到自己的结果 contract。
- 调用方负责产品级自定义后处理，例如写 launcher、更新元数据或附加权限策略。
