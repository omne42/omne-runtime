# 系统边界

## 目标

`omne-artifact-install-primitives` 提供一个窄边界的 runtime 级 artifact 物化管道，避免调用方重复实现“候选下载 + SHA 校验 + 原子落盘/解压安装”。

## 负责什么

- 消费调用方给定的有序下载候选列表。
- 对外通过 crate-local `ArtifactDownloader` 边界接收下载能力，而不是把具体 HTTP client 类型固定进 public API。
- 以受限响应体流式下载 artifact。
- 对下载结果执行可选的 SHA-256 校验。
- 对关键安装失败保留结构化错误细节和 candidate-level failure 列表，例如 archive binary 未找到时可通过 `ArtifactInstallErrorDetail::ArchiveBinaryNotFound` 分流，而不是只能解析字符串。
- 把直接二进制资产原子安装到目标路径，并对同一 binary 目标的 install phase 做 advisory lock 串行化，避免并发 commit 互相踩坏最终落点。
- 从受支持的 archive 中提取目标二进制并安装到目标路径，且提取阶段受默认 extracted-byte 预算约束；同一 binary 目标的 install phase 同样按 destination 做 advisory lock 串行化。
- 把受支持的 archive 目录树解到 `omne-fs-primitives` 提供的 staged 目录，并在默认 extracted-byte / entry-count 预算内成功后替换目标目录。
- 对同一个 archive tree 目标目录，安装阶段按目标做 advisory lock 串行化，锁名基于归一化后的 destination identity 派生，避免 root alias 或词法等价路径把同一个真实目录拆成多把锁。
- 对 archive tree 中会物化目录项的条目，要求 staging 根及其内部落点父目录链必须是 staging 目录下的真实目录；命中这些受管组件里的 symlink 祖先时 fail-closed，不能借由已创建链接把后续 regular file 写出到 staging 目录之外。
- 对 archive tree 中落到 leaf 的 regular file、symlink 和 hard link，使用 `omne-fs-primitives` 的 capability-style directory handle 完成 remove/create/link，避免 staged extraction 依赖 ambient 路径的 leaf 级 TOCTOU。
- archive tree install 在 staged 目录创建成功后，后续 unzip/untar 和最终目录替换都继续绑定同一个 staged directory / parent directory handle；如果 staging 之后原始 destination parent path 被 rename 或替换成 symlink，安装必须继续写入原绑定目录或 fail-closed，而不是沿新的 ambient 路径漂移。
- 在 Unix 上把 zip symlink 条目按 symlink 语义物化，并对 symlink target 读取施加独立长度上限；非 Unix 平台遇到 zip symlink 条目时 fail-closed。
- 对 tar hard link 条目允许目标成员晚于 link 条目出现，只要最终目标仍解析到 staging 目录内的 regular file。

## 不负责什么

- GitHub release API、release DTO 或 latest tag 选择。
- `gateway|canonical|mirror` 候选顺序策略生成。
- 产品级目标目录布局或 tool/package 映射。
- 产品级错误码、JSON 结果 contract 或 CLI。

## 依赖边界

- 对外下载边界固定为 crate-local `ArtifactDownloader`；内建的 `reqwest::Client` 适配仍通过 `http-kit` 做受限响应体下载。
- 依赖 `omne-integrity-primitives` 做 digest 校验。
- 依赖 `omne-fs-primitives` 做 staged atomic file/directory replace。
- 依赖 `omne-archive-primitives` 做 archive binary 提取。
- 对 archive tree 安装，它负责 archive 语义、预算和 link 校验；目录 staging/replace 原语下沉到 `omne-fs-primitives`。

## 调用方边界

- 调用方负责构造候选列表和决定重试顺序。
- 调用方负责解释成功来源并映射到自己的结果 contract。
- 调用方负责产品级自定义后处理，例如写 launcher、更新元数据或附加权限策略。
