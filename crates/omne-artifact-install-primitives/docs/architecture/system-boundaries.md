# 系统边界

## 目标

`omne-artifact-install-primitives` 提供一个窄边界的 runtime 级 artifact 物化管道，避免调用方重复实现“候选下载 + SHA 校验 + 原子落盘/解压安装”。

## 负责什么

- 消费调用方给定的有序下载候选列表。
- 以受限响应体流式下载 artifact。
- 对下载结果执行可选的 SHA-256 校验。
- 把直接二进制资产原子安装到目标路径。
- 从受支持的 archive 中提取目标二进制并安装到目标路径，且提取阶段受默认 extracted-byte 预算约束。
- 把受支持的 archive 目录树解到 staging 目录，并在默认 extracted-byte / entry-count 预算内成功后替换目标目录。

## 不负责什么

- GitHub release API、release DTO 或 latest tag 选择。
- `gateway|canonical|mirror` 候选顺序策略生成。
- 产品级目标目录布局、tool name 到 destination 的映射。
- 产品级错误码、JSON 结果 contract 或 CLI。

## 依赖边界

- 依赖 `http-kit` 做受限响应体下载。
- 依赖 `omne-integrity-primitives` 做 digest 校验。
- 依赖 `omne-fs-primitives` 做 staged atomic file write。
- 依赖 `omne-archive-primitives` 做 archive binary 提取。
- 对 archive tree 安装，它自己负责 staging 目录和目标替换，因为这已经是 artifact 安装语义，不再属于纯 archive 读取原语。

## 调用方边界

- 调用方负责构造候选列表和决定重试顺序。
- 调用方负责解释成功来源并映射到自己的结果 contract。
- 调用方负责产品级自定义后处理，例如写 launcher、更新元数据或附加权限策略。
