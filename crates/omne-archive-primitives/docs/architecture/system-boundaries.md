# 系统边界

## 目标

`omne-archive-primitives` 提供无策略的归档与压缩读取原语，供上层调用方复用，不让每个调用方各自重复实现 `.tar.gz`、`.tar.xz`、`.zip` 的格式识别与目标二进制提取。

## 负责什么

- 识别受支持的 archive 资产格式。
- 遍历归档条目并归一化条目路径。
- 只按精确的 `archive_binary_hint` 或约定的 `bin/<binary>` 布局匹配目标条目；这里不再保留任何 `tool_name` 派生或产品特例推断语义。
- 在读取内容前验证命中的目标条目确实是 regular file。
- 在默认 extracted-byte 预算内读取并返回匹配条目的二进制字节；预算需要覆盖大型官方单文件 release。
- 在默认 archive scan-entry 预算内查找目标条目，避免恶意 archive 通过海量小条目把目标成员拖到极后位置时放大线性扫描成本。
- 为 archive tree 调用方提供共享 walker：统一 tar/zip/xz 格式分派、路径净化、zip symlink target 读取、tar link target 提取，以及 tree 级 extracted-byte / entry-count 预算。

## 不负责什么

- 下载 archive。
- 校验摘要、来源或 release 元数据。
- 创建目录、设置权限、原子替换目标文件。
- 领域错误码、安装编排或 CLI。

## 依赖边界

- 依赖 `flate2`、`tar`、`xz2`、`zip` 作为格式读取实现。
- 不依赖产品级安装策略 crate。

## 调用方边界

- 上层调用方负责把 archive 字节提供给这里。
- 上层调用方负责在非常规 archive 布局下提供精确的 `archive_binary_hint`；这里不会从其他字段推导产品特例路径。迁移期保留的 legacy `tool_name` helper 也只会忽略该值，不再承载语义。
- 上层调用方负责决定提取后的字节或 tree entry 该如何落盘、校验或绑定到 staging 目录。
