# 系统边界

## 目标

`omne-fs-primitives` 提供无策略的低层文件系统原语，供 `omne-fs` 和其他调用方复用。

## 负责什么

- root materialization 与 capability 风格目录访问。
- no-follow 打开和 regular-file 校验。
- symlink/reparse point 错误分类。
- bounded read helper。
- staged atomic file/directory replace 与 advisory lock。
- atomic staging 需要创建父目录时，按 no-follow 目录遍历/创建处理父目录链，不会把缺失层级或已有的非 root-alias 祖先 symlink 当成可信目录继续跟随；平台级 root alias（例如 macOS `/var -> /private/var`）会先归一化后再进入这条链路。

## 不负责什么

- `SandboxPolicy`、root alias、权限决策或 secret 规则。
- 面向工具的 request/response 合约。
- CLI 或产品级错误映射。
- OS 级 sandbox。

## 调用方边界

- 上层调用方负责解释策略和权限。
- 这里不决定调用方应该允许或拒绝什么。
