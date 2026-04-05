# 系统边界

## 目标

`omne-host-info-primitives` 提供无策略的宿主平台 identity 原语，让上层调用方复用宿主识别、target triple 归一化和 home 目录解析能力。

## 负责什么

- 识别支持的宿主 OS/arch 组合。
- 把宿主组合映射到 canonical target triple，并在 Linux 上优先根据当前进程实际加载的 loader/libc 证据区分 `gnu` / `musl` 宿主 ABI；只有拿不到这层证据时才回退到本地 ABI marker，且当 glibc 与 musl marker 并存、无法可靠判定时直接 fail closed，不返回宿主平台。
- 解析可选 target override，并且只接受这个 crate 已支持的 canonical target triple；checked API 会对空字符串和未知 triple 返回结构化错误，兼容 helper 则 fail-closed 回退到已验证宿主 triple。
- 解析当前用户 home 目录，只接受来自标准环境变量的绝对路径。
- 仅根据已验证的 canonical target triple 推断可执行后缀；checked API 会对未知 triple 返回错误，兼容 helper 则 fail-closed 返回空后缀。

## 不负责什么

- `OMNE_DATA_DIR` 或产品目录布局。
- 包管理器适配。
- 下载、安装编排或 CLI。

## 调用方边界

- 上层调用方负责决定 target triple 在自己领域中的语义。
- 这里不拥有产品级 managed directory 规则。
