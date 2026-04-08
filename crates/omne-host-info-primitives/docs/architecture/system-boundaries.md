# 系统边界

## 目标

`omne-host-info-primitives` 提供无策略的宿主平台 identity 原语，让上层调用方复用宿主识别、target triple 归一化和 home 目录解析能力。

## 负责什么

- 识别支持的宿主 OS/arch 组合，并保留 Linux `libc` 识别失败后的 unknown 状态；unknown Linux 宿主仍然是已识别宿主平台，但不会被伪装成 `gnu`。
- 把宿主组合映射到 canonical target triple，并在 Linux 上优先根据当前进程实际加载的 loader/libc 证据区分 `gnu` / `musl` 宿主 ABI；只有完全拿不到这层证据时才回退到固定绝对路径上的本地 loader marker。当前进程已经明确指向 glibc 或 musl 时，不会因为磁盘上碰巧存在另一侧 loader 文件而改判；若当前进程证据或本地 loader marker 出现 glibc 与 musl 并存、无法可靠判定的情况则直接 fail closed，保持 Linux libc unknown。像 `/etc/alpine-release` 这样的粗粒度发行版 marker 不再被当成 libc 证据，避免在证据不足时继续猜测 musl/gnu triple。
- 对已识别宿主平台提供 checked target-triple 映射：Linux libc 已知时返回 canonical triple，Linux libc unknown 时返回显式错误；兼容 helper 则继续 fail closed，只在 triple 已知时返回字符串。
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
