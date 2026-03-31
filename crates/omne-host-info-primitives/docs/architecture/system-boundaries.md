# 系统边界

## 目标

`omne-host-info-primitives` 提供无策略的宿主平台 identity 原语，让上层调用方复用宿主识别、target triple 归一化和 home 目录解析能力。

## 负责什么

- 识别支持的宿主 OS/arch 组合。
- 把宿主组合映射到 canonical target triple，并在 Linux 上先成功区分默认 `gnu` / `musl`
  宿主 ABI；这里只接受运行时探测结果。如果 libc 无法判断，宿主识别直接 fail closed，而不是
  默默回退成 `gnu`，也不会因为系统里额外存在 musl/glibc 工具链文件就误判宿主 ABI。
- 解析可选 target override，并且只接受这个 crate 已知的 canonical target triple；空值时回退到
  已校验的宿主 triple。
- 解析当前用户 home 目录，只接受来自标准环境变量的绝对路径。
- 只根据已校验的 canonical target triple 推断可执行后缀。

## 不负责什么

- `OMNE_DATA_DIR` 或产品目录布局。
- 包管理器适配。
- 下载、安装编排或 CLI。

## 调用方边界

- 上层调用方负责决定 target triple 在自己领域中的语义。
- 这里不拥有产品级 managed directory 规则。
