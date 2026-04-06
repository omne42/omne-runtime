# 系统边界

## 目标

`omne-system-package-primitives` 提供无策略的包管理器识别和 install recipe 原语，让上层调用方复用统一的 manager 枚举与默认安装配方。

## 负责什么

- 只识别精确 canonical manager 名，例如 `apt-get`、`dnf`、`yum`、`apk`、`pacman`、`zypper`、`brew`；不隐式 `trim`、大小写归一化或接受别名。
- 建模支持的包管理器集合。
- 先把 package 解析成受约束的 `SystemPackageName`，拒绝空串、空白、控制字符、路径分隔符、`.`/`..` 和 option-looking token，再从 manager + package 构建安装 recipe。
- 解析显式 OS 标识；已知 OS（如 `windows`）和未知 OS 字符串分开建模，避免调用方把两种情况混为一谈。
- `OperatingSystem` 负责表达“这是哪个已知 OS”，默认 recipe 选择再单独决定“这个 OS 在本 crate 里是否有默认 system-package fallback”。
- 基于显式 OS 标识给出默认 manager 顺序和默认 recipe；不支持默认 recipe 的 OS 必须返回显式 unsupported platform 错误，而不是退化成空集合。

## 不负责什么

- 实际执行安装命令。
- 宿主机探测或平台识别。
- plan method 解释。
- 产品级 tool/package 映射。
- CLI 或领域错误码。

## 调用方边界

- 上层调用方负责决定何时执行 recipe。
- 上层调用方负责宿主机探测，并把宿主平台映射成 OS 标识后再调用这里的默认顺序能力；若宿主 OS 已知但这里不支持默认 recipe，调用方应向上游传播 unsupported platform 信号。
- 上层调用方负责把 recipe 执行结果映射为产品语义。
