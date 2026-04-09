# 系统边界

## 目标

`omne-system-package-primitives` 提供无策略的包管理器识别和 install recipe 原语，让上层调用方复用统一的 manager 枚举与默认安装配方。

## 负责什么

- 识别 canonical manager 名，例如 `apt-get`、`dnf`、`yum`、`apk`、`pacman`、`zypper`、`brew`。
- 建模支持的包管理器集合。
- 先把 package 解析成受约束的 `SystemPackageName`，拒绝空串、空白、控制字符、当前平台语义下的路径分隔符、`.`/`..` 和 option-looking token，再从 manager + package 构建安装 recipe。
- 基于显式 OS 标识给出默认 manager 顺序和默认 recipe。

## 不负责什么

- 实际执行安装命令。
- 宿主机探测或平台识别。
- plan method 解释。
- 产品级 tool/package 映射。
- CLI 或领域错误码。

## 调用方边界

- 上层调用方负责决定何时执行 recipe。
- 上层调用方负责宿主机探测，并把宿主平台映射成 OS 标识后再调用这里的默认顺序能力。
- 上层调用方负责把 recipe 执行结果映射为产品语义。
