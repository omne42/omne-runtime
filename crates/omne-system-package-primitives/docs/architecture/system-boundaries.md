# 系统边界

## 目标

`omne-system-package-primitives` 提供无策略的包管理器识别和 install recipe 原语，让上层调用方复用统一的 manager 枚举与默认安装配方。

## 负责什么

- 识别 canonical manager 名，例如 `apt-get`、`dnf`、`yum`、`apk`、`pacman`、`zypper`、`brew`。
- 建模支持的包管理器集合。
- 对 system package name 做显式校验，并从 manager + validated package 构建安装 recipe。
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
- 上层调用方负责把原始产品输入先解析成 `SystemPackageName`；这里不接受任意字符串直接拼接成安装 argv。
- 上层调用方负责把 recipe 执行结果映射为产品语义。
