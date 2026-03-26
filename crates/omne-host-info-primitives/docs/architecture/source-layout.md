# 源码布局

## 入口

- `src/lib.rs`
  - 宿主 OS/arch 识别、target triple 归一化、home 目录解析和可执行后缀推断。

## 布局规则

- 当前所有职责集中在 `src/lib.rs`。
- 若未来把宿主探测、home 目录解析或 target triple 归一化拆开，文件名必须继续直接表达职责。
