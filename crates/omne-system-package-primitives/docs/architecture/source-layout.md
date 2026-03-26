# 源码布局

## 入口

- `src/lib.rs`
  - 包管理器枚举、canonical manager 解析、install recipe 构建和默认 recipe 选择。

## 布局规则

- 当前职责集中在 `src/lib.rs`。
- 若未来按平台或 recipe family 拆分，文件名必须继续直接表达职责。
