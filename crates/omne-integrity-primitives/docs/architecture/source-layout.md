# 源码布局

## 入口

- `src/lib.rs`
  - digest 解析、哈希计算、链式 JSON 记录哈希、reader 校验和错误类型。

## 布局规则

- 当前职责集中在 `src/lib.rs`。
- 若未来拆分多种算法或 reader/bytes 子模块，文件名必须继续直接表达职责。
