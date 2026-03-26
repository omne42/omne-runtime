# 源码布局

## 顶层入口

- `src/lib.rs`
  - crate 入口与公开导出。
- `src/bin/omne-execution.rs`
  - 执行请求 CLI 入口。
- `src/bin/omne-execution-capability.rs`
  - 能力报告 CLI 入口。

## 核心模块

- `src/gateway.rs`
  - 执行主流程、校验和能力协商。
- `src/policy.rs`
  - policy 模型与默认策略。
- `src/types.rs`
  - request/isolation 相关基础类型。
- `src/error.rs`
  - 错误类型与结果。
- `src/audit.rs`
  - 执行事件、决策和 runtime 观测模型。
- `src/audit_log.rs`
  - 审计日志输出辅助。

## 平台模块

- `src/sandbox/mod.rs`
  - sandbox 平台适配汇总。
- `src/sandbox/linux.rs`
  - Linux sandbox 适配。
- `src/sandbox/macos.rs`
  - macOS sandbox 适配。
- `src/sandbox/windows.rs`
  - Windows sandbox 适配。

## 文档与生成物

- `docs/`
  - 受版本控制的记录系统。
- `mkdocs.yml`
  - 文档站配置。
- `site/`
  - 生成输出，不直接维护。
