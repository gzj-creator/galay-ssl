# galay-ssl Kernel 兼容与性能对标设计

## 背景

`galay-kernel` 已更新，`galay-ssl` 现阶段首先需要确认接口兼容性与运行正确性；在此基础上，再做有证据支撑的性能优化，并与仓库外的 `Go crypto/tls`、`Rust rustls + tokio` 对标，评估小包 QPS、大包吞吐和握手成本差距。

## 目标

1. 适配当前版本 `galay-kernel`，恢复 `galay-ssl` 的可编译、可测试、可基准状态。
2. 在不盲目重构的前提下，优先修复和优化明显热点。
3. 在仓库外建立可复现的 Go / Rust SSL Echo 对标基准，统一口径评估差距。
4. 使用采样或火焰图工具定位差距来源，区分 `galay-ssl`、`galay-kernel`、OpenSSL 与 benchmark 口径因素。

## 非目标

- 本轮不将 Go / Rust 对标程序提交到仓库。
- 本轮不为了追分做大规模 API 重设计，除非 `galay-kernel` 变更迫使异步桥接层重写。
- 本轮不对未证实的路径做投机式优化。

## 执行架构

### 阶段 1：兼容性收敛

- 重新配置并编译当前仓库，收集因 `galay-kernel` 升级产生的编译、链接和运行错误。
- 识别接口变化属于头文件路径、命名、类型签名、协程/调度器协议还是 awaitable/waker 交互变化。
- 优先采用最小兼容改造；若 `SslSocket` 与 `Awaitable` 对接模型不再成立，再局部重写异步桥接层。
- 在进入性能阶段前，至少恢复关键测试和最小 echo 示例。

### 阶段 2：本库内热点优化

- 以兼容后的版本为基线，检查 `SSL_read/SSL_write` 循环、`WANT_READ/WANT_WRITE` 处理、buffer 拷贝、对象分配和唤醒路径。
- 优先选择不改变公开 API 的优化，例如减少多余复制、降低小包路径上的状态切换和系统调用次数。
- 每次优化后回到现有 benchmark 复测，确保正确性优先且性能结果可归因。

### 阶段 3：Go / Rust 外部对标

- 在仓库外临时创建 `Go crypto/tls` 与 `Rust rustls + tokio` 的 SSL Echo benchmark。
- 统一证书、payload、连接数、请求数、线程/任务规模和测试机器环境。
- 分三类场景跑基线：`47B` 小包 QPS、`64KiB` 大包吞吐、握手成本。

### 阶段 4：差距归因与二次优化

- 使用采样或火焰图判断差距主要来自 TLS 加解密、buffer 搬运、事件循环、唤醒逻辑还是连接管理。
- 若差距主要在 `galay-ssl` 可控区域，则继续定向优化；若主要受 `galay-kernel` 或 OpenSSL 限制，则在结论中单独标注。

## 验证与 Profiling 方案

### 正确性验证

- 先跑构建、测试、最小示例和最小 benchmark，分类错误来源。
- 若接口变化较大，先恢复 `test/T1-SslSocketTest.cc` 与最小 Echo 场景，再进入压测。
- 所有性能结论必须建立在 `errors=0` 的运行结果之上。

### 性能基线

- 沿用仓库已有文档口径：小包 `47B`、大包 `64KiB`、握手单独测。
- 固定 `Release + LTO`、固定 OpenSSL 版本、固定 scheduler 与单机环境。
- 每组参数多轮执行，记录平均值与波动区间。

### Profiling 手段

- macOS 优先使用 `Instruments/Time Profiler` 或 `sample`。
- Linux 环境可使用 `perf` 与 flamegraph。
- 重点观察 `SSL_read`、`SSL_write`、record layer、buffer copy、scheduler wakeup、事件注册与取消。
- 采样不足以归因时，再增加只在 benchmark 路径启用的轻量计数。

## 主要风险

1. `galay-kernel` 升级可能同时影响正确性与性能，必须先建立稳定基线。
2. benchmark 容易被构建选项、调度器与证书校验口径污染，需要严格统一参数。
3. profiling 可能显示瓶颈在 `galay-kernel` 或 OpenSSL，而非 `galay-ssl` 自身。

## 交付物

- 一个适配当前 `galay-kernel` 的 `galay-ssl` 基线版本。
- 一组更新后的本库 benchmark 结果与必要的 profiling 辅助输出。
- 一份 Go / Rust 对标摘要，说明三类场景下的差距与归因。
- 一轮有证据支撑的性能优化。
