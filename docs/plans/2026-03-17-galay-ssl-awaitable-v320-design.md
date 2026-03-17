# galay-ssl Awaitable v3.2.0 迁移设计

**目标**

把 `galay-ssl` 从旧的 `CustomAwaitable` / 手写内部任务队列模型迁移到 `galay-kernel v3.2.0` 的共享状态机执行内核，同时把 SSL 层正式开放成可供用户扩展的状态机 / Builder 语义面，并补齐性能回归对比。

**背景**

- `galay-kernel v3.2.0` 已完成 Awaitable 状态机内核、`AwaitableBuilder::fromStateMachine(...)`、链式 Builder 桥接、`connect` 支持和 `ops.queue(...)` 误用拒绝。
- `galay-ssl` 当前仍在 [`galay-ssl/async/Awaitable.h`](../../galay-ssl/async/Awaitable.h) 与 [`galay-ssl/async/Awaitable.cc`](../../galay-ssl/async/Awaitable.cc) 中直接依赖 `CustomAwaitable`、`RecvCtx`、`SendCtx` 等内部辅助结构。
- 当前 `SslSocket::handshake()` / `shutdown()` 对业务层暴露了 OpenSSL 中间态，调用方要自行循环处理 `WantRead/WantWrite`。
- 用户要求：
  - `galay-ssl` 完整适配 `galay-kernel v3.2.0`
  - SSL 层也要开放给用户自定义状态机 / Builder
  - 同时保留性能可验证性，除了现有整体 benchmark 之外还要新增分项 benchmark

## 一、正式设计决策

### 1. 单次语义升级

- `co_await socket.handshake()` 升级为单次语义 awaitable：
  - 成功时代表整轮 TLS 握手已完成
  - 失败时直接返回最终 `SslError`
  - `WantRead/WantWrite` 不再暴露给业务层
- `co_await socket.shutdown()` 同样升级为单次语义 awaitable：
  - 成功时代表 TLS 关闭流程已跑完
  - 失败时返回最终 `SslError`
- `recv()` / `send()` 保持直觉语义：
  - `recv()` 返回解密后的明文块，`Bytes{}` 仍表示对端关闭
  - `send()` 返回已成功刷出的明文字节数

### 2. 保持现有业务入口稳定

以下业务入口保留，不要求已有业务代码改名：

- `SslSocket::connect(...)`
- `SslSocket::handshake()`
- `SslSocket::recv(...)`
- `SslSocket::send(...)`
- `SslSocket::shutdown()`
- `SslSocket::close()`

变化只发生在实现方式和语义收口上。

### 3. 新增 SSL 状态机与 Builder 扩展面

新增并正式公开：

- `SslMachineSignal`
- `SslMachineAction<ResultT>`
- `SslStateMachineAwaitable<MachineT>`
- `SslAwaitableBuilder<ResultT, InlineN, FlowT>`

设计原则：

- 用户工作在 SSL 语义层，而不是 raw socket / BIO 层
- 用户不需要直接处理 `WantRead/WantWrite`
- 用户不需要直接操作内部密文缓冲、`RecvCtx`、`SendCtx`

### 4. 性能验收双轨制

性能验收分两层：

- 保留现有 `B1-SslBenchServer` / `B1-SslBenchClient`，比较整体吞吐与错误率
- 新增 SSL 分项 benchmark，至少覆盖：
  - `B2-SslHandshake`
  - `B3-SslRecvEcho`
  - `B4-SslSendEcho`
  - 如有必要补 `B5-SslShutdown`

验收阈值：

- 总体吞吐与关键分项回退控制在 `±5%`
- 若握手或小包收发分项超过 `5%` 回退，视为阻塞项，不直接收尾

## 二、公开 API 设计

### 1. SSL 低层状态机面

用户自定义状态机的动作是 SSL 语义动作，而不是 raw IO 动作。

建议动作集合：

- `kContinue`
- `kHandshake`
- `kRecv`
- `kSend`
- `kShutdown`
- `kComplete`
- `kFail`

机器接口形态：

```cpp
struct MySslMachine {
    using result_type = std::expected<MyResult, SslError>;

    SslMachineAction<result_type> advance();
    void onHandshake(std::expected<void, SslError>);
    void onRecv(std::expected<Bytes, SslError>);
    void onSend(std::expected<size_t, SslError>);
    void onShutdown(std::expected<void, SslError>);
};
```

入口形态：

```cpp
auto awaitable =
    SslAwaitableBuilder<MyResult>::fromStateMachine(&socket, MySslMachine{}).build();
auto result = co_await awaitable;
```

可选扩展：

- 如果状态机需要先跑 TCP 连接，再进入 TLS 语义，可在 Builder 上保留前置 `connect(...)`
- 对纯 SSL 状态机而言，不开放 raw `waitRead/waitWrite` 给业务层

### 2. SSL Builder 面

Builder 面面向线性协议流程，建议支持：

- `connect(...)`
- `handshake(...)`
- `recv(...)`
- `parse(...)`
- `send(...)`
- `shutdown(...)`
- `local(...)`
- `finish(...)`
- `fromStateMachine(...)`

目标示例：

```cpp
auto awaitable = SslAwaitableBuilder<Result, 8, Flow>(&socket, flow)
    .handshake<&Flow::onHandshake>()
    .recv<&Flow::onRecv>(flow.buf, sizeof(flow.buf))
    .parse<&Flow::onParse>()
    .send<&Flow::onSend>(flow.reply.data(), flow.reply.size())
    .shutdown<&Flow::onShutdown>()
    .build();
```

适用场景：

- `handshake -> recv -> parse -> send -> shutdown`
- 带 TLS gate 的线性协议流
- 需要半包 / 粘包 parse，但不想直接写状态机的场景

### 3. 不对外暴露的内部细节

以下内容继续视为实现细节：

- `RecvCtx` / `SendCtx`
- `HandshakeRecvCtx` / `HandshakeSendCtx`
- `ShutdownRecvCtx` / `ShutdownSendCtx`
- BIO 密文缓冲
- OpenSSL `WantRead/WantWrite`

外部语义层只围绕：

- `SslSocket`
- `SslError`
- `Bytes`
- `SslMachineAction`
- `SslAwaitableBuilder`

## 三、内部架构设计

### 1. 共享执行内核

建议新增共享 SSL 执行内核，拆成两层：

- `SslOperationDriver`
- `SslMachineRunner<ResultT, MachineT>`

职责划分：

- `MachineT`
  - 只描述业务语义步骤
  - 不直接处理 raw socket 事件
  - 不直接碰 BIO 细节
- `SslOperationDriver`
  - 驱动 `SslEngine`
  - 管理 Memory BIO 输入输出
  - 注册底层 raw read/write/connect 事件
  - 把 `WantRead/WantWrite` 收口成一次完整 SSL 语义动作
- `SslMachineRunner`
  - 负责调度 machine 的 `advance()` / `onXxx(...)`
  - 复用 kernel v3.2.0 的状态机 pump 思路
  - 把 Driver 的 SSL 语义结果交还给 machine

### 2. 内建 awaitable 迁移为内建 machine

以下 awaitable 不再各自维护独立 `CustomAwaitable` 任务队列：

- `SslHandshakeAwaitable`
- `SslRecvAwaitable`
- `SslSendAwaitable`
- `SslShutdownAwaitable`

迁移后的角色：

- 变成内建 machine 的轻封装
- 共享同一套 `SslOperationDriver`
- 与用户自定义状态机共用一条热路径

### 3. 热路径约束

为避免性能回退，以下约束是硬要求：

- 不在热路径引入 `std::function`
- 不在热路径做额外堆分配
- 复用 `SslSocket` 现有 cipher buffer
- `WantRead/WantWrite`、BIO flush、密文收发循环保持在 Driver 内部
- Builder / 状态机只做语义分发，不把 raw read/write 重新暴露给用户层

## 四、迁移影响面

### 1. 主要代码文件

核心迁移面预计至少包含：

- `galay-ssl/async/Awaitable.h`
- `galay-ssl/async/Awaitable.cc`
- `galay-ssl/async/SslSocket.h`
- `galay-ssl/async/SslSocket.cc`
- `galay-ssl/module/galay.ssl.cppm`
- `galay-ssl/module/ModulePrelude.hpp`

### 2. 现有业务与示例

以下业务 / 示例需要同步到单次语义：

- `examples/include/E1-ssl_echo_server.cc`
- `examples/include/E2-ssl_client.cc`
- `examples/import/E1-ssl_echo_server.cc`
- `examples/import/E2-ssl_client.cc`
- `test/T2-ssl_loopback_smoke.cc`
- `benchmark/B1-ssl_bench_server.cc`
- `benchmark/B1-ssl_bench_client.cc`

主要变化是移除业务层对 `handshake()` / `shutdown()` 的显式循环。

### 3. 文档面

需要同步更新：

- `README.md`
- `docs/01-架构设计.md`
- `docs/02-API参考.md`
- `docs/03-使用指南.md`
- `docs/04-示例代码.md`
- `docs/05-性能测试.md`
- `docs/06-高级主题.md`

## 五、测试与示例设计

### 1. 回归测试

已有测试要改到新语义：

- `T2-SslLoopbackSmoke`

新增测试建议：

- `T3` 或后续编号：单次 `handshake()` 语义测试
- Builder `handshake -> recv -> parse -> send -> shutdown` 测试
- 自定义 SSL 状态机测试
- 错误路径测试：
  - 证书错误
  - 对端提前关闭
  - 半包
  - shutdown 中断

### 2. 官方示例

新增最小示例：

- `E3-SslCustomAwaitable`
  - 最小 SSL 状态机自定义示例
- `E4-SslBuilderProtocol`
  - 最小 Builder 协议流示例

示例目标：

- 用户看完能直接仿照写自定义 SSL awaitable
- 能明显区分“复杂状态机场景”和“线性 Builder 场景”

## 六、性能验证设计

### 1. 整体 benchmark

保留并更新现有：

- `B1-SslBenchServer`
- `B1-SslBenchClient`

对比指标：

- QPS / throughput
- `errors`
- `connect_fail`
- `handshake_fail`
- `send_fail`
- `recv_fail`
- `peer_closed`

### 2. 分项 benchmark

新增：

- `B2-SslHandshake`
  - 只测握手路径
- `B3-SslRecvEcho`
  - 固定握手完成后测 recv 主路径
- `B4-SslSendEcho`
  - 固定握手完成后测 send 主路径
- 可选 `B5-SslShutdown`
  - 测 TLS 关闭路径

### 3. 对比口径

对比方式：

- 先记录当前 `main` 基线
- 再跑迁移后版本
- 保持同一机器、同一编译模式、同一后端、同一证书、同一并发参数

目标：

- 如果整体 `B1` 基本持平，而分项显示 `handshake` / 小包路径改善或持平，则迁移可接受
- 如果 `B1` 持平但分项某一路径显著回退，需要继续优化后才能收尾

## 七、风险与缓解

### 风险 1：握手路径抽象过度导致回退

缓解：

- `WantRead/WantWrite` 收在 Driver 内部
- 先做最保守迁移，再做 Builder 对外包装

### 风险 2：Builder 为了通用性引入热路径分配

缓解：

- 使用模板 + inline storage
- 不引入运行时 type erasure

### 风险 3：文档与真实 API 不一致

缓解：

- 以公开头文件、示例、测试为真相源
- 文档只在验证完成后更新

## 八、验收标准

本次改造完成的标准是：

1. `galay-ssl` 不再依赖旧 `CustomAwaitable` 作为核心实现模型
2. `handshake()` / `shutdown()` 升级为单次语义 awaitable
3. 用户可以通过 SSL 状态机或 SSL Builder 简单创建自定义 awaitable
4. 官方 examples 中有最小自定义状态机示例和最小 Builder 示例
5. 现有示例、测试、整体 benchmark 与新增分项 benchmark 全部通过
6. 性能回退控制在约定阈值内，否则继续优化而不发布
