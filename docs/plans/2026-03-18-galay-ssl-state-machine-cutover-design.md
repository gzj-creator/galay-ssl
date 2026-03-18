# galay-ssl State Machine Cutover Design

**Goal**

一次性移除 `galay-ssl` 中所有旧 `CustomAwaitable` 及其手写任务队列路径，全面迁移到 `galay-kernel v3.2.0` 的状态机 / Builder 模型，并把 SSL 层正式开放为可供用户自定义状态机与 Builder 的扩展面。

**Current Failure Baseline**

- 在 `2026-03-18` 的独立 worktree 中，用 fresh `galay-kernel` 安装前缀重新配置 `galay-ssl`：
  - `cmake -S . -B build-baseline -DCMAKE_PREFIX_PATH=/Users/gongzhijie/Desktop/projects/git/galay-kernel/.verify-install-kernel-20260318 -DBUILD_BENCHMARKS=OFF`
  - `cmake --build build-baseline --parallel`
- 编译阶段立即失败，原因是当前源码仍直接继承已被 `galay-kernel` 删除的 `CustomAwaitable`，并继续访问 `m_tasks`、`m_cursor`、`addTask(...)`、`onCompleted()` 等旧接口。

**Non-Goals**

- 不保留兼容层
- 不再提供任何基于旧 `CustomAwaitable` 的实现路径
- 不把 OpenSSL `WantRead/WantWrite` 重新暴露给业务层

## 1. Design Decision

### 1.1 Public business surface remains stable

以下业务入口保持名称不变：

- `SslSocket::handshake()`
- `SslSocket::recv(...)`
- `SslSocket::send(...)`
- `SslSocket::shutdown()`
- `SslSocket::close()`

变化只发生在语义与实现：

- `handshake()` / `shutdown()` 升级为单次语义 awaitable
- 内部不再使用旧自定义 Awaitable 队列，而是统一走状态机 / Builder 执行内核

### 1.2 No compatibility path

迁移完成后：

- `galay-ssl/async/Awaitable.h`、`galay-ssl/async/Awaitable.cc` 中不允许再出现 `CustomAwaitable`
- SSL awaitable 内部不再维护 `m_tasks`、`m_cursor`、`addTask(...)` 这类旧任务队列状态
- 所有内建 SSL awaitable 与用户自定义扩展 awaitable 共用同一套状态机执行骨架

### 1.3 SSL extension surface becomes first-class API

对外新增稳定扩展面：

- `SslMachineAction<ResultT>`
- `SslStateMachineAwaitable<MachineT>`
- `SslAwaitableBuilder<ResultT, InlineN, FlowT>`

用户面对的是 SSL 语义动作，而不是 raw socket 事件：

- `handshake`
- `recv`
- `send`
- `shutdown`
- `complete`
- `fail`

## 2. Architecture

### 2.1 Shared SSL operation driver

新增内部共享执行骨架，建议拆为两层：

- `SslOperationDriver`
- `SslStateMachineRunner<ResultT, MachineT>`

职责划分：

- `SslOperationDriver`
  - 驱动 `SslEngine`
  - 管理 Memory BIO 输入输出
  - 收口 `WantRead/WantWrite`
  - 复用 `SslSocket` 现有密文缓冲，避免热路径重复分配
- `SslStateMachineRunner`
  - 负责 pump `MachineT::advance()`
  - 把 driver 结果回调给 machine 的 `onHandshake/onRecv/onSend/onShutdown`
  - 复用 `galay-kernel` 状态机 awaitable 的执行思路，不重新实现旧任务队列

### 2.2 Built-in SSL awaitables become built-in machines

以下内建 awaitable 不再拥有各自的旧式调度框架：

- `SslHandshakeAwaitable`
- `SslRecvAwaitable`
- `SslSendAwaitable`
- `SslShutdownAwaitable`

迁移后它们应当只是：

- 某个内建 machine 的轻封装，或者
- Builder 预组装流程的薄包装

这意味着：

- 业务 awaitable
- 用户自定义状态机
- Builder 线性协议流

都会走同一条状态机热路径。

### 2.3 Builder surface

`SslAwaitableBuilder` 至少支持：

- `fromStateMachine(...)`
- `handshake(...)`
- `recv(...)`
- `send(...)`
- `shutdown(...)`
- `parse(...)`
- `local(...)`
- `finish(...)`

典型使用目标：

```cpp
auto awaitable = SslAwaitableBuilder<Result, 8, Flow>(&socket, flow)
    .handshake<&Flow::onHandshake>()
    .recv<&Flow::onRecv>(flow.buf, sizeof(flow.buf))
    .parse<&Flow::onParse>()
    .send<&Flow::onSend>(flow.reply.data(), flow.reply.size())
    .shutdown<&Flow::onShutdown>()
    .build();
```

## 3. Data Flow

### 3.1 Handshake

`co_await socket.handshake()` 的完整数据流：

1. machine 发出 `handshake`
2. driver 调 `SslEngine::handshake()`
3. 若引擎需要发密文，driver 刷出 BIO 数据并通过底层 send 完成
4. 若引擎需要收密文，driver 注册底层 recv，把收到的数据喂回 BIO
5. driver 内部循环直至握手成功或失败
6. machine 收到最终 `expected<void, SslError>`

### 3.2 Recv / Send

- `recv`
  - machine 请求“读明文”
  - driver 负责收密文、喂 BIO、解密、必要时发送反向握手/重协商相关输出
  - machine 只接收最终明文结果 `expected<Bytes, SslError>`
- `send`
  - machine 请求“发明文”
  - driver 负责 `SSL_write`、BIO flush、raw send 分块推进
  - machine 只接收最终明文字节数 `expected<size_t, SslError>`

### 3.3 Shutdown

- 关闭流程与 handshake 类似
- driver 内部完成 `SSL_shutdown` 多轮推进
- 业务层只得到最终成功 / 失败

## 4. Files To Change

### Core runtime path

- Modify: `galay-ssl/async/Awaitable.h`
- Modify: `galay-ssl/async/Awaitable.cc`
- Modify: `galay-ssl/async/SslSocket.h`
- Modify: `galay-ssl/async/SslSocket.cc`
- Create: `galay-ssl/async/SslAwaitableCore.h`
- Create: `galay-ssl/async/SslAwaitableCore.cc`

### Public/module surface

- Modify: `galay-ssl/module/ModulePrelude.hpp`
- Modify: `galay-ssl/module/galay.ssl.cppm`

### Tests / examples / benchmark

- Modify: `test/T1-ssl_socket_test.cc`
- Modify: `test/T2-ssl_loopback_smoke.cc`
- Create: `test/T3-ssl_single_shot_semantics.cc`
- Create: `test/T4-ssl_state_machine_surface.cc`
- Create: `test/T5-ssl_builder_surface.cc`
- Create: `test/T6-ssl_recv_send_state_machine.cc`
- Create: `test/T7-ssl_custom_state_machine.cc`
- Create: `test/T8-ssl_builder_protocol.cc`
- Modify: `examples/include/E1-ssl_echo_server.cc`
- Modify: `examples/include/E2-ssl_client.cc`
- Create: `examples/include/E3-ssl_custom_awaitable.cc`
- Create: `examples/include/E4-ssl_builder_protocol.cc`
- Modify: `examples/import/E1-ssl_echo_server.cc`
- Modify: `examples/import/E2-ssl_client.cc`
- Create: `examples/import/E3-ssl_custom_awaitable.cc`
- Create: `examples/import/E4-ssl_builder_protocol.cc`
- Modify: `benchmark/B1-ssl_bench_server.cc`
- Modify: `benchmark/B1-ssl_bench_client.cc`

## 5. Error Handling

- `WantRead/WantWrite` 只允许留在 driver 内部
- `SslSocket` 对外返回统一 `SslError`
- BIO flush / raw recv / raw send / TLS handshake / TLS shutdown 的中间态全部在内部收口
- 遇到 `IOError` 时在 driver 内部统一映射成 `SslError`

## 6. Performance Constraints

- 不在热路径引入 `std::function`
- 不在热路径做额外堆分配
- 复用现有 cipher buffer
- built-in awaitables 与自定义 machine 共享同一执行骨架，避免双套实现带来的行为漂移

## 7. Verification Strategy

### 7.1 Red baseline

先保留当前 fresh 编译失败作为 red：

- `galay-ssl` 指向 fresh `galay-kernel` 安装前缀时应当复现旧 `CustomAwaitable` 编译错误

### 7.2 Green verification after cutover

至少完成以下 fresh 验证：

- `galay-ssl` fresh configure/build with installed `galay-kernel`
- `T1-SslSocketTest`
- `T2-SslLoopbackSmoke`
- 新增 `T3`~`T8`
- include examples fresh 运行
- benchmark fresh 运行
- install + consumer smoke

### 7.3 Acceptance

迁移签收标准：

- `galay-ssl` 源码中不再出现 `CustomAwaitable`
- `galay-ssl` fresh 构建可通过
- 仓库 tests/examples/benchmark 全过
- 安装与 consumer smoke 可通过

## 8. Recommended Implementation Order

1. 先新增 SSL 共享执行骨架与最小 failing surface test
2. 把 `handshake` / `shutdown` 切到单次语义 machine
3. 把 `recv` / `send` 切到新模型
4. 开放 `SslAwaitableBuilder` / 自定义 state machine 面
5. 更新 examples、tests、benchmark、module surface
6. 最后删除所有旧 `CustomAwaitable` 残留与相关文档表述
