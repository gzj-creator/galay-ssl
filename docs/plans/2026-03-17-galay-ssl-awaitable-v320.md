# galay-ssl Awaitable v3.2.0 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 把 `galay-ssl` 完整迁移到 `galay-kernel v3.2.0` 的共享状态机 Awaitable 模型，升级 `handshake()` / `shutdown()` 为单次语义，并开放 SSL 状态机 / Builder 扩展面，同时完成性能对比。

**Architecture:** 先用测试锁定单次语义和公开 API，再抽出共享 `SslOperationDriver` 与状态机 runner，把内建 `handshake/recv/send/shutdown` 迁到共享执行路径，最后补齐用户自定义状态机 / Builder、官方示例、benchmark 和文档。整个实现遵循 TDD，任何对外语义变化都先写失败测试再改代码。

**Tech Stack:** C++23、OpenSSL Memory BIO、`galay-kernel v3.2.0` `StateMachineAwaitable` / `AwaitableBuilder`、CMake、仓库内 tests / examples / benchmark。

---

### Task 1: 锁定单次语义与公开 API 面

**Files:**
- Modify: `test/CMakeLists.txt`
- Create: `test/T3-ssl_single_shot_semantics.cc`
- Create: `test/T4-ssl_state_machine_surface.cc`
- Create: `test/T5-ssl_builder_surface.cc`
- Reference: `test/T2-ssl_loopback_smoke.cc`
- Reference: `galay-ssl/async/SslSocket.h`
- Reference: `galay-ssl/async/Awaitable.h`

**Step 1: 写单次语义失败测试**

新增 `test/T3-ssl_single_shot_semantics.cc`，要求：

- 服务端与客户端都只 `co_await socket.handshake()` 一次
- 服务端与客户端都只 `co_await socket.shutdown()` 一次
- 不允许测试内部再写 `while (!socket.isHandshakeCompleted())`
- 成功条件：
  - 握手完成
  - 一次 echo 完成
  - shutdown 成功

参考骨架：

```cpp
auto handshakeResult = co_await socket.handshake();
expect(handshakeResult.has_value(), "single-shot handshake failed");

auto shutdownResult = co_await socket.shutdown();
expect(shutdownResult.has_value(), "single-shot shutdown failed");
```

**Step 2: 写扩展面失败测试**

新增 `test/T4-ssl_state_machine_surface.cc`，验证这些类型和入口在编译层面可用：

- `SslMachineSignal`
- `SslMachineAction<ResultT>`
- `SslStateMachineAwaitable<MachineT>`
- `SslAwaitableBuilder<ResultT>::fromStateMachine(...)`

新增 `test/T5-ssl_builder_surface.cc`，验证链式 Builder 至少支持：

- `handshake(...)`
- `recv(...)`
- `parse(...)`
- `send(...)`
- `shutdown(...)`

可以先只做最小编译型 / 轻量运行型测试。

**Step 3: 运行测试确认失败**

Run:

```bash
cmake -S . -B build-awaitable-v320 -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON
cmake --build build-awaitable-v320 --target T3-SslSingleShotSemantics T4-SslStateMachineSurface T5-SslBuilderSurface
```

Expected:

- 至少一个测试编译失败
- 失败点应指向：
  - `handshake()` / `shutdown()` 仍是旧语义
  - SSL 状态机 / Builder 公开类型尚未存在

**Step 4: 提交测试基线**

```bash
git add test/CMakeLists.txt test/T3-ssl_single_shot_semantics.cc test/T4-ssl_state_machine_surface.cc test/T5-ssl_builder_surface.cc
git commit -m "test: add ssl awaitable v3.2.0 surface coverage"
```

### Task 2: 抽出共享 SSL 状态机执行内核

**Files:**
- Create: `galay-ssl/async/SslAwaitableCore.h`
- Create: `galay-ssl/async/SslAwaitableCore.cc`
- Modify: `galay-ssl/async/Awaitable.h`
- Modify: `galay-ssl/async/Awaitable.cc`
- Modify: `galay-ssl/async/SslSocket.h`
- Modify: `galay-ssl/async/SslSocket.cc`
- Modify: `galay-ssl/module/ModulePrelude.hpp`
- Modify: `galay-ssl/module/galay.ssl.cppm`

**Step 1: 写共享内核最小定义**

在 `SslAwaitableCore.h` 中定义内部执行骨架：

- `SslOperationKind`
- `SslOperationDriver`
- `SslMachineSignal`
- `SslMachineAction<ResultT>`
- `SslStateMachineAwaitable<MachineT>`
- `SslStateMachineBuilder<...>` 或 `SslAwaitableBuilder::fromStateMachine(...)` 依赖的内部桥接结构

关键约束：

- 不使用 `std::function`
- 用户动作是 SSL 语义动作，不是 raw `waitRead/waitWrite`
- Driver 内部持有或借用 `SslSocket` / `SslEngine` / cipher buffer

建议骨架：

```cpp
enum class SslMachineSignal {
    kContinue,
    kHandshake,
    kRecv,
    kSend,
    kShutdown,
    kComplete,
    kFail,
};
```

**Step 2: 实现 Driver 的最小可运行路径**

在 `SslAwaitableCore.cc` 先实现：

- handshake 单次推进
- shutdown 单次推进
- 统一处理 `WantRead/WantWrite`
- 统一处理 BIO 输入输出与 raw socket 事件

先不求 Builder 完整，只求内建 handshake / shutdown 能跑通。

**Step 3: 把 `SslSocket` 接入共享内核**

在 `SslSocket.h/.cc` 中补充共享内核需要的入口：

- builder / machine 构建辅助函数
- 对 `SslEngine` / `IOController` / 复用缓冲区的安全访问

模块面同步导出新增公开类型。

**Step 4: 运行测试确认新骨架编译**

Run:

```bash
cmake --build build-awaitable-v320 --target galay-ssl T4-SslStateMachineSurface
./build-awaitable-v320/bin/T4-SslStateMachineSurface
```

Expected:

- `galay-ssl` 编译通过
- `T4-SslStateMachineSurface` 通过
- `T3` / `T5` 仍可能失败，这是允许的

**Step 5: 提交共享内核骨架**

```bash
git add galay-ssl/async/SslAwaitableCore.h galay-ssl/async/SslAwaitableCore.cc galay-ssl/async/Awaitable.h galay-ssl/async/Awaitable.cc galay-ssl/async/SslSocket.h galay-ssl/async/SslSocket.cc galay-ssl/module/ModulePrelude.hpp galay-ssl/module/galay.ssl.cppm
git commit -m "refactor: add shared ssl awaitable state machine core"
```

### Task 3: 升级 handshake / shutdown 为单次语义

**Files:**
- Modify: `galay-ssl/async/Awaitable.h`
- Modify: `galay-ssl/async/Awaitable.cc`
- Modify: `galay-ssl/async/SslSocket.h`
- Modify: `galay-ssl/async/SslSocket.cc`
- Modify: `test/T2-ssl_loopback_smoke.cc`
- Modify: `test/T3-ssl_single_shot_semantics.cc`
- Modify: `examples/include/E1-ssl_echo_server.cc`
- Modify: `examples/include/E2-ssl_client.cc`
- Modify: `examples/import/E1-ssl_echo_server.cc`
- Modify: `examples/import/E2-ssl_client.cc`
- Modify: `benchmark/B1-ssl_bench_server.cc`
- Modify: `benchmark/B1-ssl_bench_client.cc`

**Step 1: 先改内建 handshake / shutdown 实现**

要求：

- `SslHandshakeAwaitable` 只 `co_await` 一次就完成整轮握手
- `SslShutdownAwaitable` 只 `co_await` 一次就完成整轮关闭
- 业务层不再接触 `kHandshakeWantRead` / `kHandshakeWantWrite`

**Step 2: 修改业务、示例与 benchmark 调用点**

把以下旧代码删掉：

```cpp
while (!socket.isHandshakeCompleted()) {
    auto result = co_await socket.handshake();
    ...
}
```

统一改成：

```cpp
auto handshakeResult = co_await socket.handshake();
if (!handshakeResult) {
    ...
}
```

`shutdown()` 同理。

**Step 3: 运行单次语义测试**

Run:

```bash
cmake --build build-awaitable-v320 --target T2-SslLoopbackSmoke T3-SslSingleShotSemantics E1-SslEchoServer-Include E2-SslClient-Include B1-SslBenchServer B1-SslBenchClient
./build-awaitable-v320/bin/T2-SslLoopbackSmoke
./build-awaitable-v320/bin/T3-SslSingleShotSemantics
```

Expected:

- `T2` 通过
- `T3` 通过
- 旧循环语义已从示例和 benchmark 中移除

**Step 4: 提交单次语义改造**

```bash
git add galay-ssl/async/Awaitable.h galay-ssl/async/Awaitable.cc galay-ssl/async/SslSocket.h galay-ssl/async/SslSocket.cc test/T2-ssl_loopback_smoke.cc test/T3-ssl_single_shot_semantics.cc examples/include/E1-ssl_echo_server.cc examples/include/E2-ssl_client.cc examples/import/E1-ssl_echo_server.cc examples/import/E2-ssl_client.cc benchmark/B1-ssl_bench_server.cc benchmark/B1-ssl_bench_client.cc
git commit -m "refactor: make ssl handshake and shutdown single-shot"
```

### Task 4: 迁移 recv / send 到共享执行路径

**Files:**
- Modify: `galay-ssl/async/Awaitable.h`
- Modify: `galay-ssl/async/Awaitable.cc`
- Modify: `galay-ssl/async/SslAwaitableCore.h`
- Modify: `galay-ssl/async/SslAwaitableCore.cc`
- Create: `test/T6-ssl_recv_send_state_machine.cc`

**Step 1: 写 recv / send 失败测试**

在 `test/T6-ssl_recv_send_state_machine.cc` 中锁定以下行为：

- `recv()` 仍返回明文 `Bytes`
- `send()` 仍返回明文字节数
- 小包、多轮 BIO flush、对端关闭场景都能正确结束

**Step 2: 改写 `SslRecvAwaitable` / `SslSendAwaitable`**

实现要求：

- 不再基于 `CustomAwaitable`
- 改为基于共享 Driver + machine runner
- 继续复用 cipher buffer
- 不在热路径额外分配

**Step 3: 运行 recv / send 回归**

Run:

```bash
cmake --build build-awaitable-v320 --target T2-SslLoopbackSmoke T6-SslRecvSendStateMachine
./build-awaitable-v320/bin/T2-SslLoopbackSmoke
./build-awaitable-v320/bin/T6-SslRecvSendStateMachine
```

Expected:

- `T2` 继续通过
- `T6` 通过
- `recv()` / `send()` 兼容现有业务语义

**Step 4: 提交 recv / send 迁移**

```bash
git add galay-ssl/async/Awaitable.h galay-ssl/async/Awaitable.cc galay-ssl/async/SslAwaitableCore.h galay-ssl/async/SslAwaitableCore.cc test/T6-ssl_recv_send_state_machine.cc
git commit -m "refactor: move ssl recv send onto shared state machine core"
```

### Task 5: 开放用户自定义 SSL 状态机与 Builder

**Files:**
- Modify: `galay-ssl/async/Awaitable.h`
- Modify: `galay-ssl/async/Awaitable.cc`
- Modify: `galay-ssl/async/SslSocket.h`
- Modify: `galay-ssl/async/SslSocket.cc`
- Modify: `test/T4-ssl_state_machine_surface.cc`
- Modify: `test/T5-ssl_builder_surface.cc`
- Create: `test/T7-ssl_custom_state_machine.cc`
- Create: `test/T8-ssl_builder_protocol.cc`
- Modify: `examples/CMakeLists.txt`
- Create: `examples/include/E3-ssl_custom_awaitable.cc`
- Create: `examples/include/E4-ssl_builder_protocol.cc`
- Create: `examples/import/E3-ssl_custom_awaitable.cc`
- Create: `examples/import/E4-ssl_builder_protocol.cc`

**Step 1: 实现状态机入口**

提供：

- `SslMachineAction<ResultT>`
- `SslStateMachineAwaitable<MachineT>`
- `SslAwaitableBuilder<ResultT>::fromStateMachine(...)`

让 `T4` 能真正运行，而不只是编译通过。

**Step 2: 实现 Builder DSL**

Builder 至少支持：

- `handshake(...)`
- `recv(...)`
- `parse(...)`
- `send(...)`
- `shutdown(...)`
- `local(...)`
- `finish(...)`

并明确禁止错误用法，保持和 `galay-kernel v3.2.0` 一致的约束风格。

**Step 3: 补最小测试与示例**

- `T7-ssl_custom_state_machine.cc`
  - 用最小 machine 跑 `handshake -> recv -> send -> shutdown`
- `T8-ssl_builder_protocol.cc`
  - 用最小 Builder 跑 `handshake -> recv -> parse -> send -> shutdown`
- `E3-ssl_custom_awaitable.cc`
  - 官方最小自定义状态机示例
- `E4-ssl_builder_protocol.cc`
  - 官方最小 Builder 协议流示例

**Step 4: 运行扩展面回归**

Run:

```bash
cmake --build build-awaitable-v320 --target T4-SslStateMachineSurface T5-SslBuilderSurface T7-SslCustomStateMachine T8-SslBuilderProtocol E3-SslCustomAwaitable-Include E4-SslBuilderProtocol-Include
./build-awaitable-v320/bin/T4-SslStateMachineSurface
./build-awaitable-v320/bin/T5-SslBuilderSurface
./build-awaitable-v320/bin/T7-SslCustomStateMachine
./build-awaitable-v320/bin/T8-SslBuilderProtocol
./build-awaitable-v320/bin/E3-SslCustomAwaitable-Include
./build-awaitable-v320/bin/E4-SslBuilderProtocol-Include
```

Expected:

- 状态机和 Builder 测试全部通过
- 最小示例可以直接运行成功

**Step 5: 提交公开扩展面**

```bash
git add galay-ssl/async/Awaitable.h galay-ssl/async/Awaitable.cc galay-ssl/async/SslSocket.h galay-ssl/async/SslSocket.cc test/T4-ssl_state_machine_surface.cc test/T5-ssl_builder_surface.cc test/T7-ssl_custom_state_machine.cc test/T8-ssl_builder_protocol.cc examples/CMakeLists.txt examples/include/E3-ssl_custom_awaitable.cc examples/include/E4-ssl_builder_protocol.cc examples/import/E3-ssl_custom_awaitable.cc examples/import/E4-ssl_builder_protocol.cc
git commit -m "feat: expose ssl awaitable state machine and builder APIs"
```

### Task 6: 补齐 benchmark 与性能对比

**Files:**
- Modify: `benchmark/CMakeLists.txt`
- Create: `benchmark/B2-ssl_handshake.cc`
- Create: `benchmark/B3-ssl_recv_echo.cc`
- Create: `benchmark/B4-ssl_send_echo.cc`
- Optional: `benchmark/B5-ssl_shutdown.cc`
- Modify: `benchmark/B1-ssl_bench_server.cc`
- Modify: `benchmark/B1-ssl_bench_client.cc`
- Modify: `benchmark/SslStats.h`
- Modify: `benchmark/SslStats.cc`
- Modify: `docs/05-性能测试.md`

**Step 1: 新增分项 benchmark**

要求：

- `B2-SslHandshake` 只看握手耗时 / 成功率
- `B3-SslRecvEcho` 固定完成握手后测 recv 热路径
- `B4-SslSendEcho` 固定完成握手后测 send 热路径

如 shutdown 也出现不稳定或性能风险，再补 `B5-SslShutdown`。

**Step 2: 固化对比命令**

至少准备这两组命令：

```bash
./build-awaitable-v320/bin/B1-SslBenchServer 8443 certs/server.crt certs/server.key
./build-awaitable-v320/bin/B1-SslBenchClient 127.0.0.1 8443 200 500 47 4
```

```bash
./build-awaitable-v320/bin/B2-SslHandshake ...
./build-awaitable-v320/bin/B3-SslRecvEcho ...
./build-awaitable-v320/bin/B4-SslSendEcho ...
```

并把参数、输出字段、判定阈值写进 `docs/05-性能测试.md`。

**Step 3: 先跑迁移前基线，再跑迁移后结果**

基线方式：

- 在实现前的 commit 上运行一次 `B1/B2/B3/B4`
- 保存日志

迁移后方式：

- 在完成实现的 `HEAD` 上运行同样命令
- 保持同一台机器、同一编译模式、同一证书和并发参数

**Step 4: 验证性能阈值**

Expected:

- `B1` 总体吞吐和关键错误指标无明显劣化
- `B2/B3/B4` 回退不超过 `5%`
- 若超过阈值，继续调优热路径，不进入最终收尾

**Step 5: 提交 benchmark 与性能口径**

```bash
git add benchmark/CMakeLists.txt benchmark/B1-ssl_bench_server.cc benchmark/B1-ssl_bench_client.cc benchmark/B2-ssl_handshake.cc benchmark/B3-ssl_recv_echo.cc benchmark/B4-ssl_send_echo.cc benchmark/SslStats.h benchmark/SslStats.cc docs/05-性能测试.md
git commit -m "bench: add ssl awaitable migration performance coverage"
```

### Task 7: 文档收口与最终验证

**Files:**
- Modify: `README.md`
- Modify: `docs/01-架构设计.md`
- Modify: `docs/02-API参考.md`
- Modify: `docs/03-使用指南.md`
- Modify: `docs/04-示例代码.md`
- Modify: `docs/05-性能测试.md`
- Modify: `docs/06-高级主题.md`

**Step 1: 更新文档到新语义**

必须覆盖：

- `handshake()` / `shutdown()` 已改为单次语义
- 新增 SSL 状态机与 Builder 扩展面
- 新增官方 examples `E3` / `E4`
- benchmark 口径改为“整体 + 分项”

**Step 2: 跑最终 fresh 验证**

Run:

```bash
cmake -S . -B build-awaitable-v320 -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON
cmake --build build-awaitable-v320 --parallel
./scripts/run.sh test
./build-awaitable-v320/bin/E1-SslEchoServer-Include 8443 certs/server.crt certs/server.key
./build-awaitable-v320/bin/E2-SslClient-Include 127.0.0.1 8443
./build-awaitable-v320/bin/E3-SslCustomAwaitable-Include
./build-awaitable-v320/bin/E4-SslBuilderProtocol-Include
```

Expected:

- 全量构建通过
- 所有 test target 通过
- include 示例都通过
- benchmark 与性能对比日志已生成

**Step 3: 记录最终性能结论**

把实际结果写入：

- `docs/05-性能测试.md`
- 如有必要，补一份结果记录到 `docs/plans/` 下

只写真实 fresh 结果，不写“预计”“应当”。

**Step 4: 提交文档与最终验证收尾**

```bash
git add README.md docs/01-架构设计.md docs/02-API参考.md docs/03-使用指南.md docs/04-示例代码.md docs/05-性能测试.md docs/06-高级主题.md
git commit -m "docs: finalize galay-ssl awaitable v3.2.0 rollout"
```
