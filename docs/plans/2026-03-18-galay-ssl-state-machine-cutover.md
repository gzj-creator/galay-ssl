# galay-ssl State Machine Cutover Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 一次性移除 `galay-ssl` 中所有旧 `CustomAwaitable` 路径，让 `SslSocket` 与用户扩展面全部切到新的状态机 / Builder 模型，并通过 fresh `galay-kernel` 安装链验证。

**Architecture:** 在 `galay-ssl/async/` 下新增共享 `SslAwaitableCore`，把 OpenSSL Memory BIO 驱动、`WantRead/WantWrite` 收口和底层 IO 推进统一放进一个状态机执行骨架。`SslHandshakeAwaitable`、`SslRecvAwaitable`、`SslSendAwaitable`、`SslShutdownAwaitable` 都改成内建 machine/Builder 的薄封装，同时公开 `SslStateMachineAwaitable` 与 `SslAwaitableBuilder` 给用户扩展。

**Tech Stack:** C++23、OpenSSL Memory BIO、`galay-kernel v3.2.0` `StateMachineAwaitable` / `AwaitableBuilder`、CMake、仓库内 tests/examples/benchmark、fresh install smoke。

---

### Task 1: 固定当前 red 基线并补第一批表面测试

**Files:**
- Modify: `test/CMakeLists.txt`
- Create: `test/T3-ssl_single_shot_semantics.cc`
- Create: `test/T4-ssl_state_machine_surface.cc`
- Reference: `test/T2-ssl_loopback_smoke.cc`
- Reference: `galay-ssl/async/Awaitable.h`

**Step 1: 写 failing tests**

- `T3-ssl_single_shot_semantics.cc`
  - 验证 `handshake()` / `shutdown()` 作为单次语义 awaitable，只返回最终成功/失败，不要求业务循环处理 `WantRead/WantWrite`
- `T4-ssl_state_machine_surface.cc`
  - 验证新公开类型能被声明和实例化：
    - `SslMachineAction<ResultT>`
    - `SslStateMachineAwaitable<MachineT>`
    - `SslAwaitableBuilder<ResultT>::fromStateMachine(...)`

**Step 2: 运行 tests 证明当前失败**

Run:

```bash
cmake -S . -B build-plan-red \
  -DCMAKE_PREFIX_PATH=/Users/gongzhijie/Desktop/projects/git/galay-kernel/.verify-install-kernel-20260318 \
  -DBUILD_BENCHMARKS=OFF
cmake --build build-plan-red --parallel
```

Expected:

- 编译失败，报 `CustomAwaitable` 未定义
- 新增 `T3/T4` 若被编译到，也应因 surface 未实现而失败

**Step 3: 不写生产代码，只记录 red**

- 把失败输出保留为迁移前证据

**Step 4: Commit**

```bash
git add test/CMakeLists.txt test/T3-ssl_single_shot_semantics.cc test/T4-ssl_state_machine_surface.cc
git commit -m "test: add ssl state machine cutover red tests"
```

### Task 2: 引入共享 SSL 执行骨架并替换 handshake/shutdown

**Files:**
- Create: `galay-ssl/async/SslAwaitableCore.h`
- Create: `galay-ssl/async/SslAwaitableCore.cc`
- Modify: `galay-ssl/async/Awaitable.h`
- Modify: `galay-ssl/async/Awaitable.cc`
- Modify: `galay-ssl/async/SslSocket.h`
- Modify: `galay-ssl/async/SslSocket.cc`
- Test: `test/T3-ssl_single_shot_semantics.cc`

**Step 1: 先写最小内核接口**

- 在 `SslAwaitableCore.h` 声明：
  - `SslMachineAction<ResultT>`
  - `SslStateMachineAwaitable<MachineT>`
  - `SslOperationDriver`
- 在 `Awaitable.h` 中把 `SslHandshakeAwaitable` / `SslShutdownAwaitable` 改为基于新内核的薄封装

**Step 2: 跑 `T3` 让它继续 fail，但失败形态收敛**

Run:

```bash
cmake --build build-plan-red --target T3-SslSingleShotSemantics --parallel
```

Expected:

- 失败原因从 “缺失 `CustomAwaitable`” 收敛到 “接口未完成 / 逻辑未完成”

**Step 3: 实现最小 green**

- `SslOperationDriver` 收口：
  - `handshake`
  - `shutdown`
- `SslSocket::handshake()` / `shutdown()` 改成单次语义
- 删除 handshake/shutdown 对旧任务队列的依赖

**Step 4: 跑目标测试**

Run:

```bash
cmake --build build-plan-red --target T3-SslSingleShotSemantics T2-SslLoopbackSmoke --parallel
./build-plan-red/bin/T3-SslSingleShotSemantics
./build-plan-red/bin/T2-SslLoopbackSmoke
```

Expected:

- `T3` PASS
- `T2` PASS

**Step 5: Commit**

```bash
git add galay-ssl/async/SslAwaitableCore.h galay-ssl/async/SslAwaitableCore.cc galay-ssl/async/Awaitable.h galay-ssl/async/Awaitable.cc galay-ssl/async/SslSocket.h galay-ssl/async/SslSocket.cc test/T3-ssl_single_shot_semantics.cc
git commit -m "feat: migrate ssl handshake shutdown to state machine core"
```

### Task 3: 迁移 recv/send 到新状态机路径

**Files:**
- Modify: `galay-ssl/async/Awaitable.h`
- Modify: `galay-ssl/async/Awaitable.cc`
- Modify: `galay-ssl/async/SslAwaitableCore.h`
- Modify: `galay-ssl/async/SslAwaitableCore.cc`
- Create: `test/T5-ssl_recv_send_state_machine.cc`
- Reference: `test/T2-ssl_loopback_smoke.cc`

**Step 1: 写 failing test**

- `T5-ssl_recv_send_state_machine.cc`
  - 覆盖 `recv()` / `send()` 在新内核下的回环行为
  - 验证不再依赖旧 `m_tasks/addTask` 任务队列

**Step 2: 验证 red**

Run:

```bash
cmake --build build-plan-red --target T5-SslRecvSendStateMachine --parallel
./build-plan-red/bin/T5-SslRecvSendStateMachine
```

Expected:

- FAIL，原因是 `recv/send` 仍未迁完或行为不一致

**Step 3: 写最小实现**

- 把 `SslRecvAwaitable` / `SslSendAwaitable` 改成内建 machine 或新 driver 封装
- 删除：
  - `CustomAwaitable(controller)`
  - `m_tasks`
  - `m_cursor`
  - `addTask(...)`
  - `onCompleted()` 的旧路径依赖

**Step 4: 运行目标测试**

Run:

```bash
cmake --build build-plan-red --target T2-SslLoopbackSmoke T5-SslRecvSendStateMachine --parallel
./build-plan-red/bin/T2-SslLoopbackSmoke
./build-plan-red/bin/T5-SslRecvSendStateMachine
```

Expected:

- `T2` PASS
- `T5` PASS

**Step 5: Commit**

```bash
git add galay-ssl/async/Awaitable.h galay-ssl/async/Awaitable.cc galay-ssl/async/SslAwaitableCore.h galay-ssl/async/SslAwaitableCore.cc test/T5-ssl_recv_send_state_machine.cc
git commit -m "feat: migrate ssl recv send to state machine core"
```

### Task 4: 正式开放 SSL 自定义状态机 / Builder 扩展面

**Files:**
- Modify: `galay-ssl/async/Awaitable.h`
- Modify: `galay-ssl/async/Awaitable.cc`
- Modify: `galay-ssl/async/SslSocket.h`
- Modify: `galay-ssl/module/ModulePrelude.hpp`
- Modify: `galay-ssl/module/galay.ssl.cppm`
- Create: `test/T6-ssl_custom_state_machine.cc`
- Create: `test/T7-ssl_builder_surface.cc`
- Create: `test/T8-ssl_builder_protocol.cc`

**Step 1: 写 failing tests**

- `T6-ssl_custom_state_machine.cc`
  - 用户自定义 machine 走 `handshake -> recv -> send -> shutdown`
- `T7-ssl_builder_surface.cc`
  - surface 编译面：`fromStateMachine()`、`handshake()`、`recv()`、`send()`、`shutdown()`、`finish()`
- `T8-ssl_builder_protocol.cc`
  - 线性 builder 协议闭环

**Step 2: 验证 red**

Run:

```bash
cmake --build build-plan-red --target T6-SslCustomStateMachine T7-SslBuilderSurface T8-SslBuilderProtocol --parallel
```

Expected:

- FAIL，提示新 surface 还未完备

**Step 3: 实现公开扩展面**

- 在 `Awaitable.h` 中公开：
  - `SslMachineAction<ResultT>`
  - `SslStateMachineAwaitable<MachineT>`
  - `SslAwaitableBuilder<ResultT, InlineN, FlowT>`
- 在模块前置头和模块接口中同步导出

**Step 4: 跑目标测试**

Run:

```bash
cmake --build build-plan-red --target T4-SslStateMachineSurface T6-SslCustomStateMachine T7-SslBuilderSurface T8-SslBuilderProtocol --parallel
./build-plan-red/bin/T4-SslStateMachineSurface
./build-plan-red/bin/T6-SslCustomStateMachine
./build-plan-red/bin/T7-SslBuilderSurface
./build-plan-red/bin/T8-SslBuilderProtocol
```

Expected:

- 全部 PASS

**Step 5: Commit**

```bash
git add galay-ssl/async/Awaitable.h galay-ssl/async/Awaitable.cc galay-ssl/async/SslSocket.h galay-ssl/module/ModulePrelude.hpp galay-ssl/module/galay.ssl.cppm test/T4-ssl_state_machine_surface.cc test/T6-ssl_custom_state_machine.cc test/T7-ssl_builder_surface.cc test/T8-ssl_builder_protocol.cc
git commit -m "feat: expose ssl state machine and builder surfaces"
```

### Task 5: 更新 examples 与 benchmark 到新模型

**Files:**
- Modify: `examples/include/E1-ssl_echo_server.cc`
- Modify: `examples/include/E2-ssl_client.cc`
- Create: `examples/include/E3-ssl_custom_awaitable.cc`
- Create: `examples/include/E4-ssl_builder_protocol.cc`
- Modify: `examples/import/E1-ssl_echo_server.cc`
- Modify: `examples/import/E2-ssl_client.cc`
- Create: `examples/import/E3-ssl_custom_awaitable.cc`
- Create: `examples/import/E4-ssl_builder_protocol.cc`
- Modify: `examples/CMakeLists.txt`
- Modify: `benchmark/B1-ssl_bench_server.cc`
- Modify: `benchmark/B1-ssl_bench_client.cc`

**Step 1: 先改 include examples**

- 去掉业务层对 handshake/shutdown 显式循环
- 新增最小自定义状态机示例
- 新增 Builder 协议示例

**Step 2: 跑 examples**

Run:

```bash
cmake --build build-plan-red --target E1-SslEchoServer-Include E2-SslClient-Include E3-SslCustomAwaitable-Include E4-SslBuilderProtocol-Include --parallel
```

Expected:

- 全部编译通过

**Step 3: 更新 benchmark**

- 基于新的 `SslSocket` 语义更新 `B1`
- 不允许 benchmark 内部继续依赖旧 `CustomAwaitable`

**Step 4: 跑 benchmark build**

Run:

```bash
cmake --build build-plan-red --target B1-SslBenchServer B1-SslBenchClient --parallel
```

Expected:

- 两个 benchmark target 编译通过

**Step 5: Commit**

```bash
git add examples/CMakeLists.txt examples/include/E1-ssl_echo_server.cc examples/include/E2-ssl_client.cc examples/include/E3-ssl_custom_awaitable.cc examples/include/E4-ssl_builder_protocol.cc examples/import/E1-ssl_echo_server.cc examples/import/E2-ssl_client.cc examples/import/E3-ssl_custom_awaitable.cc examples/import/E4-ssl_builder_protocol.cc benchmark/B1-ssl_bench_server.cc benchmark/B1-ssl_bench_client.cc
git commit -m "feat: migrate ssl examples and benchmark to new awaitable model"
```

### Task 6: 完整 fresh 验证与旧路径清零

**Files:**
- Modify: `README.md`
- Modify: `docs/00-快速开始.md`
- Modify: `docs/01-架构设计.md`
- Modify: `docs/02-API参考.md`
- Modify: `docs/03-使用指南.md`
- Modify: `docs/06-高级主题.md`

**Step 1: 先做残留扫描**

Run:

```bash
rg -n "\\bCustomAwaitable\\b|\\bm_tasks\\b|\\baddTask\\(" galay-ssl test examples benchmark docs
```

Expected:

- 只允许命中历史设计文档；源码、测试、示例、benchmark 不再命中

**Step 2: fresh 构建与仓库内验证**

Run:

```bash
cmake -S . -B build-final \
  -DCMAKE_PREFIX_PATH=/Users/gongzhijie/Desktop/projects/git/galay-kernel/.verify-install-kernel-20260318 \
  -DBUILD_BENCHMARKS=ON
cmake --build build-final --parallel
./build-final/bin/T1-SslSocketTest
./build-final/bin/T2-SslLoopbackSmoke
./build-final/bin/T3-SslSingleShotSemantics
./build-final/bin/T4-SslStateMachineSurface
./build-final/bin/T5-SslRecvSendStateMachine
./build-final/bin/T6-SslCustomStateMachine
./build-final/bin/T7-SslBuilderSurface
./build-final/bin/T8-SslBuilderProtocol
```

Expected:

- 全部 PASS

**Step 3: install + consumer smoke**

Run:

```bash
cmake --install build-final --prefix .verify-install-ssl
cmake -S /tmp/galay-ssl-consumer-20260318 -B /tmp/galay-ssl-consumer-build-20260318 \
  -DCMAKE_PREFIX_PATH=\"$(pwd)/.verify-install-ssl;/Users/gongzhijie/Desktop/projects/git/galay-kernel/.verify-install-kernel-20260318\"
cmake --build /tmp/galay-ssl-consumer-build-20260318 --parallel
/tmp/galay-ssl-consumer-build-20260318/galay_ssl_consumer
```

Expected:

- configure/build/run 全部成功

**Step 4: 更新文档**

- 文档只描述新状态机 / Builder 模型
- 不再暗示存在 `CustomAwaitable` 兼容路径

**Step 5: Commit**

```bash
git add README.md docs/00-快速开始.md docs/01-架构设计.md docs/02-API参考.md docs/03-使用指南.md docs/06-高级主题.md
git commit -m "docs: finalize ssl state machine cutover"
```
