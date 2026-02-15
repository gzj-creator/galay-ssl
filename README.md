# galay-ssl

基于 C++23 协程的异步 SSL/TLS 库，属于 galay 生态。

## 特性

- 异步 SSL Socket API（`SslSocket`），支持 `connect/handshake/recv/send/shutdown/close`
- 基于 OpenSSL Memory BIO 的解耦实现（SSL 状态机与网络 IO 分离）
- 支持 TLS 1.2 / TLS 1.3、SNI、ALPN、Session 复用
- 统一 `std::expected` 风格错误返回（`SslError` / `IOError`）
- 与 `galay-kernel` 协程调度器无缝集成
- 支持 `kqueue`（macOS）、`epoll` / `io_uring`（Linux）

## 文档导航

建议按以下顺序阅读：

1. [快速开始](docs/01-快速开始.md)
2. [使用示例](docs/02-使用示例.md)
3. [模块介绍](docs/03-模块介绍.md)
4. [运行原理](docs/04-运行原理.md)
5. [性能分析](docs/05-性能分析.md)

## 依赖

- C++23 编译器（GCC 13+ / Clang 16+）
- CMake 3.16+
- OpenSSL 1.1.1+
- `galay-kernel`
- Linux 下启用 `io_uring` 时需要 `liburing`（缺失时自动回退 `epoll`）

## 编译安装

```bash
git clone https://github.com/gzj-creator/galay-ssl.git
cd galay-ssl

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON
cmake --build build -j

# 安装（可选）
sudo cmake --install build
```

Linux 强制使用 `epoll`：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON -DDISABLE_IOURING=ON
cmake --build build -j
```

如果要显式关闭模块接口（默认开启，工具链支持时生效）：

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_LTO=ON -DBUILD_MODULE_EXAMPLES=OFF
cmake --build build -j
```

## CMake 链接

```cmake
find_package(galay-ssl REQUIRED)
target_link_libraries(your_target PRIVATE galay-ssl::galay-ssl)
```

如果是源码同仓构建（`add_subdirectory`），也可直接链接目标 `galay-ssl`。

## C++23 Modules

`galay-ssl` 现在支持 C++23 `import/export`（工具链支持时）：

```cpp
import galay.ssl;

using namespace galay::ssl;
```

模块接口文件：`galay-ssl/module/galay.ssl.cppm`  
传统 `#include` 用法仍完全可用。  
说明：`BUILD_MODULE_EXAMPLES` 需要 CMake `>= 3.28` 且使用 `Ninja` / `Visual Studio` 生成器。`Unix Makefiles` 下会自动关闭。

`examples/` 中也提供了模块化导入版本：

- `examples/include/E1-SslEchoServer.cc`
- `examples/include/E2-SslClient.cc`
- `examples/import/E1-SslEchoServer.cc`
- `examples/import/E2-SslClient.cc`

### 模块支持更新（2026-02）

本次模块接口已统一为同一范式：

- `module;`
- `#include "galay-ssl/module/ModulePrelude.hpp"`
- `export module galay.ssl;`
- `export { #include ... }`

新增预导入头文件：`galay-ssl/module/ModulePrelude.hpp`，用于把系统/第三方依赖放在全局模块片段，降低模块构建期冲突。

推荐构建命令（Clang 20 + Ninja）：

```bash
cmake -S . -B build-mod -G Ninja \
  -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm@20/bin/clang++
cmake --build build-mod --target galay-ssl-modules -j
```

## 快速开始

```cpp
#include "galay-ssl/async/SslSocket.h"
#include "galay-ssl/ssl/SslContext.h"
#include <galay-kernel/kernel/Coroutine.h>

#ifdef USE_KQUEUE
#include <galay-kernel/kernel/KqueueScheduler.h>
using IOSchedulerType = galay::kernel::KqueueScheduler;
#elif defined(USE_EPOLL)
#include <galay-kernel/kernel/EpollScheduler.h>
using IOSchedulerType = galay::kernel::EpollScheduler;
#elif defined(USE_IOURING)
#include <galay-kernel/kernel/IOUringScheduler.h>
using IOSchedulerType = galay::kernel::IOUringScheduler;
#endif

using namespace galay::ssl;
using namespace galay::kernel;

Coroutine echoClient(SslContext* ctx)
{
    SslSocket sock(ctx);
    sock.option().handleNonBlock();
    sock.setHostname("127.0.0.1");

    auto conn = co_await sock.connect(Host(IPType::IPV4, "127.0.0.1", 8443));
    if (!conn) co_return;

    while (!sock.isHandshakeCompleted()) {
        auto hs = co_await sock.handshake();
        if (!hs) {
            co_await sock.close();
            co_return;
        }
    }

    const char* msg = "hello";
    auto s = co_await sock.send(msg, 5);
    if (!s) {
        co_await sock.close();
        co_return;
    }

    char buf[256];
    auto r = co_await sock.recv(buf, sizeof(buf));
    if (r && r.value().size() > 0) {
        // 处理 echo 数据
    }

    co_await sock.shutdown();
    co_await sock.close();
}
```

## 运行测试与压测

```bash
# 构建 + 测试
./scripts/run.sh build
./scripts/run.sh test

# 压测
./scripts/run.sh bench

# 结果检查
./scripts/check.sh
```

也可以直接运行：

```bash
./build/bin/T1-SslSocketTest
./build/bin/B1-SslBenchServer 8443 certs/server.crt certs/server.key
./build/bin/B1-SslBenchClient 127.0.0.1 8443 200 500 47 4
```

## 性能摘要

以下数据来自仓库内最新 5 轮串行复测基线（本地环回，Release + LTO，记录日期：2026-02-13）：

| 场景 | 参数 | 平均结果 |
|------|------|----------|
| 小包 QPS | `200 500 payload=47B threads=4` | 162,234 req/s |
| 大包吞吐 | `10 200 payload=64KiB threads=1` | 1,981.10 MB/s |

详细口径与历史对照见 [docs/05-性能分析.md](docs/05-性能分析.md)。

## 文档

详细文档见 [docs/](docs/)：

| 文档 | 说明 |
|------|------|
| [01-快速开始](docs/01-快速开始.md) | 依赖、编译、最小可运行示例、错误处理 |
| [02-使用示例](docs/02-使用示例.md) | 服务端/客户端、证书验证、会话复用、超时示例 |
| [03-模块介绍](docs/03-模块介绍.md) | `SslContext` / `SslEngine` / `SslSocket` / Awaitable 模块说明 |
| [04-运行原理](docs/04-运行原理.md) | Memory BIO 状态机、协程调度流程、资源生命周期 |
| [05-性能分析](docs/05-性能分析.md) | 压测方法、关键指标、优化建议 |

## 许可证

MIT License
