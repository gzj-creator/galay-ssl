# galay-ssl

基于 galay-kernel 的异步 SSL/TLS 库，提供协程友好的加密通信支持。

## 特性

- 基于 OpenSSL 的 SSL/TLS 支持
- 与 galay-kernel 无缝集成
- C++20 协程支持
- 支持服务端和客户端模式
- 支持 TLS 1.2/1.3
- 支持证书验证和 SNI
- 支持 epoll 和 io_uring 两种 IO 后端

## 依赖

- C++23 编译器 (GCC 13+, Clang 16+, MSVC 2022+)
- CMake 3.16+
- OpenSSL 1.1.1+
- galay-kernel

## 构建

```bash
mkdir build && cd build

# 使用 io_uring (默认，需要 liburing)
cmake .. -DCMAKE_BUILD_TYPE=Release

# 使用 epoll
cmake .. -DCMAKE_BUILD_TYPE=Release -DDISABLE_IOURING=ON

make -j$(nproc)
```

## 安装

```bash
sudo make install
```

## 性能测试

### 测试环境

#### Linux 环境 (x86_64)

| 项目 | 配置 |
|------|------|
| CPU | Intel Core i7-14700K |
| CPU 核心数 | 8 |
| 内存 | 7.7 GB |
| 内核版本 | 6.8.0-90-generic |
| GCC 版本 | 13.3.0 |
| OpenSSL 版本 | 3.0.13 |

#### macOS 环境 (ARM64)

| 项目 | 配置 |
|------|------|
| CPU | Apple M4 |
| CPU 核心数 | 10 |
| 内存 | 24 GB |
| 系统版本 | macOS 15.7.3 |
| 内核版本 | 24.6.0 |
| Clang 版本 | 17.0.0 |
| OpenSSL 版本 | 3.5.0 |

### 压测结果

测试场景：SSL Echo 服务器，客户端发送 47 字节消息，服务器原样返回。

#### Linux x86_64 - io_uring 后端

| 测试场景 | 连接数 | 每连接请求数 | 总请求数 | 错误数 | 耗时 | QPS | 吞吐量 |
|----------|--------|--------------|----------|--------|------|-----|--------|
| 测试1 | 100 | 1000 | 100,000 | 0 | 14.88s | 6,722 | 0.60 MB/s |
| 测试2 | 500 | 1000 | 500,000 | 0 | 88.42s | 5,655 | 0.51 MB/s |
| 测试3 | 1000 | 500 | 500,000 | 0 | 93.62s | 5,341 | 0.48 MB/s |

#### Linux x86_64 - epoll 后端

| 测试场景 | 连接数 | 每连接请求数 | 总请求数 | 错误数 | 耗时 | QPS | 吞吐量 |
|----------|--------|--------------|----------|--------|------|-----|--------|
| 测试1 | 100 | 1000 | 100,000 | 0 | 15.17s | 6,593 | 0.59 MB/s |
| 测试2 | 500 | 1000 | 500,000 | 0 | 88.71s | 5,636 | 0.51 MB/s |
| 测试3 | 1000 | 500 | 500,000 | 0 | 93.85s | 5,328 | 0.48 MB/s |

#### macOS ARM64 - kqueue 后端

| 测试场景 | 连接数 | 每连接请求数 | 总请求数 | 错误数 | 耗时 | QPS | 吞吐量 |
|----------|--------|--------------|----------|--------|------|-----|--------|
| 测试1 | 100 | 1000 | 100,000 | 0 | 0.60s | 167,224 | 14.99 MB/s |
| 测试2 | 500 | 1000 | 500,000 | 0 | 3.36s | 148,633 | 13.32 MB/s |
| 测试3 | 1000 | 500 | 500,000 | 0 | 3.88s | 129,032 | 11.57 MB/s |

#### 性能分析

**Linux x86_64 平台 (Intel i7-14700K)**：
- io_uring 和 epoll 性能接近，io_uring 略有优势（约 0.2%~2%）
- SSL 加解密是主要瓶颈，IO 后端差异影响较小
- QPS 约 5,000~6,700，吞吐量约 0.48~0.60 MB/s

**macOS ARM64 平台 (Apple M4)**：
- QPS 达到 129,000~167,000
- 吞吐量达到 11.57~14.99 MB/s
- 性能显著高于 Linux 测试环境

**注意事项**：
- 两个测试环境配置差异较大（CPU型号、核心数、内存、操作系统均不同）
- 性能差异可能来自多个因素：CPU性能、硬件加密加速、操作系统优化、OpenSSL版本等
- 不应简单归因于 ARM64 vs x86_64 架构差异
- 建议在相同或相近配置下进行对比测试以获得更准确的结论

**结论**：
1. 在 SSL 场景下，不同 IO 后端（io_uring/epoll/kqueue）性能差异较小
2. galay-ssl 在不同平台上均表现出良好的性能和稳定性
3. 实际性能受多种因素影响，建议根据实际部署环境进行测试

## 使用示例

### SSL 服务端

```cpp
#include "galay-ssl/async/SslSocket.h"
#include "galay-kernel/kernel/EpollScheduler.h"  // 或 IOUringScheduler

using namespace galay::ssl;
using namespace galay::kernel;

Coroutine handleClient(SslContext* ctx, GHandle handle) {
    SslSocket client(ctx, handle);
    client.option().handleNonBlock();

    // SSL 握手 - 需要循环直到完成
    while (!client.isHandshakeCompleted()) {
        auto result = co_await client.handshake();
        if (!result) {
            auto& err = result.error();
            if (err.code() == SslErrorCode::kHandshakeWantRead ||
                err.code() == SslErrorCode::kHandshakeWantWrite) {
                continue;
            }
            co_await client.close();
            co_return;
        }
        break;
    }

    // 接收数据 - 需要处理 WANT_READ/WANT_WRITE
    char buffer[4096];
    while (true) {
        auto recvResult = co_await client.recv(buffer, sizeof(buffer));
        if (!recvResult) {
            auto& err = recvResult.error();
            if (err.sslError() == SSL_ERROR_WANT_READ ||
                err.sslError() == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            break;
        }
        if (recvResult.value().size() == 0) break;

        // Echo 回去
        co_await client.send(recvResult.value().c_str(), recvResult.value().size());
    }

    co_await client.shutdown();
    co_await client.close();
}

Coroutine sslServer(IOScheduler* scheduler, SslContext* ctx, uint16_t port) {
    SslSocket listener(ctx);
    listener.option().handleReuseAddr();
    listener.option().handleNonBlock();
    listener.bind(Host(IPType::IPV4, "0.0.0.0", port));
    listener.listen(1024);

    while (true) {
        Host clientHost;
        auto result = co_await listener.accept(&clientHost);
        if (result) {
            scheduler->spawn(handleClient(ctx, result.value()));
        }
    }
}

int main() {
    SslContext ctx(SslMethod::TLS_Server);
    ctx.loadCertificate("server.crt");
    ctx.loadPrivateKey("server.key");

    EpollScheduler scheduler;  // 或 IOUringScheduler
    scheduler.start();
    scheduler.spawn(sslServer(&scheduler, &ctx, 8443));

    // 等待...
    scheduler.stop();
    return 0;
}
```

### SSL 客户端

```cpp
Coroutine sslClient(SslContext* ctx, const std::string& host, uint16_t port) {
    SslSocket socket(ctx);
    socket.option().handleNonBlock();
    socket.setHostname(host);  // SNI

    // 连接
    auto connectResult = co_await socket.connect(Host(IPType::IPV4, host, port));
    if (!connectResult) co_return;

    // SSL 握手
    while (!socket.isHandshakeCompleted()) {
        auto result = co_await socket.handshake();
        if (!result) {
            auto& err = result.error();
            if (err.code() == SslErrorCode::kHandshakeWantRead ||
                err.code() == SslErrorCode::kHandshakeWantWrite) {
                continue;
            }
            co_await socket.close();
            co_return;
        }
        break;
    }

    // 发送数据
    const char* msg = "Hello, SSL!";
    co_await socket.send(msg, strlen(msg));

    // 接收响应
    char buffer[4096];
    while (true) {
        auto recvResult = co_await socket.recv(buffer, sizeof(buffer));
        if (!recvResult) {
            if (recvResult.error().sslError() == SSL_ERROR_WANT_READ ||
                recvResult.error().sslError() == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            break;
        }
        // 处理数据...
        break;
    }

    co_await socket.shutdown();
    co_await socket.close();
}
```

## 目录结构

```
galay-ssl/
├── CMakeLists.txt
├── README.md
├── galay-ssl-config.cmake.in
├── galay-ssl/
│   ├── CMakeLists.txt
│   ├── common/
│   │   ├── Defn.hpp          # SSL 相关定义
│   │   └── Error.h/cc        # SSL 错误处理
│   ├── ssl/
│   │   ├── SslContext.h/cc   # SSL 上下文管理
│   │   └── SslEngine.h/cc    # SSL 引擎封装
│   └── async/
│       ├── SslSocket.h/cc    # 异步 SSL Socket
│       └── Awaitable.h/cc    # SSL 可等待对象
├── test/
│   └── T1-SslSocketTest.cc   # 单元测试
├── benchmark/
│   ├── B1-SslBenchServer.cc  # 压测服务器
│   └── B1-SslBenchClient.cc  # 压测客户端
└── certs/                    # 测试证书
```

## 许可证

MIT License
