# galay-ssl

基于 galay-kernel 的异步 SSL/TLS 库，提供协程友好的加密通信支持。

## 特性

- 基于 OpenSSL 的 SSL/TLS 支持
- 与 galay-kernel 无缝集成
- C++20 协程支持
- 支持服务端和客户端模式
- 支持 TLS 1.2/1.3
- 支持证书验证和 SNI

## 依赖

- C++23 编译器 (GCC 13+, Clang 16+, MSVC 2022+)
- CMake 3.16+
- OpenSSL 1.1.1+
- galay-kernel

## 构建

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

## 安装

```bash
make install
```

## 使用示例

### SSL 服务端

```cpp
#include "galay-ssl/async/SslSocket.h"
#include "galay-kernel/kernel/KqueueScheduler.h"

using namespace galay::ssl;
using namespace galay::kernel;

Coroutine sslServer(IOScheduler* scheduler) {
    // 创建 SSL 上下文
    SslContext ctx(SslMethod::TLS_Server);
    ctx.loadCertificate("server.crt");
    ctx.loadPrivateKey("server.key");

    // 创建监听 socket
    SslSocket listener(scheduler, &ctx);
    listener.create(IPType::IPV4);
    listener.option().handleReuseAddr();
    listener.option().handleNonBlock();
    listener.bind(Host(IPType::IPV4, "0.0.0.0", 8443));
    listener.listen(1024);

    while (true) {
        Host clientHost;
        auto result = co_await listener.accept(&clientHost);
        if (result) {
            scheduler->spawn(handleClient(scheduler, &ctx, result.value()));
        }
    }
}

Coroutine handleClient(IOScheduler* scheduler, SslContext* ctx, GHandle handle) {
    SslSocket client(scheduler, ctx, handle);

    // SSL 握手
    auto handshakeResult = co_await client.handshake();
    if (!handshakeResult) {
        co_await client.close();
        co_return;
    }

    // 接收数据
    char buffer[1024];
    auto recvResult = co_await client.recv(buffer, sizeof(buffer));
    if (recvResult) {
        // 发送响应
        co_await client.send(buffer, recvResult.value().size());
    }

    co_await client.shutdown();
    co_await client.close();
}
```

### SSL 客户端

```cpp
Coroutine sslClient(IOScheduler* scheduler) {
    SslContext ctx(SslMethod::TLS_Client);
    ctx.setVerifyMode(SslVerifyMode::Peer);
    ctx.loadCACertificate("ca.crt");

    SslSocket socket(scheduler, &ctx);
    socket.create(IPType::IPV4);
    socket.option().handleNonBlock();

    // 连接服务器
    auto connectResult = co_await socket.connect(Host(IPType::IPV4, "127.0.0.1", 8443));
    if (!connectResult) {
        co_return;
    }

    // SSL 握手
    auto handshakeResult = co_await socket.handshake();
    if (!handshakeResult) {
        co_await socket.close();
        co_return;
    }

    // 发送数据
    const char* msg = "Hello, SSL!";
    co_await socket.send(msg, strlen(msg));

    // 接收响应
    char buffer[1024];
    auto recvResult = co_await socket.recv(buffer, sizeof(buffer));

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
│   ├── CMakeLists.txt
│   ├── test_ssl_socket.cc
│   └── certs/                # 测试证书
└── benchmark/
    ├── CMakeLists.txt
    └── bench_ssl.cc
```

## 许可证

MIT License
