/**
 * @file E1-SslEchoServer.cc
 * @brief SSL Echo服务器示例
 * @details 演示如何使用SslSocket创建一个简单的SSL Echo服务器
 *
 * 使用场景：
 *   - 学习SSL服务器基本用法
 *   - 理解SSL握手和异步IO的配合
 *   - 作为HTTPS等SSL服务器的基础模板
 *
 * 运行方式：
 *   ./E1-SslEchoServer <port> <cert_file> <key_file>
 *   例如: ./E1-SslEchoServer 8443 certs/server.crt certs/server.key
 */

#include <iostream>
#include <csignal>
#include <atomic>
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

std::atomic<bool> g_running{true};

void signalHandler(int) {
    g_running = false;
}

/**
 * @brief 处理单个客户端连接
 * @param ctx SSL上下文
 * @param handle 客户端socket句柄
 */
Coroutine handleClient(SslContext* ctx, GHandle handle) {
    SslSocket client(ctx, handle);
    client.option().handleNonBlock();

    // SSL握手（可能需要多轮）
    while (!client.isHandshakeCompleted()) {
        auto result = co_await client.handshake();
        if (!result) {
            auto& err = result.error();
            if (err.code() == SslErrorCode::kHandshakeWantRead ||
                err.code() == SslErrorCode::kHandshakeWantWrite) {
                continue;
            }
            std::cerr << "Handshake failed: " << err.message() << std::endl;
            co_await client.close();
            co_return;
        }
        break;
    }

    std::cout << "Client connected, SSL handshake completed" << std::endl;

    // Echo循环
    char buffer[4096];
    while (g_running) {
        auto recvResult = co_await client.recv(buffer, sizeof(buffer));
        if (!recvResult) {
            std::cerr << "Recv error: " << recvResult.error().message() << std::endl;
            break;
        }

        auto& bytes = recvResult.value();
        if (bytes.size() == 0) {
            std::cout << "Client disconnected" << std::endl;
            break;
        }

        std::cout << "Received: " << bytes.toStringView() << std::endl;

        // 回显数据
        auto sendResult = co_await client.send(bytes.c_str(), bytes.size());
        if (!sendResult) {
            std::cerr << "Send error: " << sendResult.error().message() << std::endl;
            break;
        }
    }

    co_await client.shutdown();
    co_await client.close();
}

/**
 * @brief SSL Echo服务器协程
 */
Coroutine sslEchoServer(IOSchedulerType* scheduler, SslContext* ctx, uint16_t port) {
    SslSocket listener(ctx);

    if (!listener.isValid()) {
        std::cerr << "Failed to create socket" << std::endl;
        co_return;
    }

    listener.option().handleReuseAddr();
    listener.option().handleNonBlock();

    auto bindResult = listener.bind(Host(IPType::IPV4, "0.0.0.0", port));
    if (!bindResult) {
        std::cerr << "Failed to bind: " << bindResult.error().message() << std::endl;
        co_return;
    }

    auto listenResult = listener.listen(128);
    if (!listenResult) {
        std::cerr << "Failed to listen: " << listenResult.error().message() << std::endl;
        co_return;
    }

    std::cout << "SSL Echo Server listening on port " << port << std::endl;

    while (g_running) {
        Host clientHost;
        auto acceptResult = co_await listener.accept(&clientHost);
        if (acceptResult) {
            std::cout << "New connection from " << clientHost.ip()
                      << ":" << clientHost.port() << std::endl;
            scheduler->spawn(handleClient(ctx, acceptResult.value()));
        }
    }

    co_await listener.close();
    std::cout << "Server stopped" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <port> <cert_file> <key_file>" << std::endl;
        std::cerr << "Example: " << argv[0] << " 8443 certs/server.crt certs/server.key" << std::endl;
        return 1;
    }

    uint16_t port = static_cast<uint16_t>(std::stoi(argv[1]));
    std::string certFile = argv[2];
    std::string keyFile = argv[3];

    // 设置信号处理
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGPIPE, SIG_IGN);

    // 创建SSL上下文
    SslContext ctx(SslMethod::TLS_Server);
    if (!ctx.isValid()) {
        std::cerr << "Failed to create SSL context" << std::endl;
        return 1;
    }

    auto certResult = ctx.loadCertificate(certFile);
    if (!certResult) {
        std::cerr << "Failed to load certificate: " << certResult.error().message() << std::endl;
        return 1;
    }

    auto keyResult = ctx.loadPrivateKey(keyFile);
    if (!keyResult) {
        std::cerr << "Failed to load private key: " << keyResult.error().message() << std::endl;
        return 1;
    }

    // 创建调度器
    IOSchedulerType scheduler;
    scheduler.start();

    // 启动服务器
    scheduler.spawn(sslEchoServer(&scheduler, &ctx, port));

    // 等待退出
    std::cout << "Press Ctrl+C to stop server..." << std::endl;
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    scheduler.stop();
    return 0;
}
