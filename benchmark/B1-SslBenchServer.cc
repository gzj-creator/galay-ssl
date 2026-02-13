/**
 * @file bench_ssl_server.cc
 * @brief SSL 服务端性能测试
 */

#include "galay-ssl/async/SslSocket.h"
#include "galay-ssl/ssl/SslContext.h"
#include <galay-kernel/kernel/Coroutine.h>
#include <iostream>
#include <atomic>
#include <csignal>
#include <cerrno>
#include <cstring>

#ifdef USE_KQUEUE
#include <galay-kernel/kernel/KqueueScheduler.h>
using TestScheduler = galay::kernel::KqueueScheduler;
#elif defined(USE_IOURING)
#include <galay-kernel/kernel/IOUringScheduler.h>
using TestScheduler = galay::kernel::IOUringScheduler;
#elif defined(USE_EPOLL)
#include <galay-kernel/kernel/EpollScheduler.h>
using TestScheduler = galay::kernel::EpollScheduler;
#endif

using namespace galay::ssl;
using namespace galay::kernel;

std::atomic<bool> g_running{true};
std::atomic<uint64_t> g_connections{0};
std::atomic<uint64_t> g_bytes_recv{0};
std::atomic<uint64_t> g_bytes_sent{0};

void logErrno(const char* prefix) {
    std::cerr << prefix << ": errno=" << errno << " (" << std::strerror(errno) << ")" << std::endl;
}

void signalHandler(int) {
    g_running = false;
}

Coroutine handleClient(SslContext* ctx, GHandle handle) {
    SslSocket client(ctx, handle);
    client.option().handleNonBlock();

    // SSL 握手 - 需要循环直到完成（SSL 握手是多轮的）
    while (!client.isHandshakeCompleted()) {
        auto handshakeResult = co_await client.handshake();
        if (!handshakeResult) {
            auto& err = handshakeResult.error();
            // WantRead/WantWrite 表示需要继续握手
            if (err.code() == SslErrorCode::kHandshakeWantRead ||
                err.code() == SslErrorCode::kHandshakeWantWrite) {
                continue;
            }
            // 其他错误则退出
            co_await client.close();
            co_return;
        }
        break;  // 握手成功
    }

    g_connections++;

    char buffer[64 * 1024];
    while (g_running) {
        auto recvResult = co_await client.recv(buffer, sizeof(buffer));
        if (!recvResult) {
            auto& err = recvResult.error();
            // WANT_READ/WANT_WRITE 表示需要继续等待
            if (err.sslError() == SSL_ERROR_WANT_READ ||
                err.sslError() == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            break;
        }

        auto& bytes = recvResult.value();
        if (bytes.size() == 0) {
            break;  // 对端关闭
        }

        g_bytes_recv += bytes.size();

        // Echo 回去
        auto sendResult = co_await client.send(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        if (!sendResult) {
            break;
        }
        g_bytes_sent += sendResult.value();
    }

    co_await client.shutdown();
    co_await client.close();
}

Coroutine sslServer(IOScheduler* scheduler, SslContext* ctx, uint16_t port) {
    SslSocket listener(ctx);

    if (!listener.isValid()) {
        co_return;
    }

    listener.option().handleReuseAddr();
    listener.option().handleNonBlock();

    auto bindResult = listener.bind(Host(IPType::IPV4, "0.0.0.0", port));
    if (!bindResult) {
        logErrno("bind failed");
        co_return;
    }

    auto listenResult = listener.listen(1024);
    if (!listenResult) {
        logErrno("listen failed");
        co_return;
    }

    std::cout << "SSL Server listening on port " << port << std::endl;

    while (g_running) {
        Host clientHost;
        auto acceptResult = co_await listener.accept(&clientHost);
        if (!acceptResult) {
            logErrno("accept failed");
            continue;
        }
        if (!scheduler->spawn(handleClient(ctx, acceptResult.value()))) {
            std::cerr << "spawn failed for client handler" << std::endl;
        }
    }

    co_await listener.close();
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        return 1;
    }

    uint16_t port = static_cast<uint16_t>(std::stoi(argv[1]));
    std::string certFile = argv[2];
    std::string keyFile = argv[3];

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGPIPE, SIG_IGN);

    SslContext ctx(SslMethod::TLS_Server);
    if (!ctx.isValid()) {
        return 1;
    }

    auto certResult = ctx.loadCertificate(certFile);
    if (!certResult) {
        return 1;
    }

    auto keyResult = ctx.loadPrivateKey(keyFile);
    if (!keyResult) {
        return 1;
    }

    TestScheduler scheduler;
    scheduler.start();

    scheduler.spawn(sslServer(&scheduler, &ctx, port));

    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    scheduler.stop();

    std::cout << "\nFinal stats:" << std::endl;
    std::cout << "Total connections: " << g_connections << std::endl;
    std::cout << "Total bytes received: " << g_bytes_recv << std::endl;
    std::cout << "Total bytes sent: " << g_bytes_sent << std::endl;

    return 0;
}
