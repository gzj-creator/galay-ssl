/**
 * @file bench_ssl_server.cc
 * @brief SSL 服务端性能测试
 */

#include "galay-ssl/async/SslSocket.h"
#include "galay-ssl/ssl/SslContext.h"
#include <galay-kernel/kernel/Task.h>
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

void configureBenchmarkTlsContext(SslContext& ctx) {
    ctx.setSessionCacheMode(SSL_SESS_CACHE_OFF);
    ctx.setSessionTimeout(0);
    if (ctx.native()) {
        SSL_CTX_set_options(ctx.native(), SSL_OP_NO_TICKET);
    }
}

void logErrno(const char* prefix) {
    std::cerr << prefix << ": errno=" << errno << " (" << std::strerror(errno) << ")" << std::endl;
}

void signalHandler(int) {
    g_running = false;
}

Task<void> handleClient(SslContext* ctx, GHandle handle) {
    SslSocket client(ctx, handle);
    client.option().handleNonBlock();

    auto handshakeResult = co_await client.handshake();
    if (!handshakeResult) {
        co_await client.close();
        co_return;
    }

    g_connections++;

    char buffer[64 * 1024];
    while (g_running) {
        auto recvResult = co_await client.recv(buffer, sizeof(buffer));
        if (!recvResult) {
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

Task<void> sslServer(IOScheduler* scheduler, SslContext* ctx, uint16_t port, int backlog) {
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

    auto listenResult = listener.listen(backlog);
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
        if (!scheduleTask(scheduler, handleClient(ctx, acceptResult.value()))) {
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
    int backlog = 4096;
    if (argc >= 5) {
        backlog = std::max(128, std::stoi(argv[4]));
    }

    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGPIPE, SIG_IGN);

    SslContext ctx(SslMethod::TLS_1_3_Server);
    if (!ctx.isValid()) {
        return 1;
    }

    configureBenchmarkTlsContext(ctx);

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

    scheduleTask(scheduler, sslServer(&scheduler, &ctx, port, backlog));

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
