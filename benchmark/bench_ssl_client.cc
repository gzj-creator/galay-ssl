/**
 * @file bench_ssl_client.cc
 * @brief SSL 客户端性能测试
 */

#include "galay-ssl/async/SslSocket.h"
#include "galay-ssl/ssl/SslContext.h"
#include <galay-kernel/kernel/Coroutine.h>
#include <iostream>
#include <atomic>
#include <csignal>
#include <vector>
#include <thread>
#include <chrono>

#ifdef USE_KQUEUE
#include <galay-kernel/kernel/KqueueScheduler.h>
using TestScheduler = galay::kernel::KqueueScheduler;
#elif defined(USE_EPOLL)
#include <galay-kernel/kernel/EpollScheduler.h>
using TestScheduler = galay::kernel::EpollScheduler;
#endif

using namespace galay::ssl;
using namespace galay::kernel;

std::atomic<bool> g_running{true};
std::atomic<uint64_t> g_requests{0};
std::atomic<uint64_t> g_bytes_sent{0};
std::atomic<uint64_t> g_bytes_recv{0};
std::atomic<uint64_t> g_errors{0};
std::atomic<uint64_t> g_connections_done{0};

void signalHandler(int) {
    g_running = false;
}

Coroutine sslClient(IOScheduler* scheduler, SslContext* ctx,
                    const std::string& host, uint16_t port,
                    const std::string& message, int requestCount) {
    SslSocket socket(scheduler, ctx);

    auto createResult = socket.create(IPType::IPV4);
    if (!createResult) {
        g_errors++;
        g_connections_done++;
        co_return;
    }

    socket.option().handleNonBlock();

    // 设置 SNI
    socket.setHostname(host);

    // 连接
    auto connectResult = co_await socket.connect(Host(IPType::IPV4, host, port));
    if (!connectResult) {
        std::cerr << "Connect failed: " << connectResult.error().message() << std::endl;
        g_errors++;
        co_await socket.close();
        g_connections_done++;
        co_return;
    }

    // SSL 握手 - 需要循环直到完成（SSL 握手是多轮的）
    while (!socket.isHandshakeCompleted()) {
        auto handshakeResult = co_await socket.handshake();
        if (!handshakeResult) {
            auto& err = handshakeResult.error();
            // WantRead/WantWrite 表示需要继续握手
            if (err.code() == SslErrorCode::kHandshakeWantRead ||
                err.code() == SslErrorCode::kHandshakeWantWrite) {
                continue;
            }
            // 其他错误则退出
            std::cerr << "Handshake failed: " << err.message() << std::endl;
            g_errors++;
            co_await socket.close();
            g_connections_done++;
            co_return;
        }
        break;  // 握手成功
    }

    char buffer[4096];
    for (int i = 0; i < requestCount && g_running; i++) {
        // 发送
        auto sendResult = co_await socket.send(message.c_str(), message.size());
        if (!sendResult) {
            g_errors++;
            break;
        }
        g_bytes_sent += sendResult.value();

        // 接收
        auto recvResult = co_await socket.recv(buffer, sizeof(buffer));
        if (!recvResult) {
            g_errors++;
            break;
        }
        g_bytes_recv += recvResult.value().size();
        g_requests++;
    }

    co_await socket.shutdown();
    co_await socket.close();
    g_connections_done++;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <host> <port> <connections> <requests_per_conn>" << std::endl;
        return 1;
    }

    std::string host = argv[1];
    uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));
    int connections = std::stoi(argv[3]);
    int requestsPerConn = std::stoi(argv[4]);

    // 设置信号处理
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    signal(SIGPIPE, SIG_IGN);

    // 创建 SSL 上下文
    SslContext ctx(SslMethod::TLS_Client);
    if (!ctx.isValid()) {
        std::cerr << "Failed to create SSL context" << std::endl;
        return 1;
    }

    // 加载CA证书，即使不验证（用于建立信任链）
    auto caResult = ctx.loadCACertificate("certs/ca.crt");
    if (!caResult) {
        std::cerr << "Failed to load CA certificate: " << caResult.error().message() << std::endl;
        return 1;
    }

    // 不验证服务器证书（测试用）
    ctx.setVerifyMode(SslVerifyMode::None);

    // 创建调度器
    TestScheduler scheduler;
    scheduler.start();

    std::string message = "Hello, SSL Server! This is a benchmark message.";

    auto startTime = std::chrono::high_resolution_clock::now();

    // 启动客户端连接
    for (int i = 0; i < connections; i++) {
        scheduler.spawn(sslClient(&scheduler, &ctx, host, port, message, requestsPerConn));
    }

    // 等待完成
    while (g_running && g_connections_done < static_cast<uint64_t>(connections)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    g_running = false;
    scheduler.stop();

    std::cout << "\nBenchmark Results:" << std::endl;
    std::cout << "==================" << std::endl;
    std::cout << "Connections: " << connections << std::endl;
    std::cout << "Requests per connection: " << requestsPerConn << std::endl;
    std::cout << "Total requests: " << g_requests << std::endl;
    std::cout << "Total errors: " << g_errors << std::endl;
    std::cout << "Total bytes sent: " << g_bytes_sent << std::endl;
    std::cout << "Total bytes received: " << g_bytes_recv << std::endl;
    std::cout << "Duration: " << duration.count() << " ms" << std::endl;

    if (duration.count() > 0) {
        double rps = static_cast<double>(g_requests) * 1000.0 / duration.count();
        double throughput = static_cast<double>(g_bytes_sent + g_bytes_recv) / 1024.0 / 1024.0 * 1000.0 / duration.count();
        std::cout << "Requests/sec: " << rps << std::endl;
        std::cout << "Throughput: " << throughput << " MB/s" << std::endl;
    }

    return 0;
}
