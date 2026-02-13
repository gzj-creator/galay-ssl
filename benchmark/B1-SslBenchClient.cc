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
#include <algorithm>
#include <vector>
#include <thread>
#include <chrono>

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
std::atomic<uint64_t> g_requests{0};
std::atomic<uint64_t> g_bytes_sent{0};
std::atomic<uint64_t> g_bytes_recv{0};
std::atomic<uint64_t> g_errors{0};
std::atomic<uint64_t> g_connections_done{0};

void signalHandler(int) {
    g_running = false;
}

Coroutine sslClient(SslContext* ctx,
                    const std::string& host, uint16_t port,
                    const std::string& message, int requestCount) {
    SslSocket socket(ctx);

    if (!socket.isValid()) {
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
            g_errors++;
            co_await socket.close();
            g_connections_done++;
            co_return;
        }
        break;  // 握手成功
    }

    for (int i = 0; i < requestCount && g_running; i++) {
        // 发送
        auto sendResult = co_await socket.send(message.c_str(), message.size());
        if (!sendResult) {
            std::cerr << "Send failed: " << sendResult.error().message() << std::endl;
            g_errors++;
            break;
        }
        g_bytes_sent += sendResult.value();

        // 接收 - echo 是字节流，可能被拆包；按发送长度累计读满
        size_t remaining = message.size();
        std::vector<char> buffer(std::min<size_t>(64 * 1024, remaining));
        int recvLoops = 0;
        bool recvFailed = false;
        // 防止异常情况下无限等待（比如少读/漏读导致 remaining 永远不为 0）
        const int kMaxRecvLoops = 200000;
        while (remaining > 0 && recvLoops++ < kMaxRecvLoops) {
            auto recvLen = std::min(remaining, buffer.size());
            auto recvResult = co_await socket.recv(buffer.data(), recvLen);
            if (!recvResult) {
                auto& err = recvResult.error();
                // WANT_READ/WANT_WRITE 表示需要继续等待
                if (err.sslError() == SSL_ERROR_WANT_READ ||
                    err.sslError() == SSL_ERROR_WANT_WRITE) {
                    continue;
                }
                std::cerr << "Recv failed: " << err.message()
                          << " (ssl_error=" << err.sslError() << ")"
                          << " after sending " << g_bytes_sent << " bytes" << std::endl;
                recvFailed = true;
                break;
            }
            if (recvResult.value().size() == 0) {
                std::cerr << "Recv returned 0 bytes (connection closed by peer)" << std::endl;
                recvFailed = true;
                break;
            }
            g_bytes_recv += recvResult.value().size();
            remaining -= recvResult.value().size();
        }
        if (recvFailed || remaining != 0) {
            g_errors++;
            break;
        }
        g_requests++;
    }

    co_await socket.shutdown();
    co_await socket.close();
    g_connections_done++;
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <host> <port> <connections> <requests_per_conn> [payload_bytes]"
                  << std::endl;
        return 1;
    }

    std::string host = argv[1];
    uint16_t port = static_cast<uint16_t>(std::stoi(argv[2]));
    int connections = std::stoi(argv[3]);
    int requestsPerConn = std::stoi(argv[4]);
    // 保持默认与历史压测一致（47 字节），大包场景用第 5 个参数显式指定。
    size_t payloadBytes = 47;
    if (argc >= 6) {
        payloadBytes = static_cast<size_t>(std::stoull(argv[5]));
        if (payloadBytes == 0) {
            payloadBytes = 1;
        }
    }

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

    // 固定 payload，避免构造成本影响压测结果；内容无所谓（echo 只看字节流）
    std::string message(payloadBytes, 'x');

    auto startTime = std::chrono::high_resolution_clock::now();

    // 启动客户端连接
    for (int i = 0; i < connections; i++) {
        scheduler.spawn(sslClient(&ctx, host, port, message, requestsPerConn));
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
    std::cout << "Payload bytes: " << payloadBytes << std::endl;
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
