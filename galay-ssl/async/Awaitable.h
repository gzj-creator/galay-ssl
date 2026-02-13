#ifndef GALAY_SSL_AWAITABLE_H
#define GALAY_SSL_AWAITABLE_H

#include "galay-ssl/common/Error.h"
#include "galay-ssl/ssl/SslEngine.h"
#include <galay-kernel/kernel/IOScheduler.hpp>
#include <galay-kernel/kernel/Awaitable.h>
#include <galay-kernel/kernel/Waker.h>
#include <galay-kernel/kernel/Timeout.hpp>
#include <galay-kernel/common/Bytes.h>
#include <coroutine>
#include <expected>
#include <vector>

namespace galay::ssl
{

using namespace galay::kernel;

// ==================== SslRecvAwaitable ====================

/**
 * @brief SSL 接收可等待对象（Memory BIO 模式）
 *
 * @details 继承 RecvAwaitable，重写 handleComplete 实现：
 * recv 密文 → BIO_write(rbio) → SSL_read 解密 → 明文
 *
 * 基类的 m_buffer/m_length 指向内部密文 buffer（用于 raw recv），
 * 用户的明文 buffer 存在 m_plainBuffer/m_plainLength。
 */
struct SslRecvAwaitable : public RecvAwaitable {
    SslRecvAwaitable(IOController* controller, SslEngine* engine,
                     char* buffer, size_t length,
                     std::vector<char>* cipherBuffer = nullptr);

#ifdef USE_IOURING
    bool handleComplete(struct io_uring_cqe* cqe, GHandle handle) override;
#else
    bool handleComplete(GHandle handle) override;
#endif

    bool await_suspend(std::coroutine_handle<> handle);
    std::expected<Bytes, SslError> await_resume();

    SslEngine* m_engine;
    char* m_plainBuffer;
    size_t m_plainLength;
    std::vector<char>* m_cipherBuffer;
    std::vector<char> m_cipherBufferOwned;
    size_t m_flushOffset = 0;
    size_t m_flushLength = 0;
    std::expected<Bytes, SslError> m_sslResult;
    bool m_sslResultSet = false;
};

// ==================== SslSendAwaitable ====================

/**
 * @brief SSL 发送可等待对象（Memory BIO 模式）
 *
 * @details 继承 SendAwaitable：
 * - 非 io_uring 路径：构造时先 SSL_write(明文) → BIO_read(wbio) 取密文，再做 raw send
 * - io_uring 路径：按需增量 SSL_write + 分块 BIO_read，避免一次性累积全部密文
 */
struct SslSendAwaitable : public SendAwaitable {
    SslSendAwaitable(IOController* controller, SslEngine* engine,
                     const char* buffer, size_t length,
                     std::vector<char>* cipherBuffer = nullptr);

#ifdef USE_IOURING
    bool handleComplete(struct io_uring_cqe* cqe, GHandle handle) override;
#else
    bool handleComplete(GHandle handle) override;
#endif

    bool await_suspend(std::coroutine_handle<> handle);
    std::expected<size_t, SslError> await_resume();

    bool fillNextSendChunk();

    SslEngine* m_engine;
    const char* m_plainBuffer;
    size_t m_plainLength;
    size_t m_plainOffset = 0;
    std::vector<char>* m_cipherBuffer;
    std::vector<char> m_cipherBufferOwned;
    size_t m_cipherLength = 0;
    std::expected<size_t, SslError> m_sslResult;
    bool m_sslResultSet = false;
};

// ==================== SslHandshakeAwaitable ====================

/**
 * @brief SSL 握手可等待对象（Memory BIO 模式）
 *
 * @details 继承 CustomAwaitable，通过内嵌 RecvIOContext/SendIOContext
 * 实现多轮握手的 BIO 数据交换。
 *
 * 核心流程：
 * 1. 构造时调用 SSL_do_handshake()
 * 2. WantWrite → BIO_read(wbio) 取密文 → addTask(SEND)
 * 3. WantRead → addTask(RECV)
 * 4. handleComplete 中：raw IO 完成 → 喂 BIO → 重试握手 → 根据结果动态 addTask
 * 5. 握手成功或出错时队列清空，调度器 wakeUp
 */
struct SslHandshakeAwaitable : public CustomAwaitable {

    struct HandshakeRecvCtx : public RecvIOContext {
        HandshakeRecvCtx(char* buf, size_t len, SslHandshakeAwaitable* owner)
            : RecvIOContext(buf, len), m_owner(owner) {}

#ifdef USE_IOURING
        bool handleComplete(struct io_uring_cqe* cqe, GHandle handle) override;
#else
        bool handleComplete(GHandle handle) override;
#endif

        SslHandshakeAwaitable* m_owner;
    };

    struct HandshakeSendCtx : public SendIOContext {
        HandshakeSendCtx(const char* buf, size_t len, SslHandshakeAwaitable* owner)
            : SendIOContext(buf, len), m_owner(owner) {}

#ifdef USE_IOURING
        bool handleComplete(struct io_uring_cqe* cqe, GHandle handle) override;
#else
        bool handleComplete(GHandle handle) override;
#endif

        SslHandshakeAwaitable* m_owner;
        bool m_followedByRecv = false;  // RECV 已入队则不需要再调 tryHandshake
    };

    SslHandshakeAwaitable(IOController* controller, SslEngine* engine);

    bool await_ready();
    std::expected<void, SslError> await_resume();

    /// 内部：尝试握手并根据结果填充 IO 任务队列
    void tryHandshake();

    SslEngine* m_engine;
    std::vector<char> m_ioBuf;
    std::expected<void, SslError> m_result;
    bool m_resultSet = false;
    bool m_handshakeSucceeded = false;  ///< 握手已成功，正在发送剩余密文

    HandshakeRecvCtx m_recvCtx;
    HandshakeSendCtx m_sendCtx;
};

// ==================== SslShutdownAwaitable ====================

/**
 * @brief SSL 关闭可等待对象（Memory BIO 模式）
 *
 * @details 继承 CustomAwaitable，用 SSL_shutdown 替代 SSL_do_handshake，
 * 逻辑与 SslHandshakeAwaitable 类似。
 */
struct SslShutdownAwaitable : public CustomAwaitable {

    struct ShutdownRecvCtx : public RecvIOContext {
        ShutdownRecvCtx(char* buf, size_t len, SslShutdownAwaitable* owner)
            : RecvIOContext(buf, len), m_owner(owner) {}

#ifdef USE_IOURING
        bool handleComplete(struct io_uring_cqe* cqe, GHandle handle) override;
#else
        bool handleComplete(GHandle handle) override;
#endif

        SslShutdownAwaitable* m_owner;
    };

    struct ShutdownSendCtx : public SendIOContext {
        ShutdownSendCtx(const char* buf, size_t len, SslShutdownAwaitable* owner)
            : SendIOContext(buf, len), m_owner(owner) {}

#ifdef USE_IOURING
        bool handleComplete(struct io_uring_cqe* cqe, GHandle handle) override;
#else
        bool handleComplete(GHandle handle) override;
#endif

        SslShutdownAwaitable* m_owner;
        bool m_followedByRecv = false;
    };

    SslShutdownAwaitable(IOController* controller, SslEngine* engine);

    bool await_ready();
    std::expected<void, SslError> await_resume();

    /// 内部：尝试 shutdown 并根据结果填充 IO 任务队列
    void tryShutdown();

    SslEngine* m_engine;
    std::vector<char> m_ioBuf;
    std::expected<void, SslError> m_result;
    bool m_resultSet = false;

    ShutdownRecvCtx m_recvCtx;
    ShutdownSendCtx m_sendCtx;
};

} // namespace galay::ssl

#endif // GALAY_SSL_AWAITABLE_H
